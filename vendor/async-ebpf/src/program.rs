//! This module contains the core logic for eBPF program execution. A lot of
//! `unsafe` code is used - be careful when making changes here.

use std::{
  any::{Any, TypeId},
  cell::{Cell, RefCell},
  collections::HashMap,
  ffi::CStr,
  marker::PhantomData,
  mem::ManuallyDrop,
  ops::{Deref, DerefMut},
  pin::Pin,
  ptr::NonNull,
  rc::Rc,
  sync::{
    atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering},
    Arc, Once,
  },
  thread::ThreadId,
  time::{Duration, Instant},
};

use corosensei::{
  stack::{DefaultStack, Stack},
  Coroutine, CoroutineResult, ScopedCoroutine, Yielder,
};
use futures::{Future, FutureExt};
use memmap2::{MmapOptions, MmapRaw};
use parking_lot::{Condvar, Mutex};
use rand::prelude::SliceRandom;

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  linker::link_elf,
  pointer_cage::PointerCage,
  util::nonnull_bytes_overlap,
};

const NATIVE_STACK_SIZE: usize = 16384;
const SHADOW_STACK_SIZE: usize = 32768;
const MAX_CALLDATA_SIZE: usize = 512;
const MAX_MUTABLE_DEREF_REGIONS: usize = 4;
const MAX_IMMUTABLE_DEREF_REGIONS: usize = 16;

/// Per-invocation storage for helper state during a program run.
pub struct InvokeScope {
  data: HashMap<TypeId, Box<dyn Any + Send>>,
}

impl InvokeScope {
  /// Gets or creates typed data scoped to this invocation.
  pub fn data_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
    let ty = TypeId::of::<T>();
    self
      .data
      .entry(ty)
      .or_insert_with(|| Box::new(T::default()))
      .downcast_mut()
      .expect("InvokeScope::data_mut: downcast failed")
  }
}

/// Context passed to helpers while a program is executing.
pub struct HelperScope<'a, 'b> {
  /// The program being executed.
  pub program: &'a Program,
  /// Mutable per-invocation data for helpers.
  pub invoke: RefCell<&'a mut InvokeScope>,
  resources: RefCell<&'a mut [&'b mut dyn Any]>,
  mutable_dereferenced_regions: [Cell<Option<NonNull<[u8]>>>; MAX_MUTABLE_DEREF_REGIONS],
  immutable_dereferenced_regions: [Cell<Option<NonNull<[u8]>>>; MAX_IMMUTABLE_DEREF_REGIONS],
  can_post_task: bool,
}

/// A validated mutable view into user memory.
pub struct MutableUserMemory<'a, 'b, 'c> {
  _scope: &'c HelperScope<'a, 'b>,
  region: NonNull<[u8]>,
}

impl<'a, 'b, 'c> Deref for MutableUserMemory<'a, 'b, 'c> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    unsafe { self.region.as_ref() }
  }
}

impl<'a, 'b, 'c> DerefMut for MutableUserMemory<'a, 'b, 'c> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    unsafe { self.region.as_mut() }
  }
}

impl<'a, 'b> HelperScope<'a, 'b> {
  /// Posts an async task to be run between timeslices.
  pub fn post_task(
    &self,
    task: impl Future<Output = impl FnOnce(&HelperScope) -> Result<u64, ()> + 'static> + 'static,
  ) {
    if !self.can_post_task {
      panic!("HelperScope::post_task() called in a context where posting task is not allowed");
    }

    PENDING_ASYNC_TASK.with(|x| {
      let mut x = x.borrow_mut();
      if x.is_some() {
        panic!("post_task called while another task is pending");
      }
      *x = Some(async move { Box::new(task.await) as AsyncTaskOutput }.boxed_local());
    });
  }

  /// Calls `callback` with a mutable resource of type `T`, if present.
  pub fn with_resource_mut<'c, T: 'static, R>(
    &'c self,
    callback: impl FnOnce(Result<&mut T, ()>) -> R,
  ) -> R {
    let mut resources = self.resources.borrow_mut();
    let Some(res) = resources
      .iter_mut()
      .filter_map(|x| x.downcast_mut::<T>())
      .next()
    else {
      tracing::warn!(resource_type = ?TypeId::of::<T>(), "resource not found");
      return callback(Err(()));
    };

    callback(Ok(res))
  }

  /// Validates and returns an immutable view into user memory.
  pub fn user_memory(&self, ptr: u64, size: u64) -> Result<&[u8], ()> {
    let Some(region) = self
      .program
      .unbound
      .cage
      .safe_deref_for_read(ptr as usize, size as usize)
    else {
      tracing::warn!(ptr, size, "invalid read");
      return Err(());
    };

    if size != 0 {
      // The region must not overlap with any previously dereferenced mutable regions
      if self
        .mutable_dereferenced_regions
        .iter()
        .filter_map(|x| x.get())
        .any(|x| nonnull_bytes_overlap(x, region))
      {
        tracing::warn!(ptr, size, "read overlapped with previous write");
        return Err(());
      }

      // Find a slot to record this dereference
      let Some(slot) = self
        .immutable_dereferenced_regions
        .iter()
        .find(|x| x.get().is_none())
      else {
        tracing::warn!(ptr, size, "too many reads");
        return Err(());
      };
      slot.set(Some(region));
    }

    Ok(unsafe { region.as_ref() })
  }

  /// Validates and returns a mutable view into user memory.
  pub fn user_memory_mut<'c>(
    &'c self,
    ptr: u64,
    size: u64,
  ) -> Result<MutableUserMemory<'a, 'b, 'c>, ()> {
    let Some(region) = self
      .program
      .unbound
      .cage
      .safe_deref_for_write(ptr as usize, size as usize)
    else {
      tracing::warn!(ptr, size, "invalid write");
      return Err(());
    };

    if size != 0 {
      // The region must not overlap with any other previously dereferenced mutable or immutable regions
      if self
        .mutable_dereferenced_regions
        .iter()
        .chain(self.immutable_dereferenced_regions.iter())
        .filter_map(|x| x.get())
        .any(|x| nonnull_bytes_overlap(x, region))
      {
        tracing::warn!(ptr, size, "write overlapped with previous read/write");
        return Err(());
      }

      // Find a slot to record this dereference
      let Some(slot) = self
        .mutable_dereferenced_regions
        .iter()
        .find(|x| x.get().is_none())
      else {
        tracing::warn!(ptr, size, "too many writes");
        return Err(());
      };
      slot.set(Some(region));
    }

    Ok(MutableUserMemory {
      _scope: self,
      region,
    })
  }
}

#[derive(Copy, Clone)]
struct AssumeSend<T>(T);
unsafe impl<T> Send for AssumeSend<T> {}

struct ExecContext {
  native_stack: DefaultStack,
  copy_stack: Box<[u8; SHADOW_STACK_SIZE]>,
}

impl ExecContext {
  fn new() -> Self {
    Self {
      native_stack: DefaultStack::new(NATIVE_STACK_SIZE)
        .expect("failed to initialize native stack"),
      copy_stack: Box::new([0u8; SHADOW_STACK_SIZE]),
    }
  }
}

/// A pending async task spawned by a helper.
pub type PendingAsyncTask = Pin<Box<dyn Future<Output = AsyncTaskOutput>>>;
/// The callback produced by a helper async task when it resumes.
pub type AsyncTaskOutput = Box<dyn FnOnce(&HelperScope) -> Result<u64, ()>>;

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Copy, Clone, Debug)]
enum PreemptionState {
  Inactive,
  Active(usize),
  Shutdown,
}

type PreemptionStateSignal = (Mutex<PreemptionState>, Condvar);

thread_local! {
  static RUST_TID: ThreadId = std::thread::current().id();
  static SIGUSR1_COUNTER: Cell< u64> = Cell::new(0);
  static ACTIVE_JIT_CODE_ZONE: ActiveJitCodeZone = ActiveJitCodeZone::default();
  static EXEC_CONTEXT_POOL: RefCell<Vec<ExecContext>> = Default::default();
  static PENDING_ASYNC_TASK: RefCell<Option<PendingAsyncTask>> = RefCell::new(None);
  static PREEMPTION_STATE: Arc<PreemptionStateSignal> = Arc::new((Mutex::new(PreemptionState::Inactive), Condvar::new()));
  static LOADING_PROGRAM_LOADER: Cell<*const ProgramLoader> = const { Cell::new(std::ptr::null()) };
}

struct BorrowedExecContext {
  ctx: ManuallyDrop<ExecContext>,
}

impl BorrowedExecContext {
  fn new() -> Self {
    let mut me = Self {
      ctx: ManuallyDrop::new(
        EXEC_CONTEXT_POOL.with(|x| x.borrow_mut().pop().unwrap_or_else(ExecContext::new)),
      ),
    };
    me.ctx.copy_stack.fill(0x8e);
    me
  }
}

impl Drop for BorrowedExecContext {
  fn drop(&mut self) {
    let ctx = unsafe { ManuallyDrop::take(&mut self.ctx) };
    EXEC_CONTEXT_POOL.with(|x| x.borrow_mut().push(ctx));
  }
}

#[derive(Default)]
struct ActiveJitCodeZone {
  valid: AtomicBool,
  code_range: Cell<(usize, usize)>,
  pointer_cage_protected_range: Cell<(usize, usize)>,
  yielder: Cell<Option<NonNull<Yielder<u64, Dispatch>>>>,
}

/// Hooks for observing program execution events.
pub trait ProgramEventListener: Send + Sync + 'static {
  /// Called after an async preemption is triggered.
  fn did_async_preempt(&self, _scope: &HelperScope) {}
  /// Called after yielding back to the async runtime.
  fn did_yield(&self) {}
  /// Called after throttling a program's execution.
  fn did_throttle(&self, _scope: &HelperScope) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
    None
  }
  /// Called after saving the shadow stack before yielding.
  fn did_save_shadow_stack(&self) {}
  /// Called after restoring the shadow stack on resume.
  fn did_restore_shadow_stack(&self) {}
}

/// No-op event listener implementation.
pub struct DummyProgramEventListener;
impl ProgramEventListener for DummyProgramEventListener {}

/// Default limit for the total JIT-compiled native code size of one program.
pub const DEFAULT_CODE_SIZE_LIMIT: usize = 1 << 20;

/// Prepares helper tables and loads eBPF programs.
pub struct ProgramLoader {
  helpers_inverse: HashMap<&'static str, i32>,
  event_listener: Arc<dyn ProgramEventListener>,
  helper_id_xor: u16,
  helpers: Arc<Vec<(u16, &'static str, Helper)>>,
  code_size_limit: usize,
}

/// A loaded program that is not yet pinned to a thread.
pub struct UnboundProgram {
  id: u64,
  _code_mem: MmapRaw,
  cage: PointerCage,
  helper_id_xor: u16,
  helpers: Arc<Vec<(u16, &'static str, Helper)>>,
  event_listener: Arc<dyn ProgramEventListener>,
  entrypoints: HashMap<String, Entrypoint>,
}

/// A program pinned to a specific thread and ready to execute.
pub struct Program {
  unbound: UnboundProgram,
  data: RefCell<HashMap<TypeId, Rc<dyn Any>>>,
  t: ThreadEnv,
}

#[derive(Copy, Clone)]
struct Entrypoint {
  code_ptr: usize,
  code_len: usize,
}

/// Time limits used to yield or throttle execution.
#[derive(Clone, Debug)]
pub struct TimesliceConfig {
  /// Maximum runtime before yielding to the async scheduler.
  pub max_run_time_before_yield: Duration,
  /// Maximum runtime before a throttle sleep is forced.
  pub max_run_time_before_throttle: Duration,
  /// Duration of the throttle sleep once triggered.
  pub throttle_duration: Duration,
}

/// Async runtime integration for yielding and sleeping.
pub trait Timeslicer {
  /// Sleep for the provided duration.
  fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;
  /// Yield to the async scheduler.
  fn yield_now(&self) -> impl Future<Output = ()>;
}

/// Global runtime environment for signal handlers.
#[derive(Copy, Clone)]
pub struct GlobalEnv(());

/// Per-thread runtime environment for preemption handling.
#[derive(Copy, Clone)]
pub struct ThreadEnv {
  _not_send_sync: std::marker::PhantomData<*const ()>,
}

impl GlobalEnv {
  /// Initializes global state and installs signal handlers.
  ///
  /// # Safety
  /// Must be called in a process that can install SIGUSR1/SIGSEGV handlers.
  pub unsafe fn new() -> Self {
    static INIT: Once = Once::new();

    // SIGUSR1 must be blocked during exception handling
    // Otherwise it seems that Linux gives up and throws an uncatchable SI_KERNEL SIGSEGV:
    //
    // [pid 517110] tgkill(517109, 517112, SIGUSR1 <unfinished ...>
    // [pid 517112] --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x793789be227e} ---
    // [pid 517109] write(15, "\1\0\0\0\0\0\0\0", 8 <unfinished ...>
    // [pid 517110] <... tgkill resumed>)      = 0
    // [pid 517109] <... write resumed>)       = 8
    // [pid 517112] --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=517109, si_uid=1000} ---
    // [pid 517109] recvfrom(57,  <unfinished ...>
    // [pid 517110] futex(0x79378abff5a8, FUTEX_WAIT_PRIVATE, 1, {tv_sec=0, tv_nsec=5999909} <unfinished ...>
    // [pid 517109] <... recvfrom resumed>"GET /write_rodata HTTP/1.1\r\nHost"..., 8192, 0, NULL, NULL) = 61
    // [pid 517112] --- SIGSEGV {si_signo=SIGSEGV, si_code=SI_KERNEL, si_addr=NULL} ---

    INIT.call_once(|| {
      let sa_mask = get_blocked_sigset();

      for (sig, handler) in [
        (libc::SIGUSR1, sigusr1_handler as *const () as usize),
        (libc::SIGSEGV, sigsegv_handler as *const () as usize),
      ] {
        let act = libc::sigaction {
          sa_sigaction: handler,
          sa_flags: libc::SA_SIGINFO,
          sa_mask,
          sa_restorer: None,
        };
        if libc::sigaction(sig, &act, std::ptr::null_mut()) != 0 {
          panic!("failed to setup handler for signal {}", sig);
        }
      }
    });

    Self(())
  }

  /// Initializes per-thread state and starts the async preemption watcher.
  pub fn init_thread(self, async_preemption_interval: Duration) -> ThreadEnv {
    struct DeferDrop(Arc<PreemptionStateSignal>);
    impl Drop for DeferDrop {
      fn drop(&mut self) {
        let x = &self.0;
        *x.0.lock() = PreemptionState::Shutdown;
        x.1.notify_one();
      }
    }

    thread_local! {
      static WATCHER: RefCell<Option<DeferDrop>> = RefCell::new(None);
    }

    if WATCHER.with(|x| x.borrow().is_some()) {
      return ThreadEnv {
        _not_send_sync: PhantomData,
      };
    }

    let preemption_state = PREEMPTION_STATE.with(|x| x.clone());

    unsafe {
      let tgid = libc::getpid();
      let tid = libc::gettid();

      std::thread::Builder::new()
        .name("preempt-watcher".to_string())
        .spawn(move || {
          let mut state = preemption_state.0.lock();
          loop {
            match *state {
              PreemptionState::Shutdown => break,
              PreemptionState::Inactive => {
                preemption_state.1.wait(&mut state);
              }
              PreemptionState::Active(_) => {
                let timeout = preemption_state.1.wait_while_for(
                  &mut state,
                  |x| matches!(x, PreemptionState::Active(_)),
                  async_preemption_interval,
                );
                if timeout.timed_out() {
                  let ret = libc::syscall(libc::SYS_tgkill, tgid, tid, libc::SIGUSR1);
                  if ret != 0 {
                    break;
                  }
                }
              }
            }
          }
        })
        .expect("failed to spawn preemption watcher");

      WATCHER.with(|x| {
        x.borrow_mut()
          .replace(DeferDrop(PREEMPTION_STATE.with(|x| x.clone())));
      });

      ThreadEnv {
        _not_send_sync: PhantomData,
      }
    }
  }
}

impl UnboundProgram {
  /// Pins the program to the current thread using a prepared `ThreadEnv`.
  pub fn pin_to_current_thread(self, t: ThreadEnv) -> Program {
    Program {
      unbound: self,
      data: RefCell::new(HashMap::new()),
      t,
    }
  }
}

pub struct PreemptionEnabled(());

impl PreemptionEnabled {
  pub fn new(_: ThreadEnv) -> Self {
    PREEMPTION_STATE.with(|x| {
      let mut notify = false;
      {
        let mut st = x.0.lock();
        let next = match *st {
          PreemptionState::Inactive => {
            notify = true;
            PreemptionState::Active(1)
          }
          PreemptionState::Active(n) => PreemptionState::Active(n + 1),
          PreemptionState::Shutdown => unreachable!(),
        };
        *st = next;
      }

      if notify {
        x.1.notify_one();
      }
    });
    Self(())
  }
}

impl Drop for PreemptionEnabled {
  fn drop(&mut self) {
    PREEMPTION_STATE.with(|x| {
      let mut st = x.0.lock();
      let next = match *st {
        PreemptionState::Active(1) => PreemptionState::Inactive,
        PreemptionState::Active(n) => {
          assert!(n > 1);
          PreemptionState::Active(n - 1)
        }
        PreemptionState::Inactive | PreemptionState::Shutdown => unreachable!(),
      };
      *st = next;
    });
  }
}

impl Program {
  /// Returns the unique program identifier.
  pub fn id(&self) -> u64 {
    self.unbound.id
  }

  pub fn thread_env(&self) -> ThreadEnv {
    self.t
  }

  /// Gets or creates shared typed data for this program instance.
  pub fn data<T: Default + 'static>(&self) -> Rc<T> {
    let mut data = self.data.borrow_mut();
    let entry = data.entry(TypeId::of::<T>());
    let entry = entry.or_insert_with(|| Rc::new(T::default()));
    entry.clone().downcast().unwrap()
  }

  pub fn has_section(&self, name: &str) -> bool {
    self.unbound.entrypoints.contains_key(name)
  }

  /// Runs the program entrypoint with the provided resources and calldata.
  pub async fn run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    preemption: &PreemptionEnabled,
  ) -> Result<i64, Error> {
    self
      ._run(
        timeslice, timeslicer, entrypoint, resources, calldata, preemption,
      )
      .await
      .map_err(Error)
  }

  async fn _run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    _: &PreemptionEnabled,
  ) -> Result<i64, RuntimeError> {
    let Some(entrypoint) = self.unbound.entrypoints.get(entrypoint).copied() else {
      return Err(RuntimeError::InvalidArgument("entrypoint not found"));
    };

    let entry = unsafe {
      std::mem::transmute::<
        _,
        unsafe extern "C" fn(ctx: usize, mem_len: usize, stack: usize, stack_len: usize) -> u64,
      >(entrypoint.code_ptr)
    };
    struct CoDropper<'a, Input, Yield, Return, DefaultStack: Stack>(
      ScopedCoroutine<'a, Input, Yield, Return, DefaultStack>,
    );
    impl<'a, Input, Yield, Return, DefaultStack: Stack> Drop
      for CoDropper<'a, Input, Yield, Return, DefaultStack>
    {
      fn drop(&mut self) {
        // Prevent the coroutine library from attempting to unwind the stack of the coroutine
        // and run destructors, because this stack might be running a signal handler and
        // it's not allowed to unwind from there.
        //
        // SAFETY: The coroutine stack only contains stack frames for JIT-compiled code and
        // carefully chosen Rust code that do not hold Droppable values, so it's safe to
        // skip destructors.
        unsafe {
          self.0.force_reset();
        }
      }
    }

    let mut ectx = BorrowedExecContext::new();

    if calldata.len() > MAX_CALLDATA_SIZE {
      return Err(RuntimeError::InvalidArgument("calldata too large"));
    }
    ectx.ctx.copy_stack[SHADOW_STACK_SIZE - calldata.len()..].copy_from_slice(calldata);
    let calldata_len = calldata.len();

    let program_ret: u64 = {
      let shadow_stack_top = self.unbound.cage.stack_top();
      let shadow_stack_bottom = self.unbound.cage.stack_bottom();
      let shadow_stack_ptr = AssumeSend(
        self
          .unbound
          .cage
          .safe_deref_for_write(self.unbound.cage.stack_bottom(), SHADOW_STACK_SIZE)
          .unwrap(),
      );
      let ctx = &mut *ectx.ctx;

      let mut co = AssumeSend(CoDropper(Coroutine::with_stack(
        &mut ctx.native_stack,
        move |yielder, _input| unsafe {
          ACTIVE_JIT_CODE_ZONE.with(|x| {
            x.yielder.set(NonNull::new(yielder as *const _ as *mut _));
          });
          let calldata_start = shadow_stack_top - calldata_len;
          let stack_top = calldata_start & !0x7;
          let stack_len = stack_top - shadow_stack_bottom;
          entry(
            calldata_start,
            calldata_start,
            shadow_stack_bottom,
            stack_len,
          )
        },
      )));

      let mut last_yield_time = Instant::now();
      let mut last_throttle_time = Instant::now();
      let mut yielder: Option<AssumeSend<NonNull<Yielder<u64, Dispatch>>>> = None;
      let mut resume_input: u64 = 0;
      let mut did_throttle = false;
      let mut shadow_stack_saved = true;
      let mut rust_tid_sigusr1_counter = (RUST_TID.with(|x| *x), SIGUSR1_COUNTER.with(|x| x.get()));
      let mut prev_async_task_output: Option<(&'static str, AsyncTaskOutput)> = None;
      let mut invoke_scope = InvokeScope {
        data: HashMap::new(),
      };

      loop {
        ACTIVE_JIT_CODE_ZONE.with(|x| {
          x.code_range.set((
            entrypoint.code_ptr,
            entrypoint.code_ptr + entrypoint.code_len,
          ));
          x.yielder.set(yielder.map(|x| x.0));
          x.pointer_cage_protected_range
            .set(self.unbound.cage.protected_range_without_margins());
          compiler_fence(Ordering::Release);
          x.valid.store(true, Ordering::Relaxed);
        });

        if shadow_stack_saved {
          shadow_stack_saved = false;

          // restore shadow stack
          unsafe {
            std::ptr::copy_nonoverlapping(
              ctx.copy_stack.as_ptr() as *const u8,
              shadow_stack_ptr.0.as_ptr() as *mut u8,
              SHADOW_STACK_SIZE,
            );
          }

          self.unbound.event_listener.did_restore_shadow_stack();
        }

        // If the previous iteration wants to write back to machine state
        if let Some((helper_name, prev_async_task_output)) = prev_async_task_output.take() {
          resume_input = prev_async_task_output(&HelperScope {
            program: self,
            invoke: RefCell::new(&mut invoke_scope),
            resources: RefCell::new(resources),
            mutable_dereferenced_regions: unsafe { std::mem::zeroed() },
            immutable_dereferenced_regions: unsafe { std::mem::zeroed() },
            can_post_task: false,
          })
          .map_err(|_| RuntimeError::AsyncHelperError(helper_name))?;
        }

        let ret = co.0 .0.resume(resume_input);
        ACTIVE_JIT_CODE_ZONE.with(|x| {
          x.valid.store(false, Ordering::Relaxed);
          compiler_fence(Ordering::Release);
          yielder = x.yielder.get().map(AssumeSend);
        });

        let dispatch: Dispatch = match ret {
          CoroutineResult::Return(x) => break x,
          CoroutineResult::Yield(x) => x,
        };

        // restore signal mask of current thread
        if dispatch.memory_access_error.is_some() || dispatch.async_preemption {
          unsafe {
            let unblock = get_blocked_sigset();
            libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
          }
        }

        if let Some(si_addr) = dispatch.memory_access_error {
          let vaddr = si_addr - self.unbound.cage.offset();
          return Err(RuntimeError::MemoryFault(vaddr));
        }

        // Clear pending task if something else has set it
        PENDING_ASYNC_TASK.with(|x| x.borrow_mut().take());
        let mut helper_name: &'static str = "";

        let mut helper_scope = HelperScope {
          program: self,
          invoke: RefCell::new(&mut invoke_scope),
          resources: RefCell::new(resources),
          mutable_dereferenced_regions: unsafe { std::mem::zeroed() },
          immutable_dereferenced_regions: unsafe { std::mem::zeroed() },
          can_post_task: false,
        };

        if dispatch.async_preemption {
          self
            .unbound
            .event_listener
            .did_async_preempt(&mut helper_scope);
        } else {
          // validator should ensure all helper indexes are present in the table
          let Some((_, got_helper_name, helper)) = self
            .unbound
            .helpers
            .get(
              ((dispatch.index & 0xffff) as u16 ^ self.unbound.helper_id_xor).wrapping_sub(1)
                as usize,
            )
            .copied()
          else {
            panic!("unknown helper index: {}", dispatch.index);
          };
          helper_name = got_helper_name;

          helper_scope.can_post_task = true;
          resume_input = helper(
            &mut helper_scope,
            dispatch.arg1,
            dispatch.arg2,
            dispatch.arg3,
            dispatch.arg4,
            dispatch.arg5,
          )
          .map_err(|()| RuntimeError::HelperError(helper_name))?;
          helper_scope.can_post_task = false;
        }

        let pending_async_task = PENDING_ASYNC_TASK.with(|x| x.borrow_mut().take());

        // Fast path: do not read timestamp if no thread migration or async preemption happened
        let new_rust_tid_sigusr1_counter =
          (RUST_TID.with(|x| *x), SIGUSR1_COUNTER.with(|x| x.get()));
        if new_rust_tid_sigusr1_counter == rust_tid_sigusr1_counter && pending_async_task.is_none()
        {
          continue;
        }

        rust_tid_sigusr1_counter = new_rust_tid_sigusr1_counter;

        let now = Instant::now();
        let should_throttle = now > last_throttle_time
          && now.duration_since(last_throttle_time) >= timeslice.max_run_time_before_throttle;
        let should_yield = now > last_yield_time
          && now.duration_since(last_yield_time) >= timeslice.max_run_time_before_yield;
        if should_throttle || should_yield || pending_async_task.is_some() {
          // We are about to yield control to tokio. Save the shadow stack, and release the guard.
          shadow_stack_saved = true;
          unsafe {
            std::ptr::copy_nonoverlapping(
              shadow_stack_ptr.0.as_ptr() as *const u8,
              ctx.copy_stack.as_mut_ptr() as *mut u8,
              SHADOW_STACK_SIZE,
            );
          }
          self.unbound.event_listener.did_save_shadow_stack();

          // we are now free to give up control of current thread to other async tasks

          if should_throttle {
            if !did_throttle {
              did_throttle = true;
              tracing::warn!("throttling program");
            }
            timeslicer.sleep(timeslice.throttle_duration).await;
            let now = Instant::now();
            last_throttle_time = now;
            last_yield_time = now;
            let task = self.unbound.event_listener.did_throttle(&mut helper_scope);
            if let Some(task) = task {
              task.await;
            }
          } else if should_yield {
            timeslicer.yield_now().await;
            let now = Instant::now();
            last_yield_time = now;
            self.unbound.event_listener.did_yield();
          }

          // Now we have released all exclusive resources and can safely execute the async task
          if let Some(pending_async_task) = pending_async_task {
            let async_start = Instant::now();
            prev_async_task_output = Some((helper_name, pending_async_task.await));
            let async_dur = async_start.elapsed();
            last_throttle_time += async_dur;
            last_yield_time += async_dur;
          }
        }
      }
    };

    Ok(program_ret as i64)
  }
}

struct Vm(NonNull<crate::ubpf::ubpf_vm>);

impl Vm {
  fn new(cage: &PointerCage) -> Self {
    let vm = NonNull::new(unsafe { crate::ubpf::ubpf_create() }).expect("failed to create ubpf_vm");
    unsafe {
      crate::ubpf::ubpf_toggle_bounds_check(vm.as_ptr(), false);
      crate::ubpf::ubpf_set_jit_pointer_mask_and_offset(vm.as_ptr(), cage.mask(), cage.offset());
    }
    Self(vm)
  }
}

impl Drop for Vm {
  fn drop(&mut self) {
    unsafe {
      crate::ubpf::ubpf_destroy(self.0.as_ptr());
    }
  }
}

struct LoaderValidationScope {
  previous: *const ProgramLoader,
}

impl LoaderValidationScope {
  fn new(loader: &ProgramLoader) -> Self {
    let previous = LOADING_PROGRAM_LOADER.with(|x| {
      let previous = x.get();
      x.set(loader as *const _);
      previous
    });
    Self { previous }
  }
}

impl Drop for LoaderValidationScope {
  fn drop(&mut self) {
    LOADING_PROGRAM_LOADER.with(|x| x.set(self.previous));
  }
}

impl ProgramLoader {
  /// Creates a new `ProgramLoader` to load eBPF code.
  pub fn new(
    rng: &mut impl rand::Rng,
    event_listener: Arc<dyn ProgramEventListener>,
    raw_helpers: &[&[(&'static str, Helper)]],
  ) -> Self {
    let helper_id_xor = rng.gen::<u16>();
    let mut helpers_inverse: HashMap<&'static str, i32> = HashMap::new();
    // Collect first to a HashMap then to a Vec to deduplicate
    let mut shuffled_helpers = raw_helpers
      .iter()
      .flat_map(|x| x.iter().copied())
      .collect::<HashMap<_, _>>()
      .into_iter()
      .collect::<Vec<_>>();
    shuffled_helpers.shuffle(rng);
    let mut helpers: Vec<(u16, &'static str, Helper)> = Vec::with_capacity(shuffled_helpers.len());

    assert!(shuffled_helpers.len() <= 65535);

    for (i, (name, helper)) in shuffled_helpers.into_iter().enumerate() {
      let entropy = rng.gen::<u16>() & 0x7fff;
      helpers.push((entropy, name, helper));
      helpers_inverse.insert(
        name,
        (((entropy as usize) << 16) | ((i + 1) ^ (helper_id_xor as usize))) as i32,
      );
    }

    tracing::info!(?helpers_inverse, "generated helper table");
    Self {
      helper_id_xor,
      helpers: Arc::new(helpers),
      helpers_inverse,
      event_listener,
      code_size_limit: DEFAULT_CODE_SIZE_LIMIT,
    }
  }

  /// Sets the maximum total size of JIT-compiled native code per program.
  ///
  /// Must be a non-zero multiple of 64 KiB so the code region stays
  /// page-aligned on all supported page sizes.
  ///
  /// Note for arm64: conditional branches and literal loads emitted by the
  /// JIT have a ±1 MiB range, and a section's helper calls reference a
  /// literal pool at the end of that section's code. Any single ELF section
  /// whose jitted code exceeds ~1 MiB is therefore rejected at load time
  /// ("ubpf: code translation failed") regardless of this limit; raising it
  /// past 1 MiB only adds room for more or larger sections within that
  /// per-section ceiling. x86-64 has no such per-section constraint.
  pub fn with_code_size_limit(mut self, limit: usize) -> Self {
    assert!(
      limit > 0 && limit % (64 * 1024) == 0,
      "code size limit must be a non-zero multiple of 64 KiB"
    );
    assert!(limit <= u32::MAX as usize, "code size limit must fit in u32");
    self.code_size_limit = limit;
    self
  }

  /// Loads an ELF image into a new `UnboundProgram`.
  pub fn load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, Error> {
    self._load(rng, elf).map_err(Error)
  }

  fn _load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, RuntimeError> {
    let start_time = Instant::now();
    let cage = PointerCage::new(rng, SHADOW_STACK_SIZE, elf.len())?;
    let vm = Vm::new(&cage);

    // Relocate ELF
    let code_sections = {
      // XXX: Although we are writing to the data region, we need to use `safe_deref_for_read`
      // here because the `_write` variant checks that the requested region is within the
      // stack. It's safe here because `freeze_data` is not yet called.
      let mut data = cage
        .safe_deref_for_read(cage.data_bottom(), elf.len())
        .unwrap();
      let data = unsafe { data.as_mut() };
      data.copy_from_slice(elf);

      link_elf(data, cage.data_bottom(), &self.helpers_inverse).map_err(RuntimeError::Linker)?
    };
    cage.freeze_data();

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size < 0 {
      return Err(RuntimeError::PlatformError("failed to get page size"));
    }
    let page_size = page_size as usize;

    // Allocate code memory
    let guard_size_before = rng.gen_range(16..128) * page_size;
    let mut guard_size_after = rng.gen_range(16..128) * page_size;

    let code_len_allocated = self.code_size_limit;
    let code_mem = MmapRaw::from(
      MmapOptions::new()
        .len(code_len_allocated + guard_size_before + guard_size_after)
        .map_anon()
        .map_err(|_| RuntimeError::PlatformError("failed to allocate code memory"))?,
    );

    unsafe {
      if crate::ubpf::ubpf_register_external_dispatcher(
        vm.0.as_ptr(),
        Some(tls_dispatcher),
        Some(std_validator),
      ) != 0
      {
        return Err(RuntimeError::PlatformError(
          "ubpf: failed to register external dispatcher",
        ));
      }
      if libc::mprotect(
        code_mem.as_mut_ptr() as *mut _,
        guard_size_before,
        libc::PROT_NONE,
      ) != 0
        || libc::mprotect(
          code_mem
            .as_mut_ptr()
            .offset((guard_size_before + code_len_allocated) as isize) as *mut _,
          guard_size_after,
          libc::PROT_NONE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError("failed to protect guard pages"));
      }
    }

    let mut entrypoints: HashMap<String, Entrypoint> = HashMap::new();

    unsafe {
      // Translate eBPF to native code
      let mut code_slice = std::slice::from_raw_parts_mut(
        code_mem.as_mut_ptr().offset(guard_size_before as isize),
        code_len_allocated,
      );
      for (section_name, code_vaddr_size) in code_sections {
        if code_slice.is_empty() {
          return Err(RuntimeError::InvalidArgument(
            "no space left for jit compilation",
          ));
        }

        crate::ubpf::ubpf_unload_code(vm.0.as_ptr());

        let mut errmsg_ptr = std::ptr::null_mut();
        let code = cage
          .safe_deref_for_read(code_vaddr_size.0, code_vaddr_size.1)
          .unwrap();
        let ret = {
          let validation_scope = LoaderValidationScope::new(self);
          let ret = crate::ubpf::ubpf_load(
            vm.0.as_ptr(),
            code.as_ptr() as *const _,
            code.len() as u32,
            &mut errmsg_ptr,
          );
          drop(validation_scope);
          ret
        };
        if ret != 0 {
          let errmsg = if errmsg_ptr.is_null() {
            "".to_string()
          } else {
            CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned()
          };
          if !errmsg_ptr.is_null() {
            libc::free(errmsg_ptr as _);
          }
          tracing::error!(section_name, error = errmsg, "failed to load code");
          return Err(RuntimeError::InvalidArgumentOwned(format!(
            "ubpf: code load failed: {errmsg}"
          )));
        }

        let mut written_len = code_slice.len();
        let ret = crate::ubpf::ubpf_translate_ex(
          vm.0.as_ptr(),
          code_slice.as_mut_ptr(),
          &mut written_len,
          &mut errmsg_ptr,
          crate::ubpf::JitMode_ExtendedJitMode,
        );
        if ret != 0 {
          let errmsg = if errmsg_ptr.is_null() {
            "".to_string()
          } else {
            CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned()
          };
          if !errmsg_ptr.is_null() {
            libc::free(errmsg_ptr as _);
          }
          tracing::error!(section_name, error = errmsg, "failed to translate code");
          return Err(RuntimeError::PlatformError("ubpf: code translation failed"));
        }

        assert!(written_len <= code_slice.len());
        entrypoints.insert(
          section_name,
          Entrypoint {
            code_ptr: code_mem.as_ptr() as usize + guard_size_before + code_len_allocated
              - code_slice.len(),
            code_len: written_len,
          },
        );
        code_slice = &mut code_slice[written_len..];
      }

      // Align up code_len to page size
      let unpadded_code_len = code_len_allocated - code_slice.len();
      if std::env::var("JIT_DUMP").is_ok() {
        eprintln!(
          "[JITSIZE] elf={} native_unpadded={} buffer={}",
          elf.len(),
          unpadded_code_len,
          code_len_allocated
        );
        let native = std::slice::from_raw_parts(
          code_mem.as_ptr().offset(guard_size_before as isize),
          unpadded_code_len,
        );
        let mut hex = String::with_capacity(native.len() * 2);
        for b in native {
          hex.push_str(&format!("{b:02x}"));
        }
        eprintln!("[JITHEX] {hex}");
      }
      let code_len = (unpadded_code_len + page_size - 1) & !(page_size - 1);
      assert!(code_len <= code_len_allocated);

      // RW- -> R-X
      // Also make the unused part of the pre-allocated code region PROT_NONE
      if libc::mprotect(
        code_mem.as_mut_ptr().offset(guard_size_before as isize) as *mut _,
        code_len,
        libc::PROT_READ | libc::PROT_EXEC,
      ) != 0
        || (code_len < code_len_allocated
          && libc::mprotect(
            code_mem
              .as_mut_ptr()
              .offset((guard_size_before + code_len) as isize) as *mut _,
            code_len_allocated - code_len,
            libc::PROT_NONE,
          ) != 0)
      {
        return Err(RuntimeError::PlatformError("failed to protect code memory"));
      }

      guard_size_after += code_len_allocated - code_len;

      tracing::info!(
        elf_size = elf.len(),
        native_code_addr = ?code_mem.as_ptr(),
        native_code_size = code_len,
        native_code_size_unpadded = unpadded_code_len,
        guard_size_before,
        guard_size_after,
        duration = ?start_time.elapsed(),
        cage_ptr = ?cage.region().as_ptr(),
        cage_mapped_size = cage.region().len(),
        "jit compiled program"
      );

      Ok(UnboundProgram {
        id: NEXT_PROGRAM_ID.fetch_add(1, Ordering::Relaxed),
        _code_mem: code_mem,
        cage,
        helper_id_xor: self.helper_id_xor,
        helpers: self.helpers.clone(),
        event_listener: self.event_listener.clone(),
        entrypoints,
      })
    }
  }
}

#[derive(Default)]
struct Dispatch {
  async_preemption: bool,
  memory_access_error: Option<usize>,

  index: u32,
  arg1: u64,
  arg2: u64,
  arg3: u64,
  arg4: u64,
  arg5: u64,
}

unsafe extern "C" fn tls_dispatcher(
  arg1: u64,
  arg2: u64,
  arg3: u64,
  arg4: u64,
  arg5: u64,
  index: std::os::raw::c_uint,
  _cookie: *mut std::os::raw::c_void,
) -> u64 {
  let yielder = ACTIVE_JIT_CODE_ZONE
    .with(|x| x.yielder.get())
    .expect("no yielder");
  let yielder = yielder.as_ref();
  let ret = yielder.suspend(Dispatch {
    async_preemption: false,
    memory_access_error: None,
    index,
    arg1,
    arg2,
    arg3,
    arg4,
    arg5,
  });
  ret
}

unsafe extern "C" fn std_validator(
  index: std::os::raw::c_uint,
  _vm: *const crate::ubpf::ubpf_vm,
) -> bool {
  let loader = LOADING_PROGRAM_LOADER.with(|x| x.get());
  if loader.is_null() {
    return false;
  }
  let loader = &*loader;
  let entropy = (index >> 16) & 0xffff;
  let index = (((index & 0xffff) as u16) ^ loader.helper_id_xor).wrapping_sub(1);
  loader.helpers.get(index as usize).map(|x| x.0) == Some(entropy as u16)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).uc_mcontext.pc as usize
}

unsafe extern "C" fn sigsegv_handler(
  _sig: i32,
  siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  let fail = || restore_default_signal_handler(libc::SIGSEGV);

  let Some((jit_code_zone, pointer_cage, yielder)) = ACTIVE_JIT_CODE_ZONE.with(|x| {
    if x.valid.load(Ordering::Relaxed) {
      compiler_fence(Ordering::Acquire);
      Some((
        x.code_range.get(),
        x.pointer_cage_protected_range.get(),
        x.yielder.get(),
      ))
    } else {
      None
    }
  }) else {
    return fail();
  };

  let pc = program_counter(uctx);

  if pc < jit_code_zone.0 || pc >= jit_code_zone.1 {
    return fail();
  }

  // SEGV_ACCERR
  if (*siginfo).si_code != 2 {
    return fail();
  }

  let si_addr = (*siginfo).si_addr() as usize;
  if si_addr < pointer_cage.0 || si_addr >= pointer_cage.1 {
    return fail();
  }

  let yielder = yielder.expect("no yielder").as_ref();
  yielder.suspend(Dispatch {
    memory_access_error: Some(si_addr),
    ..Default::default()
  });
}

unsafe extern "C" fn sigusr1_handler(
  _sig: i32,
  _siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  SIGUSR1_COUNTER.with(|x| x.set(x.get() + 1));

  let Some((jit_code_zone, yielder)) = ACTIVE_JIT_CODE_ZONE.with(|x| {
    if x.valid.load(Ordering::Relaxed) {
      compiler_fence(Ordering::Acquire);
      Some((x.code_range.get(), x.yielder.get()))
    } else {
      None
    }
  }) else {
    return;
  };
  let pc = program_counter(uctx);
  if pc < jit_code_zone.0 || pc >= jit_code_zone.1 {
    return;
  }

  let yielder = yielder.expect("no yielder").as_ref();
  yielder.suspend(Dispatch {
    async_preemption: true,
    ..Default::default()
  });
}

unsafe fn restore_default_signal_handler(signum: i32) {
  let act = libc::sigaction {
    sa_sigaction: libc::SIG_DFL,
    sa_flags: libc::SA_SIGINFO,
    sa_mask: std::mem::zeroed(),
    sa_restorer: None,
  };
  if libc::sigaction(signum, &act, std::ptr::null_mut()) != 0 {
    libc::abort();
  }
}

fn get_blocked_sigset() -> libc::sigset_t {
  unsafe {
    let mut s: libc::sigset_t = std::mem::zeroed();
    libc::sigaddset(&mut s, libc::SIGUSR1);
    libc::sigaddset(&mut s, libc::SIGSEGV);
    s
  }
}
