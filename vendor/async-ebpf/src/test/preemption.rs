use std::{
  sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
  },
  time::Duration,
};

use crate::{
  program::{GlobalEnv, PreemptionEnabled, ProgramEventListener, ProgramLoader, TimesliceConfig},
  test_util::{compile_ebpf, TokioTimeslicer},
};

const LOOP_ITERS: u64 = 10_000_000;
const EXPECTED_SUM: i64 = (LOOP_ITERS / 8 * 28) as i64;

const STATEFUL_LOOP: &str = r#"
#define LOOP_ITERS 10000000ULL

unsigned long long __attribute__((section("test"))) entry(void) {
  volatile unsigned long long guard = 0x1122334455667788ULL;
  volatile unsigned long long sum = 0;

  for (unsigned long long i = 0; i < LOOP_ITERS; i++) {
    sum += i & 7;
    guard ^= i | 1;
    guard ^= i | 1;
  }

  if (guard != 0x1122334455667788ULL) {
    return 0xffffffffffffffffULL;
  }

  return sum;
}
"#;

#[derive(Default)]
struct CountingEventListener {
  async_preempts: AtomicUsize,
  yields: AtomicUsize,
  saves: AtomicUsize,
  restores: AtomicUsize,
}

impl ProgramEventListener for CountingEventListener {
  fn did_async_preempt(&self, _: &crate::program::HelperScope) {
    self.async_preempts.fetch_add(1, Ordering::SeqCst);
  }

  fn did_yield(&self) {
    self.yields.fetch_add(1, Ordering::SeqCst);
  }

  fn did_save_shadow_stack(&self) {
    self.saves.fetch_add(1, Ordering::SeqCst);
  }

  fn did_restore_shadow_stack(&self) {
    self.restores.fetch_add(1, Ordering::SeqCst);
  }
}

#[test]
fn test_async_preemption_preserves_guest_state() {
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::from_secs(60),
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, false);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(events.async_preempts.load(Ordering::SeqCst) > 0);
  assert_eq!(events.yields.load(Ordering::SeqCst), 0);
  assert_eq!(events.saves.load(Ordering::SeqCst), 0);
  assert_eq!(events.restores.load(Ordering::SeqCst), 1);
  assert_eq!(heartbeat_ticks, 0);
}

#[test]
fn test_async_preemption_yields_to_async_runtime() {
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::ZERO,
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, true);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(events.async_preempts.load(Ordering::SeqCst) > 0);
  assert!(events.yields.load(Ordering::SeqCst) > 0);
  assert!(events.saves.load(Ordering::SeqCst) > 0);
  assert_eq!(
    events.restores.load(Ordering::SeqCst),
    events.saves.load(Ordering::SeqCst) + 1
  );
  assert!(heartbeat_ticks > 0);
}

fn run_preempted_program(
  timeslice: TimesliceConfig,
  run_heartbeat: bool,
) -> (i64, Arc<CountingEventListener>, usize) {
  std::thread::spawn(move || {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_io()
      .enable_time()
      .build()
      .unwrap();

    runtime.block_on(async move {
      let binary = compile_ebpf(STATEFUL_LOOP.as_bytes().to_vec())
        .await
        .unwrap();
      let global = unsafe { GlobalEnv::new() };
      let thread = global.init_thread(Duration::from_millis(2));
      let events = Arc::new(CountingEventListener::default());
      let loader = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[]);
      let program = loader
        .load(&mut rand::thread_rng(), &binary)
        .unwrap()
        .pin_to_current_thread(thread);
      let preemption = PreemptionEnabled::new(thread);

      let stop_heartbeat = Arc::new(AtomicBool::new(false));
      let heartbeat_ticks = Arc::new(AtomicUsize::new(0));
      let heartbeat = if run_heartbeat {
        let stop_heartbeat = stop_heartbeat.clone();
        let heartbeat_ticks = heartbeat_ticks.clone();
        Some(tokio::spawn(async move {
          while !stop_heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
            heartbeat_ticks.fetch_add(1, Ordering::SeqCst);
          }
        }))
      } else {
        None
      };

      let mut resources: [&mut dyn std::any::Any; 0] = [];
      let ret = program
        .run(
          &timeslice,
          &TokioTimeslicer,
          "test",
          &mut resources,
          &[],
          &preemption,
        )
        .await
        .unwrap();

      stop_heartbeat.store(true, Ordering::SeqCst);
      if let Some(heartbeat) = heartbeat {
        heartbeat.await.unwrap();
      }

      (ret, events, heartbeat_ticks.load(Ordering::SeqCst))
    })
  })
  .join()
  .unwrap()
}
