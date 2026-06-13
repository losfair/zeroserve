use std::{any::Any, process::Stdio, sync::Arc, time::Duration};

use futures::Future;
use tokio::{io::AsyncWriteExt, process::Command};

use crate::{
  error::Error,
  helpers::Helper,
  program::{
    DummyProgramEventListener, GlobalEnv, PreemptionEnabled, ProgramLoader, ThreadEnv,
    TimesliceConfig, Timeslicer,
  },
};

/// `Timeslicer` implementation backed by Tokio.
pub struct TokioTimeslicer;

impl Timeslicer for TokioTimeslicer {
  fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
    tokio::time::sleep(duration)
  }

  fn yield_now(&self) -> impl Future<Output = ()> {
    tokio::task::yield_now()
  }
}

/// Compiles C source to an eBPF ELF object using LLVM tools.
pub async fn compile_ebpf(src: Vec<u8>) -> anyhow::Result<Vec<u8>> {
  let mut clang = Command::new("clang")
    .arg("-target")
    .arg("bpf")
    .arg("-emit-llvm")
    .arg("-c")
    .arg("-x")
    .arg("c")
    .arg("-")
    .arg("-o")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut clang_stdin = clang.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = clang_stdin.write_all(&src).await;
  });

  let mut llvm_link = Command::new("llvm-link")
    .arg("-o")
    .arg("-")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut clang_stdout = clang.stdout.take().unwrap();
  let mut llvm_link_stdin = llvm_link.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut clang_stdout, &mut llvm_link_stdin).await;
  });

  let mut opt = Command::new("opt")
    .arg("-O2")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut llvm_link_stdout = llvm_link.stdout.take().unwrap();
  let mut opt_stdin = opt.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut llvm_link_stdout, &mut opt_stdin).await;
  });

  let mut llc = Command::new("llc")
    .arg("-march=bpf")
    .arg("-bpf-stack-size=4096")
    .arg("-mcpu=v3")
    .arg("-filetype=obj")
    .arg("-o")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut opt_stdout = opt.stdout.take().unwrap();
  let mut llc_stdin = llc.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut opt_stdout, &mut llc_stdin).await;
  });

  let mut llvm_objcopy = Command::new("llvm-objcopy")
    .arg("--remove-section")
    .arg(".text")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut llc_stdout = llc.stdout.take().unwrap();
  let mut llvm_objcopy_stdin = llvm_objcopy.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut llc_stdout, &mut llvm_objcopy_stdin).await;
  });

  let (clang_out, llvm_link_out, opt_out, llc_out, output) = tokio::join!(
    clang.wait(),
    llvm_link.wait(),
    opt.wait(),
    llc.wait(),
    llvm_objcopy.wait_with_output()
  );
  let output = output?;
  let exit_status_list = [
    clang_out?,
    llvm_link_out?,
    opt_out?,
    llc_out?,
    output.status,
  ];
  if exit_status_list.iter().any(|x| !x.success()) {
    anyhow::bail!("one or more commands failed");
  }

  Ok(output.stdout)
}

/// Creates a default global and thread environment for tests.
pub fn gt_env() -> (GlobalEnv, ThreadEnv) {
  let g = unsafe { GlobalEnv::new() };
  let t = g.init_thread(Duration::from_millis(10));
  (g, t)
}

/// Returns a timeslice configuration suitable for tests.
pub fn timeslice_config() -> TimesliceConfig {
  TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(10),
    max_run_time_before_yield: Duration::from_millis(5),
    throttle_duration: Duration::from_millis(1),
  }
}

/// Options for running a single program in tests.
pub struct RunOpts<'a, 'b> {
  /// Helper tables to register with the loader.
  pub helpers: Vec<&'static [(&'static str, Helper)]>,
  /// Entrypoint name to invoke.
  pub entrypoint: &'a str,
  /// Calldata passed to the program.
  pub calldata: &'a [u8],
  /// Host resources exposed to helpers.
  pub resources: &'a mut [&'b mut dyn Any],
}

impl<'a, 'b> RunOpts<'a, 'b> {
  /// Creates options with no calldata or resources.
  pub fn simple(helpers: Vec<&'static [(&'static str, Helper)]>, entrypoint: &'a str) -> Self {
    Self {
      helpers,
      entrypoint,
      calldata: &[],
      resources: &mut [],
    }
  }
}

/// Compiles and runs a single program, returning its result.
pub async fn run_one_program(opts: RunOpts<'_, '_>, code: &str) -> Result<i64, Error> {
  let (_, t_env) = gt_env();

  let binary = compile_ebpf(code.as_bytes().to_vec()).await.unwrap();
  let helpers = opts.helpers;

  // ensure the Send trait bound works
  let prog = tokio::task::spawn_blocking(move || {
    let loader = ProgramLoader::new(
      &mut rand::thread_rng(),
      Arc::new(DummyProgramEventListener),
      &helpers,
    );
    loader.load(&mut rand::thread_rng(), &binary)
  })
  .await
  .unwrap()
  .unwrap();

  let prog = prog.pin_to_current_thread(t_env);
  prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      opts.entrypoint,
      opts.resources,
      opts.calldata,
      &PreemptionEnabled::new(t_env),
    )
    .await
}
