use std::time::Duration;

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  program::HelperScope,
  test_util::{run_one_program, RunOpts},
};

static HELPERS: &'static [(&'static str, Helper)] = &[
  ("return_5", h_return_5),
  ("return_7_async", h_return_7_async),
];

#[tokio::test]
#[tracing_test::traced_test]
async fn test_sync_and_async_call() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  extern int return_5(void);
  extern int return_7_async(void);
  int __attribute__((section("test"))) entry(void) {
    int a = return_5();
    int b = return_5();
    int c = return_5();
    int d = return_7_async();
    int e = return_7_async();
    return a + b + c + d + e;
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, 5 * 3 + 7 * 2);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_calldata() {
  let v_100 = 100u64.to_le_bytes();

  let ret = run_one_program(
    RunOpts {
      helpers: vec![HELPERS],
      entrypoint: "test",
      calldata: &v_100,
      resources: &mut [],
    },
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *input) {
    return *input + 1;
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, 101);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_write_rodata() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  extern int return_5(const char *x);
  unsigned long long __attribute__((section("test"))) entry() {
    const char *rostr = "test";
    *(char *) rostr = 'a';
    return_5(rostr); // force side effect
    return 0;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_read_past_stack() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    return *bad;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_write_past_stack() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    *bad = 1;
    return 0;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_read_null_ptr() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  extern char * return_5(void);
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    char *p = return_5() - 5;
    return *p;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

fn h_return_5(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  Ok(5)
}

fn h_return_7_async(
  scope: &HelperScope,
  _: u64,
  _: u64,
  _: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  scope.post_task(async move {
    tokio::time::sleep(Duration::from_millis(5)).await;
    |_: &HelperScope| Ok(7)
  });
  Ok(0)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_custom_code_size_limit() {
  use crate::program::{DummyProgramEventListener, ProgramLoader};
  use crate::test_util::compile_ebpf;
  use std::sync::Arc;

  let binary = compile_ebpf(
    br#"
  int __attribute__((section("test"))) entry(void) {
    return 42;
  }
  "#
    .to_vec(),
  )
  .await
  .unwrap();

  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(64 * 1024);
  loader.load(&mut rand::thread_rng(), &binary).unwrap();
}

#[test]
#[should_panic(expected = "multiple of 64 KiB")]
fn test_invalid_code_size_limit() {
  use crate::program::{DummyProgramEventListener, ProgramLoader};
  use std::sync::Arc;

  let _ = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(4096);
}
