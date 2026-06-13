use std::{sync::Arc, time::Instant};

use async_ebpf::{
  helpers::Helper,
  program::{DummyProgramEventListener, HelperScope, PreemptionEnabled, Program, ProgramLoader},
  test_util::{compile_ebpf, gt_env, timeslice_config, TokioTimeslicer},
};
use criterion::{criterion_group, criterion_main, measurement::WallTime, Bencher, Criterion};
use tokio::runtime::Runtime;

fn criterion_benchmark(c: &mut Criterion) {
  c.bench_function("run program", |b| {
    let (rt, prog) = compile_and_load(
      r#"
  int __attribute__((section("test"))) entry(void) {
    return 42;
  }
  "#,
      &[],
    );
    let mut b = b.to_async(&rt);

    let preemption = PreemptionEnabled::new(prog.thread_env());
    b.iter(|| async {
      let ret = prog
        .run(
          &timeslice_config(),
          &TokioTimeslicer,
          "test",
          &mut [],
          b"",
          &preemption,
        )
        .await
        .unwrap();
      assert_eq!(ret, 42);
    });
  });

  let host_invoke_bench = |b: &mut Bencher<WallTime>, use_async: bool| {
    let (rt, prog) = compile_and_load(
      r#"
  extern unsigned long long return_42(void);
  int __attribute__((section("test"))) entry(unsigned long long *iter_p) {
    int iter = *iter_p;
    unsigned long long output = 0;
    for(int i = 0; i < iter; i++) output += return_42();
    return output;
  }
  "#,
      &[if use_async {
        &[("return_42", |scope, _, _, _, _, _| -> Result<u64, ()> {
          scope.post_task(async { |_: &HelperScope| Ok(42) });
          Ok(0)
        })]
      } else {
        &[("return_42", |_, _, _, _, _, _| -> Result<u64, ()> {
          Ok(42)
        })]
      }],
    );
    let mut b = b.to_async(&rt);
    let preemption = PreemptionEnabled::new(prog.thread_env());

    b.iter_custom(|iters| {
      let prog = &prog;
      let preemption = &preemption;
      async move {
        let start = Instant::now();
        let calldata: [u8; 8] = iters.to_le_bytes();
        let ret = prog
          .run(
            &timeslice_config(),
            &TokioTimeslicer,
            "test",
            &mut [],
            &calldata,
            &preemption,
          )
          .await
          .unwrap();
        assert_eq!(ret as u64, iters * 42);
        start.elapsed()
      }
    });
  };

  c.bench_function("host invoke", |b| host_invoke_bench(b, false));
  c.bench_function("async host invoke", |b| host_invoke_bench(b, true));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn compile_and_load(
  code: &str,
  helpers: &[&'static [(&'static str, Helper)]],
) -> (Runtime, Program) {
  let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();

  let (_, t_env) = gt_env();

  let binary = rt.block_on(async { compile_ebpf(code.as_bytes().to_vec()).await.unwrap() });

  let prog = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    helpers,
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);
  (rt, prog)
}
