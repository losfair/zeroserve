# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the Rust library. Core runtime logic lives in `src/program.rs`, with helper APIs in `src/helpers.rs`, pointer-cage memory safety in `src/pointer_cage.rs`, and ELF relocation in `src/linker.rs`.
- `src/test/` contains crate tests (Tokio-based) for execution and memory fault behavior.
- `benches/bench.rs` hosts Criterion benchmarks (requires the `testing` feature).
- `vendor/ubpf/` is the vendored uBPF C runtime; `build.rs` integrates CMake/bindgen.

## Build, Test, and Development Commands
- `cargo build` — build the library.
- `cargo test --features testing` — run tests; enables optional deps used by `test_util`.
- `cargo bench --features testing` — run benchmarks (Criterion).
- `cargo fmt` — format with rustfmt (configured in `rustfmt.toml`).

## Coding Style & Naming Conventions
- Rust 2021 edition; follow rustfmt with 2-space indentation (`tab_spaces = 2`).
- Use standard Rust naming: `CamelCase` for types, `snake_case` for functions/vars, and `SCREAMING_SNAKE_CASE` for consts.
- Keep public APIs documented with `///` comments.

## Testing Guidelines
- Tests are in `src/test/` and use `#[tokio::test]` plus `tracing-test`.
- The eBPF compile pipeline shells out to LLVM tools. Ensure `clang`, `llvm-link`, `opt`, `llc`, and `llvm-objcopy` are available in PATH.
- Prefer adding tests alongside existing patterns in `src/test/basic.rs`.

## Commit & Pull Request Guidelines
- Git history uses short, imperative summaries (e.g., `rename`, `aarch64`). Keep commit messages concise and action-oriented.
- PRs should include: a brief change summary, testing commands run (or “not run”), and any platform constraints (Linux x86_64/aarch64 only).

## Platform & Environment Notes
- The crate is Linux-only for `x86_64` and `aarch64` (enforced at compile time).
- Changes touching `vendor/ubpf/` or `build.rs` should note external toolchain requirements (CMake, bindgen/clang).
