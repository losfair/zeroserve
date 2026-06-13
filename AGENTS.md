# Repository Guidelines

## Project Structure & Module Organization

- `src/` is the Rust server. Important entry points include `main.rs` for CLI dispatch and runtime setup, `cli.rs` for flags, `server.rs`/`server/` for request serving, `site.rs` for tarball-backed static files, `pack.rs` for site packaging and script compilation, `script.rs` plus `helpers/` for async eBPF execution, `tls.rs`/`boringtls.rs`/`ech/` for TLS and ECH, and `reload.rs`/`hupwatch.rs` for reload coordination.
- `src/caddyfile/`, `src/caddy_file.rs`, `src/caddy_compile.rs`, and `src/caddy_run.rs` implement the Caddyfile/Caddy JSON adapter, compiler, and direct `--caddy` runtime path. `build.rs` regenerates the LALRPOP parser from `src/caddyfile/grammar.lalrpop`.
- `src/http/` contains protocol handling, currently including HTTP/1 support and HTTP/2-related integration through dependencies.
- `sdk/` contains embedded C headers (`zeroserve.h`, `zeroserve_caddy.h`) included by `pack.rs` and emitted by `--dump-sdk`.
- `examples/` contains native eBPF C request-script examples.
- `testing/` contains Deno end-to-end tests and Caddyfile fixtures. Test helpers expect `target/release/zeroserve`.
- `docs/user_manual.md` is embedded in the binary via `--manual`; keep it aligned with user-facing behavior.
- `CADDY_COMPAT.md` records the intended Caddy compatibility surface and known non-goals.
- `benchmark/` and `tools/` hold benchmark scripts, results, and helper utilities.

## Build, Test, and Development Commands

- `cargo fmt --all` or `cargo fmt --all --check` - format or verify Rust formatting.
- `cargo build` - compile the debug binary.
- `cargo build --release --locked` - build the release binary used by the Deno e2e suite and CI.
- `cargo test --locked` - run Rust unit tests.
- `cd testing && deno test -A --parallel` - run end-to-end tests against `../target/release/zeroserve`.
- `cargo run -- --addr 0.0.0.0:8080 site.tar` - run the server against a site tarball.
- `cargo run -- --pack . > site.tar` - pack the current directory into a tarball, compiling `.zeroserve/scripts/*.c` to `.o`.
- `cargo run -- --dump-sdk > zeroserve.h` - print the embedded scripting SDK header.
- `cargo run -- --manual` - print the embedded user manual.
- `cargo run -- --caddy-compile Caddyfile > .zeroserve/scripts/caddy.c` - adapt/compile Caddy config to middleware C.
- `cargo run -- --caddy Caddyfile --addr 0.0.0.0:8080` - run the Caddy adapter/compiler/serve pipeline in memory.
- `killall -SIGHUP zeroserve` - trigger tarball and TLS reload for a running server.

## Toolchain & Environment Notes

- The project uses Rust 2024 edition and expects a recent stable toolchain.
- Runtime and tests are Linux-oriented because the server relies on `io_uring`, namespaces, capabilities, and eBPF object loading.
- Script packing and scripting e2e tests require `clang` and `llc` on `PATH`; missing tools cause scripting tests to skip or `--pack` to fail.
- Caddy comparison tests need a `caddy` binary. CI installs a pinned Caddy commit and exposes it through `CADDY_BIN`; without Caddy, comparison tests may skip.
- Ubuntu runners may need unprivileged user namespaces enabled. For local debugging, `--disable-ns-isolation` can bypass namespace setup, but do not make tests depend on it unless the test explicitly targets that mode.
- CI also builds release artifacts with `cargo-zigbuild` for glibc 2.31 and assembles the multi-arch Docker image from prebuilt binaries.

## Coding Style & Naming Conventions

- Follow standard Rust style: `snake_case` for functions and variables, `CamelCase` for types, and small focused modules.
- Prefer existing local patterns and helper APIs over new abstractions. The request path, script runtime, Caddy compiler, and TLS paths each have established helper layers.
- Keep CLI flags descriptive and documented in `src/cli.rs`; update `docs/user_manual.md` and README snippets when user-facing behavior changes.
- For Caddy compatibility changes, update `CADDY_COMPAT.md` when the supported surface, rejection behavior, warnings, or non-goals change.
- For SDK/script-helper changes, keep `sdk/zeroserve.h`, `sdk/zeroserve_caddy.h`, Rust helper registration, examples, and relevant tests in sync.
- Use structured parsing/serialization (`serde_json`, Caddyfile parser modules, HTTP types) instead of ad hoc string manipulation when the codebase already has a parser or typed representation.

## Testing Guidelines

- Run `cargo fmt --all --check` and `cargo test --locked` for Rust changes.
- Run `cargo build --release --locked` before Deno e2e tests; `testing/test_utils.ts` launches `target/release/zeroserve`.
- Run `cd testing && deno test -A --parallel` for user-visible runtime, packaging, Caddy, TLS, proxy, OIDC, rate-limit, body, hostname, and scripting behavior.
- Narrow test runs are useful while iterating, for example `cd testing && deno test -A caddyfile_test.ts`.
- Add or update Caddyfile fixtures under `testing/caddyfile_fixtures/` when changing adapter behavior.
- Scripting e2e tests use the tinycc library linked into the zeroserve binary
  by default. Clang/llc coverage should still be exercised when the compiler
  selection path changes.

## Security & Runtime Configuration Tips

- TLS expects PEM files. Do not commit real keys; use local or test certificates only.
- Checked-in `certificate.pem` and `key.pem` are local test material, not production credentials.
- `--expose-filesystem` allows generated Caddy middleware and file logging to access host filesystem paths; treat changes around it as security-sensitive.
- Namespace isolation and capability dropping are part of the runtime hardening model. Avoid broadening filesystem or network access without documenting the reason and tests.
- `--enable-proxy-protocol` trusts the incoming PROXY v1 header for peer metadata; validate behavior carefully when touching connection setup.
- The pack step includes compiled `.o` files from `.zeroserve/scripts/` and omits source `.c` files. If both `.c` and `.o` exist with the same stem, packing recompiles from `.c` and skips the stale `.o`.
- Hot reload must preserve the last good runtime state on reload failure; changes to reload, TLS, script loading, or site indexing should test failure paths as well as success paths.
