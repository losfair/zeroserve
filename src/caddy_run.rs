//! The `--caddy` entry point: take a Caddyfile (or Caddy JSON) and produce an
//! in-memory site tarball ready to be served, running the whole
//! Caddyfile -> Caddy JSON -> middleware C -> eBPF object -> tarball pipeline.
//!
//! The generated middleware C is compiled through the selected eBPF compiler
//! and the tarball is assembled in memory. Only compiler scratch files and the
//! static SDK headers are materialized in a temporary directory, which is
//! removed before returning.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use ulid::Ulid;

use crate::bpf_compiler::{self, EbpfCompiler};
use crate::config::StaticConfig;
use crate::pack::{ZEROSERVE_CADDY_H, ZEROSERVE_H};
use crate::site::Site;

/// The name the generated middleware object is given inside the tarball. The
/// runtime loads every `.zeroserve/scripts/*.o` entry as an eBPF program.
const SCRIPT_TAR_PATH: &str = ".zeroserve/scripts/caddy.o";

/// Build an in-memory site tarball from a Caddyfile or Caddy JSON config.
///
/// Returns the raw bytes of a tar archive containing a single compiled
/// middleware object at `.zeroserve/scripts/caddy.o`. Adapter and compiler
/// warnings are printed to stderr.
pub fn build_caddy_tarball(config_path: &Path, compiler: EbpfCompiler) -> Result<Vec<u8>> {
    let source = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    // Auto-detect: a Caddy JSON config parses as a JSON object; a native
    // Caddyfile does not. Adapt a Caddyfile to JSON first, then compile.
    let json_source = if crate::is_caddy_json(&source, config_path) {
        source
    } else {
        let name = config_path.to_string_lossy();
        let (json, warnings) = crate::caddyfile::adapt_to_string(&source, &name)
            .with_context(|| format!("failed to adapt {}", config_path.display()))?;
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }
        json
    };

    let (generated, warnings) =
        crate::caddy_compile::compile_caddy_json_collecting(&json_source)
            .with_context(|| format!("failed to compile {}", config_path.display()))?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

    let object = compile_middleware_to_object(&generated, compiler)
        .context("failed to compile generated middleware to an eBPF object")?;

    build_tarball(&object).context("failed to assemble in-memory site tarball")
}

/// Compile the generated middleware C into an eBPF object.
/// The static SDK headers and output object are written to a temporary
/// directory for the compiler, then immediately read back and removed.
fn compile_middleware_to_object(c_source: &str, compiler: EbpfCompiler) -> Result<Vec<u8>> {
    let header_dir = write_sdk_headers()?;
    let object_path = header_dir.join("caddy.o");
    let result = (|| -> Result<Vec<u8>> {
        bpf_compiler::compile_source_to_object(
            compiler,
            c_source,
            "caddy.c",
            &header_dir,
            &object_path,
        )?;
        let object = fs::read(&object_path).with_context(|| {
            format!(
                "failed to read compiled object from {}",
                object_path.display()
            )
        })?;
        if object.is_empty() {
            bail!("compiled middleware object is empty");
        }
        Ok(object)
    })();
    let _ = fs::remove_dir_all(&header_dir);
    result
}

/// Materialize the SDK headers into a fresh temporary directory and return it,
/// for use as the compiler's include path. The caller removes it.
fn write_sdk_headers() -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("zeroserve-caddy-{}", Ulid::new()));
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create temp header dir {}", dir.display()))?;
    fs::write(dir.join("zeroserve.h"), ZEROSERVE_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    fs::write(dir.join("zeroserve_caddy.h"), ZEROSERVE_CADDY_H)
        .with_context(|| format!("failed to write headers into {}", dir.display()))?;
    Ok(dir)
}

/// Assemble a tar archive containing the single compiled middleware object.
fn build_tarball(object: &[u8]) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header
        .set_path(SCRIPT_TAR_PATH)
        .context("invalid script tar path")?;
    header.set_size(object.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, object)
        .context("failed to append middleware object to tar")?;
    builder
        .into_inner()
        .context("failed to finalize tar stream")
}

/// Load the site at startup: from the in-memory `--caddy` tarball when one is
/// attached (already built by `main` while reporting errors fatally), or from
/// the on-disk `tar_path` otherwise.
pub fn load_site(config: &StaticConfig) -> Result<Site> {
    match &config.caddy_tarball {
        Some(bytes) => {
            Site::load_from_bytes("zeroserve-caddy-site", bytes, config.max_rate_limit_buckets)
                .context("failed to load in-memory caddy site tarball")
        }
        None => Site::load_path(&config.tar_path, config.max_rate_limit_buckets),
    }
}

/// Load the site for a hot reload. In the `--caddy` flow `tar_path` holds the
/// source Caddyfile path, so the config is re-adapted and recompiled from disk
/// — reusing the startup tarball would silently ignore Caddyfile edits. This
/// still works under namespace isolation: the mount namespace keeps the host
/// filesystem visible (only /etc is shadowed), and /tmp stays writable for the
/// SDK headers and output object. On any failure the caller keeps serving the
/// previous configuration.
pub fn reload_site(config: &StaticConfig) -> Result<Site> {
    if config.caddy_tarball.is_some() {
        let bytes =
            build_caddy_tarball(&config.tar_path, config.ebpf_compiler).with_context(|| {
                format!("failed to rebuild site from {}", config.tar_path.display())
            })?;
        Site::load_from_bytes(
            "zeroserve-caddy-site",
            &bytes,
            config.max_rate_limit_buckets,
        )
        .context("failed to load rebuilt caddy site tarball")
    } else {
        Site::load_path(&config.tar_path, config.max_rate_limit_buckets)
    }
}
