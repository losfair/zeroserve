use std::{
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tar::Builder;
use ulid::Ulid;

use crate::bpf_compiler::{self, EbpfCompiler};

pub const ZEROSERVE_H: &[u8] = include_bytes!("../sdk/zeroserve.h");
pub const ZEROSERVE_CADDY_H: &[u8] = include_bytes!("../sdk/zeroserve_caddy.h");
pub const USER_MANUAL: &str = include_str!("../docs/user_manual.md");

pub fn pack_site(root: &Path, compiler: EbpfCompiler) -> Result<()> {
    let meta = fs::metadata(root)
        .with_context(|| format!("failed to stat pack path {}", root.display()))?;
    if !meta.is_dir() {
        bail!("--pack expects a directory, got {}", root.display());
    }

    let temp_dir = create_temp_dir()?;
    let header_dir = extract_header(&temp_dir)?;
    let stdout = io::stdout();
    let mut builder = Builder::new(stdout.lock());

    let result = (|| {
        pack_dir(&mut builder, root, root, &temp_dir, &header_dir, compiler)?;
        builder.finish().context("failed to finalize tar stream")?;
        Ok(())
    })();

    let _ = fs::remove_dir_all(&temp_dir);
    result
}

fn pack_dir(
    builder: &mut Builder<impl io::Write>,
    root: &Path,
    dir: &Path,
    temp_dir: &Path,
    header_dir: &Path,
    compiler: EbpfCompiler,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("failed to strip prefix {}", root.display()))?;
        if file_type.is_dir() {
            builder
                .append_dir(rel, &path)
                .with_context(|| format!("failed to append directory {}", rel.display()))?;
            pack_dir(builder, root, &path, temp_dir, header_dir, compiler)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        if is_script_c(rel) {
            let compiled = compile_script(&path, temp_dir, header_dir, compiler)?;
            let mut tar_path = rel.to_path_buf();
            tar_path.set_extension("o");
            builder
                .append_path_with_name(&compiled.obj_path, &tar_path)
                .with_context(|| format!("failed to append {}", tar_path.display()))?;
            compiled.cleanup();
            continue;
        }

        if is_script_o(rel) {
            let mut c_path = path.clone();
            c_path.set_extension("c");
            if c_path.exists() {
                continue;
            }
        }

        builder
            .append_path_with_name(&path, rel)
            .with_context(|| format!("failed to append {}", rel.display()))?;
    }

    Ok(())
}

fn is_script_c(rel: &Path) -> bool {
    is_scripts_path(rel) && has_extension(rel, "c")
}

fn is_script_o(rel: &Path) -> bool {
    is_scripts_path(rel) && has_extension(rel, "o")
}

fn is_scripts_path(rel: &Path) -> bool {
    let mut comps = rel.components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(first)), Some(Component::Normal(second)))
            if first == OsStr::new(".zeroserve") && second == OsStr::new("scripts") =>
        {
            true
        }
        _ => false,
    }
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

fn create_temp_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("zeroserve-pack-{}", Ulid::new()));
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create temp dir {}", dir.display()))?;
    Ok(dir)
}

fn extract_header(temp_dir: &Path) -> Result<PathBuf> {
    let header_path = temp_dir.join("zeroserve.h");
    fs::write(&header_path, ZEROSERVE_H)
        .with_context(|| format!("failed to write {}", header_path.display()))?;
    let caddy_header_path = temp_dir.join("zeroserve_caddy.h");
    fs::write(&caddy_header_path, ZEROSERVE_CADDY_H)
        .with_context(|| format!("failed to write {}", caddy_header_path.display()))?;
    Ok(temp_dir.to_path_buf())
}

struct CompiledScript {
    obj_path: PathBuf,
}

impl CompiledScript {
    fn cleanup(&self) {
        let _ = fs::remove_file(&self.obj_path);
    }
}

fn compile_script(
    source: &Path,
    temp_dir: &Path,
    header_dir: &Path,
    compiler: EbpfCompiler,
) -> Result<CompiledScript> {
    let stem = source
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script");
    let unique = Ulid::new();
    let obj_path = temp_dir.join(format!("{}-{}.o", stem, unique));

    bpf_compiler::compile_file_to_object(compiler, source, header_dir, &obj_path)?;

    Ok(CompiledScript { obj_path })
}
