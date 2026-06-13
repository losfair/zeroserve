use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;

use crate::tinycc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EbpfCompiler {
    Tcc,
    Clang,
}

impl std::fmt::Display for EbpfCompiler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcc => f.write_str("tcc"),
            Self::Clang => f.write_str("clang"),
        }
    }
}

pub fn compile_file_to_object(
    compiler: EbpfCompiler,
    source: &Path,
    include_dir: &Path,
    output: &Path,
) -> Result<()> {
    match compiler {
        EbpfCompiler::Tcc => tinycc::compile_file_to_object(source, include_dir, output),
        EbpfCompiler::Clang => compile_file_with_clang(source, include_dir, output),
    }
}

pub fn compile_source_to_object(
    compiler: EbpfCompiler,
    source: &str,
    source_name: &str,
    include_dir: &Path,
    output: &Path,
) -> Result<()> {
    match compiler {
        EbpfCompiler::Tcc => {
            tinycc::compile_source_to_object(source, source_name, include_dir, output)
        }
        EbpfCompiler::Clang => compile_source_with_clang(source, source_name, include_dir, output),
    }
}

fn compile_source_with_clang(
    source: &str,
    source_name: &str,
    include_dir: &Path,
    output: &Path,
) -> Result<()> {
    let source_path = include_dir.join(source_name);
    fs::write(&source_path, source)
        .with_context(|| format!("failed to write {}", source_path.display()))?;
    let result = compile_file_with_clang(&source_path, include_dir, output);
    let _ = fs::remove_file(&source_path);
    result
}

fn compile_file_with_clang(source: &Path, include_dir: &Path, output: &Path) -> Result<()> {
    let bc_path = bitcode_path(output);
    let result = (|| {
        let clang_status = Command::new("clang")
            .args([
                "-O2",
                "-Wall",
                "-target",
                "bpf",
                "-fno-builtin",
                "-emit-llvm",
                "-c",
            ])
            .arg("-I")
            .arg(include_dir)
            .arg(source)
            .arg("-o")
            .arg(&bc_path)
            .stdout(Stdio::null())
            .status()
            .with_context(|| format!("failed to run clang on {}", source.display()))?;
        if !clang_status.success() {
            bail!("clang failed for {}", source.display());
        }

        let llc_status = Command::new("llc")
            .args([
                "-march=bpf",
                "-bpf-stack-size=4096",
                "-mcpu=v3",
                "-filetype=obj",
            ])
            .arg(&bc_path)
            .arg("-o")
            .arg(output)
            .stdout(Stdio::null())
            .status()
            .with_context(|| format!("failed to run llc on {}", source.display()))?;
        if !llc_status.success() {
            bail!("llc failed for {}", source.display());
        }
        ensure_nonempty_object(output, "clang")
    })();
    let _ = fs::remove_file(&bc_path);
    result
}

fn bitcode_path(output: &Path) -> PathBuf {
    let mut path = output.to_path_buf();
    path.set_extension("bc");
    path
}

fn ensure_nonempty_object(path: &Path, compiler: &str) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() == 0 {
        bail!("{compiler} produced an empty object at {}", path.display());
    }
    Ok(())
}
