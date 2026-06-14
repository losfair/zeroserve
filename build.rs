use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const TINYCC_OBJECTS: &[&str] = &[
    "bpf-libtcc.o",
    "bpf-tccpp.o",
    "bpf-tccgen.o",
    "bpf-tccdbg.o",
    "bpf-tccelf.o",
    "bpf-tccasm.o",
    "bpf-tccrun.o",
    "bpf-bpf-gen.o",
    "bpf-bpf-link.o",
];

const TINYCC_SOURCES: &[&str] = &[
    "libtcc.c",
    "tccpp.c",
    "tccgen.c",
    "tccdbg.c",
    "tccelf.c",
    "tccasm.c",
    "tccrun.c",
    "bpf-gen.c",
    "bpf-link.c",
    "tcc.h",
    "libtcc.h",
    "elf.h",
    "Makefile",
    "config.mak",
    "config.h",
];

const TINYCC_COMMIT: &str = "afcb3aa1a59568fec8b4bb604e43686723e34c94";
const TINYCC_ZIP_URL: &str =
    "https://github.com/losfair/tinycc/archive/afcb3aa1a59568fec8b4bb604e43686723e34c94.zip";

fn main() {
    // Generate the Caddyfile block-interior parser from the lalrpop grammar.
    // We use an external lexer (our own tokenizer), so lalrpop's built-in
    // lexer is disabled; it only generates the LR(1) tables.
    lalrpop::process_src().expect("lalrpop grammar generation failed");
    println!("cargo:rerun-if-changed=src/caddyfile/grammar.lalrpop");

    link_tinycc();
}

fn link_tinycc() {
    println!("cargo:rerun-if-env-changed=ZEROSERVE_TINYCC_DIR");
    println!("cargo:rerun-if-env-changed=AR");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CFLAGS");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let tinycc_source_dir = env::var_os("ZEROSERVE_TINYCC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| fetch_default_tinycc(&out_dir));
    if !tinycc_source_dir.join("Makefile").exists() {
        panic!(
            "tinycc source directory not found at {}; set ZEROSERVE_TINYCC_DIR",
            tinycc_source_dir.display()
        );
    }

    let target = env::var("TARGET").expect("TARGET is set by Cargo");
    let host = env::var("HOST").expect("HOST is set by Cargo");
    emit_target_tool_rerun_hints(&target);
    let tinycc_dir = stage_tinycc_source(&tinycc_source_dir, &out_dir, &target);
    let toolchain = TinyccToolchain::new(&host, &target);
    configure_tinycc(&tinycc_dir, &target, &toolchain);
    generate_tinycc_predefs(&tinycc_dir, &toolchain);

    for file in TINYCC_SOURCES {
        println!("cargo:rerun-if-changed={}", tinycc_dir.join(file).display());
    }

    let status = Command::new("make")
        .current_dir(&tinycc_dir)
        .env("CC", &toolchain.target_cc)
        .env("AR", &toolchain.target_ar)
        .args(["bpf-tcc", "ONE_SOURCE=no"])
        .status()
        .unwrap_or_else(|err| panic!("failed to run make in {}: {err}", tinycc_dir.display()));
    if !status.success() {
        panic!("failed to build BPF tinycc in {}", tinycc_dir.display());
    }

    let archive = out_dir.join("libzeroserve_tinycc_bpf.a");
    build_archive(&archive, &tinycc_dir);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zeroserve_tinycc_bpf");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
}

fn fetch_default_tinycc(out_dir: &Path) -> PathBuf {
    let tinycc_dir = out_dir.join(format!("tinycc-{TINYCC_COMMIT}"));
    if tinycc_dir.join("Makefile").exists() {
        return tinycc_dir;
    }

    let zip_path = out_dir.join(format!("tinycc-{TINYCC_COMMIT}.zip"));
    let tmp_dir = out_dir.join(format!("tinycc-{TINYCC_COMMIT}.extracting"));
    let _ = fs::remove_file(&zip_path);
    let _ = fs::remove_dir_all(&tmp_dir);

    println!("cargo:warning=downloading tinycc from {TINYCC_ZIP_URL}");
    let status = Command::new("curl")
        .args(["-fsSL", TINYCC_ZIP_URL, "-o"])
        .arg(&zip_path)
        .status()
        .unwrap_or_else(|err| panic!("failed to run curl to download tinycc: {err}"));
    if !status.success() {
        panic!("failed to download tinycc from {TINYCC_ZIP_URL}");
    }

    fs::create_dir_all(&tmp_dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", tmp_dir.display()));
    let status = Command::new("unzip")
        .arg("-q")
        .arg(&zip_path)
        .arg("-d")
        .arg(&tmp_dir)
        .status()
        .unwrap_or_else(|err| panic!("failed to run unzip for {}: {err}", zip_path.display()));
    if !status.success() {
        panic!("failed to extract {}", zip_path.display());
    }

    let mut extracted_dirs = fs::read_dir(&tmp_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", tmp_dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then_some(path)
        })
        .collect::<Vec<_>>();
    if extracted_dirs.len() != 1 {
        panic!(
            "expected tinycc archive to contain one directory, found {}",
            extracted_dirs.len()
        );
    }

    let _ = fs::remove_dir_all(&tinycc_dir);
    fs::rename(extracted_dirs.remove(0), &tinycc_dir).unwrap_or_else(|err| {
        panic!(
            "failed to move tinycc source into {}: {err}",
            tinycc_dir.display()
        )
    });
    let _ = fs::remove_dir_all(&tmp_dir);
    tinycc_dir
}

struct TinyccToolchain {
    target_cc: String,
    target_ar: String,
    host_cc: cc::Tool,
}

impl TinyccToolchain {
    fn new(host: &str, target: &str) -> Self {
        let cargo_target = cargo_target_without_glibc_version(target);
        let host_cc = cc::Build::new().host(host).target(host).get_compiler();
        let target_cc = cargo_target_env("CC", target)
            .or_else(|| cargo_target_env("LINKER", target))
            .or_else(|| zig_cc_for_glibc_target(target))
            .unwrap_or_else(|| {
                make_command_for_cc_tool(
                    cc::Build::new()
                        .host(host)
                        .target(&cargo_target)
                        .get_compiler(),
                )
            });
        let target_ar = cargo_target_env("AR", target)
            .or_else(|| env::var("AR").ok())
            .unwrap_or_else(|| "ar".to_string());

        Self {
            target_cc,
            target_ar,
            host_cc,
        }
    }
}

fn cargo_target_env(prefix: &str, target: &str) -> Option<String> {
    let cargo_target = cargo_target_without_glibc_version(target);
    let mut normalized_targets = vec![normalize_target_env(target)];
    let normalized_cargo_target = normalize_target_env(&cargo_target);
    if normalized_targets[0] != normalized_cargo_target {
        normalized_targets.push(normalized_cargo_target);
    }

    let mut names = Vec::new();
    for normalized in &normalized_targets {
        if prefix == "LINKER" {
            names.push(format!("CARGO_TARGET_{normalized}_LINKER"));
        } else {
            names.push(format!("{prefix}_{normalized}"));
        }
    }
    if prefix != "LINKER" {
        names.push(format!("{}_{}", prefix.to_ascii_lowercase(), target));
        if cargo_target != target {
            names.push(format!("{}_{}", prefix.to_ascii_lowercase(), cargo_target));
        }
        names.push(format!("TARGET_{prefix}"));
        names.push(prefix.to_string());
    }

    names.into_iter().find_map(|name| env::var(name).ok())
}

fn normalize_target_env(target: &str) -> String {
    target.replace(['-', '.'], "_").to_ascii_uppercase()
}

fn cargo_target_without_glibc_version(target: &str) -> String {
    if let Some((base, version)) = target.rsplit_once('.')
        && base.ends_with("-linux-gnu")
        && version.chars().all(|ch| ch.is_ascii_digit())
    {
        return base.to_string();
    }
    target.to_string()
}

fn zig_cc_for_glibc_target(target: &str) -> Option<String> {
    let (base, version) = target.rsplit_once('.')?;
    if !base.ends_with("-linux-gnu") || !version.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let arch = base.split('-').next()?;
    let zig_arch = match arch {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        _ => return None,
    };
    Some(format!("zig cc -target {zig_arch}-linux-gnu.{version}"))
}

fn make_command_for_cc_tool(tool: cc::Tool) -> String {
    let mut parts = vec![shell_quote(tool.path().as_os_str())];
    parts.extend(tool.args().iter().map(|arg| shell_quote(arg.as_os_str())));
    parts.join(" ")
}

fn shell_quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&byte))
    {
        value.into_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn emit_target_tool_rerun_hints(target: &str) {
    let cargo_target = cargo_target_without_glibc_version(target);
    let normalized = normalize_target_env(target);
    let normalized_cargo_target = normalize_target_env(&cargo_target);
    for name in [
        format!("CC_{normalized}"),
        format!("CC_{normalized_cargo_target}"),
        format!("cc_{target}"),
        format!("cc_{cargo_target}"),
        "TARGET_CC".to_string(),
        format!("AR_{normalized}"),
        format!("AR_{normalized_cargo_target}"),
        format!("ar_{target}"),
        format!("ar_{cargo_target}"),
        "TARGET_AR".to_string(),
        format!("CARGO_TARGET_{normalized}_LINKER"),
        format!("CARGO_TARGET_{normalized_cargo_target}_LINKER"),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
}

fn stage_tinycc_source(source_dir: &Path, out_dir: &Path, target: &str) -> PathBuf {
    let build_dir = out_dir.join(format!("tinycc-build-{target}"));
    let _ = fs::remove_dir_all(&build_dir);
    fs::create_dir_all(&build_dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", build_dir.display()));
    copy_tinycc_source_tree(source_dir, &build_dir);
    build_dir
}

fn copy_tinycc_source_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source)
        .unwrap_or_else(|err| panic!("failed to read tinycc source {}: {err}", source.display()))
    {
        let entry = entry.unwrap_or_else(|err| panic!("failed to read tinycc source entry: {err}"));
        let path = entry.path();
        let file_name = entry.file_name();
        if skip_tinycc_staged_path(&path, &file_name) {
            continue;
        }

        let target = destination.join(&file_name);
        let file_type = entry
            .file_type()
            .unwrap_or_else(|err| panic!("failed to stat {}: {err}", path.display()));
        if file_type.is_dir() {
            fs::create_dir_all(&target)
                .unwrap_or_else(|err| panic!("failed to create {}: {err}", target.display()));
            copy_tinycc_source_tree(&path, &target);
        } else if file_type.is_file() {
            fs::copy(&path, &target).unwrap_or_else(|err| {
                panic!(
                    "failed to copy tinycc source {} to {}: {err}",
                    path.display(),
                    target.display()
                )
            });
        }
    }
}

fn skip_tinycc_staged_path(path: &Path, file_name: &OsStr) -> bool {
    let name = file_name.to_string_lossy();
    if matches!(
        name.as_ref(),
        ".git"
            | "config.mak"
            | "config.h"
            | "tccdefs_.h"
            | "tcc"
            | "bpf-tcc"
            | "c2str.exe"
            | "libtcc.a"
            | "libtcc1.a"
    ) {
        return true;
    }
    if name.ends_with("-tcc") || name.ends_with("-libtcc1.a") {
        return true;
    }
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("o" | "a" | "so" | "dylib" | "dll" | "exe")
    )
}

fn configure_tinycc(tinycc_dir: &Path, target: &str, toolchain: &TinyccToolchain) {
    let mut command = Command::new("./configure");
    command
        .current_dir(tinycc_dir)
        .arg(format!("--cc={}", toolchain.target_cc))
        .arg(format!("--ar={}", toolchain.target_ar));
    if let Some(cpu) = tinycc_cpu(target) {
        command.arg(format!("--cpu={cpu}"));
    }

    let status = command.status().unwrap_or_else(|err| {
        panic!(
            "failed to run ./configure in {}: {err}",
            tinycc_dir.display()
        )
    });
    if !status.success() {
        panic!("failed to configure tinycc in {}", tinycc_dir.display());
    }
}

fn tinycc_cpu(target: &str) -> Option<&'static str> {
    match target.split('-').next()? {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("x86_64"),
        "arm" | "armv7" => Some("arm"),
        "riscv64gc" | "riscv64" => Some("riscv64"),
        "i586" | "i686" => Some("i386"),
        _ => None,
    }
}

fn generate_tinycc_predefs(tinycc_dir: &Path, toolchain: &TinyccToolchain) {
    let mut compile = toolchain.host_cc.to_command();
    let status = compile
        .current_dir(tinycc_dir)
        .arg("-DC2STR")
        .arg("conftest.c")
        .arg("-o")
        .arg("c2str.exe")
        .status()
        .unwrap_or_else(|err| {
            panic!(
                "failed to build tinycc c2str helper in {}: {err}",
                tinycc_dir.display()
            )
        });
    if !status.success() {
        panic!(
            "failed to build tinycc c2str helper in {}",
            tinycc_dir.display()
        );
    }

    let status = Command::new("./c2str.exe")
        .current_dir(tinycc_dir)
        .arg("include/tccdefs.h")
        .arg("tccdefs_.h")
        .status()
        .unwrap_or_else(|err| {
            panic!(
                "failed to generate tinycc predefs in {}: {err}",
                tinycc_dir.display()
            )
        });
    if !status.success() {
        panic!(
            "failed to generate tinycc predefs in {}",
            tinycc_dir.display()
        );
    }
}

fn build_archive(archive: &Path, tinycc_dir: &Path) {
    let ar = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let mut command = Command::new(ar);
    command.arg("crs").arg(archive);
    for object in TINYCC_OBJECTS {
        let path = tinycc_dir.join(object);
        if !path.exists() {
            panic!("expected tinycc object {} to exist", path.display());
        }
        command.arg(path);
    }

    let status = command
        .status()
        .unwrap_or_else(|err| panic!("failed to run ar for {}: {err}", archive.display()));
    if !status.success() {
        panic!("failed to create {}", archive.display());
    }
}
