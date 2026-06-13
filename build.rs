use std::{
    env, fs,
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

const TINYCC_COMMIT: &str = "17caf669f03c80fcd4499aa2d4fd1ffc3ec5f153";
const TINYCC_ZIP_URL: &str =
    "https://github.com/losfair/tinycc/archive/17caf669f03c80fcd4499aa2d4fd1ffc3ec5f153.zip";

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

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let tinycc_dir = env::var_os("ZEROSERVE_TINYCC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| fetch_default_tinycc(&out_dir));
    if !tinycc_dir.join("Makefile").exists() {
        panic!(
            "tinycc source directory not found at {}; set ZEROSERVE_TINYCC_DIR",
            tinycc_dir.display()
        );
    }
    if !tinycc_dir.join("config.mak").exists() {
        configure_tinycc(&tinycc_dir);
    }

    for file in TINYCC_SOURCES {
        println!("cargo:rerun-if-changed={}", tinycc_dir.join(file).display());
    }

    let status = Command::new("make")
        .current_dir(&tinycc_dir)
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

fn configure_tinycc(tinycc_dir: &Path) {
    let status = Command::new("./configure")
        .current_dir(tinycc_dir)
        .status()
        .unwrap_or_else(|err| {
            panic!(
                "failed to run ./configure in {}: {err}",
                tinycc_dir.display()
            )
        });
    if !status.success() {
        panic!("failed to configure tinycc in {}", tinycc_dir.display());
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
