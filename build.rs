use std::{
    env,
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

    let tinycc_dir = env::var_os("ZEROSERVE_TINYCC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/jfs/tinycc"));
    if !tinycc_dir.join("Makefile").exists() {
        panic!(
            "tinycc source directory not found at {}; set ZEROSERVE_TINYCC_DIR",
            tinycc_dir.display()
        );
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

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let archive = out_dir.join("libzeroserve_tinycc_bpf.a");
    build_archive(&archive, &tinycc_dir);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zeroserve_tinycc_bpf");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
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
