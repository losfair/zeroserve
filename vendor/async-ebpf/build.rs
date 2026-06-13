use std::path::PathBuf;

fn main() {
  println!("cargo:rerun-if-changed=vendor/ubpf/CMakeLists.txt");
  println!("cargo:rerun-if-changed=vendor/ubpf/cmake");
  println!("cargo:rerun-if-changed=vendor/ubpf/vm");

  let dst = cmake::Config::new("vendor/ubpf")
    .define("UBPF_SKIP_EXTERNAL", "ON")
    .build_target("ubpf")
    .build();

  println!(
    "cargo:rustc-link-search=native={}",
    dst.join("build/lib").display()
  );
  println!("cargo:rustc-link-lib=static=ubpf");

  let bindings = bindgen::Builder::default()
    .header("vendor/ubpf/vm/inc/ubpf.h")
    .clang_arg(format!("-I{}", dst.join("build/vm").display()))
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .generate()
    .expect("Unable to generate bindings");

  let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
  bindings
    .write_to_file(out_path.join("ubpf_bindings.rs"))
    .expect("Couldn't write bindings!");
}
