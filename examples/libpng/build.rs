use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

fn check_output_res(res: std::io::Result<std::process::Output>, msg: &'static str) {
    match res {
        Err(e) => Err(e).expect(msg),
        Ok(out) => {
            if !out.status.success() {
                panic!(
                    "{},\nstdout: \n{},\nstderr: \n{}",
                    msg,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=libpng.omniglot.toml");
    println!("cargo:rerun-if-changed=og_bindings_rustfmt.toml");
    println!("cargo:rerun-if-changed=libpng_nojmp.c");
    println!("cargo:rerun-if-changed=libpng_nojmp.h");

    let bindings = bindgen::Builder::default()
        .header("libpng_nojmp.h")
        .clang_args(option_env!("NIX_CFLAGS_COMPILE").unwrap_or("").split(" "))
        .omniglot_configuration_file(Some(
            PathBuf::from("./libpng.omniglot.toml")
                .canonicalize()
                .unwrap(),
        ))
        .rustfmt_configuration_file(Some(
            PathBuf::from("./og_bindings_rustfmt.toml")
                .canonicalize()
                .unwrap(),
        ))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("libpng_bindings.rs"))
        .expect("Couldn't write bindings!");

    let cc = env::var("CC").expect("No C compiler (CC environment variable) provided!");

    check_output_res(
        std::process::Command::new(&cc)
            .args([
                OsStr::new("-Wall"),
                OsStr::new("-Werror"),
                OsStr::new("-g"), // Produce debug symbols in the target's native format
                OsStr::new("-ggdb"), // Provide debug symbols readable by GDB
                OsStr::new("-fPIC"), // Produce PIC code to support loading as shared lib
                OsStr::new("-rdynamic"), // Add all symbols (not just used) to the ELF
                OsStr::new("-shared"), // Produce a shared object
                OsStr::new("-lpng"), // Link against the system libpng
                OsStr::new("libpng_nojmp.c"),
                OsStr::new("-o"),
                out_path.join("libpng_nojmp.so").as_os_str(),
            ])
            .output(),
        "Failed to compile the libpng_nojmp wrapper!",
    );

    println!("cargo:rustc-link-lib=png");
    println!("cargo:rustc-link-search={}", out_path.display());
}
