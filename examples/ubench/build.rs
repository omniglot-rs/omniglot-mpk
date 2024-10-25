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
    println!("cargo:rerun-if-changed=./ogdemo.omniglot.toml");
    println!("cargo:rerun-if-changed=./c_src/ogdemo.h");
    println!("cargo:rerun-if-changed=./c_src/ogdemo.c");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("c_src/ogdemo.h")
        //.header("c_src/testmalloc.h")
        .omniglot_configuration_file(Some(
            PathBuf::from("./ogdemo.omniglot.toml")
                .canonicalize()
                .unwrap(),
        ))
        .rustfmt_configuration_file(Some(
            PathBuf::from("./og_bindings_rustfmt.toml")
                .canonicalize()
                .unwrap(),
        ))
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    //
    // We avoid using OUT_DIR as this does not allow us to view the
    // intermediate artifacts.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("libogdemo_bindings.rs"))
        .expect("Couldn't write bindings!");

    // Build the libogdemo as a shared library.
    //
    // We cannot use the cc crate, as it does not support building
    // dynamic libraries. Thus, determine the compiler based on the
    // CC environment variable:
    let cc = env::var("CC").expect("No C compiler (CC environment variable) provided!");
    check_output_res(
        std::process::Command::new(&cc)
            .args([
                OsStr::new("-g"),        // Produce debug symbols in the target's native format
                OsStr::new("-ggdb"),     // Provide debug symbols readable by GDB
                OsStr::new("-fPIC"),     // Produce PIC code to support loading as shared lib
                OsStr::new("-rdynamic"), // Add all symbols (not just used) to the ELF
                OsStr::new("-shared"),   // Produce a shared object
                OsStr::new("c_src/ogdemo.c"),
                //OsStr::new("c_src/testmalloc.c"),
                OsStr::new("-o"),
                out_path.join("libogdemo.so").as_os_str(),
            ])
            .output(),
        "Failed to compile the Omniglot MPK runtime into a shared library!",
    );

    // For the mock runtime, we also want to link against the library directly.
    // This can be commented out, but there must be no code path to instantiate
    // the MockRt, or otherwise there will be linker errors:
    println!("cargo:rustc-link-search={}", out_path.display());
    println!("cargo:rustc-link-lib=ogdemo");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", out_path.display());
}
