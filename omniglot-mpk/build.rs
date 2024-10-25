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
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Generate the libc bindings used for dlopen and walking the
    // dlinfo RTLD_DI_LINKMAP data structures:
    bindgen::Builder::default()
        .header("src/dlfcn_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("dlfcn_bindings.rs"))
        .expect("Couldn't write bindings!");

    bindgen::Builder::default()
        .header("src/link_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("link_bindings.rs"))
        .expect("Couldn't write bindings!");

    bindgen::Builder::default()
        .header("src/sys_mman_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("sys_mman_bindings.rs"))
        .expect("Couldn't write bindings!");

    // Build the Omniglot MPK C runtime. We cannot use the cc crate, as it does
    // not support building dynamic libraries:
    let cc = env::var("CC").expect("No C compiler (CC environment variable) provided!");

    println!("cargo:rerun-if-changed=src/omniglot_mpk_rt.c");
    println!("cargo:rerun-if-changed=src/omniglot_mpk_rt.h");
    check_output_res(
        std::process::Command::new(&cc)
            .args([
                OsStr::new("-g"),        // Produce debug symbols in the target's native format
                OsStr::new("-ggdb"),     // Provide debug symbols readable by GDB
                OsStr::new("-fPIC"),     // Produce PIC code to support loading as shared lib
                OsStr::new("-rdynamic"), // Add all symbols (not just used) to the ELF
                OsStr::new("-nostdlib"), // The point of the RT is to replace the stdlib
                OsStr::new("-shared"),   // Produce a shared object
                OsStr::new("-static"),   // Prevent linking with shared libraries
                OsStr::new("src/omniglot_mpk_rt.c"),
                OsStr::new("-o"),
                out_path.join("libomniglot_mpk_rt.so").as_os_str(),
            ])
            .output(),
        "Failed to compile the Omniglot MPK runtime into a shared library!",
    );

    // TODO: support cross-compilation:
    println!("cargo:rerun-if-changed=src/omniglot_mpk_loader.c");
    println!("cargo:rerun-if-changed=src/omniglot_mpk_loader.h");
    check_output_res(
        std::process::Command::new(&cc)
            .args([
                OsStr::new("-g"),        // Produce debug symbols in the target's native format
                OsStr::new("-ggdb"),     // Provide debug symbols readable by GDB
                OsStr::new("-fPIC"),     // Produce PIC code to support loading as shared lib
                OsStr::new("-rdynamic"), // Add all symbols (not just used) to the ELF
                OsStr::new("-nostdlib"), // The point of the RT is to replace the stdlib
                OsStr::new("-shared"),   // Produce a shared object
                OsStr::new("-static"),   // Prevent linking with shared libraries
                OsStr::new("src/omniglot_mpk_loader_stub.c"),
                OsStr::new("-o"),
                out_path.join("libomniglot_mpk_loader_stub.so").as_os_str(),
            ])
            .output(),
        "Failed to compile the Omniglot MPK loader into a shared library!",
    );
}
