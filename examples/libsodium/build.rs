use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system's libsodium shared
    // library. This is required for the Mock runtime, which simply
    // calls the raw function symbols.
    println!("cargo:rustc-link-lib=sodium");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .clang_args(option_env!("NIX_CFLAGS_COMPILE").unwrap_or("").split(" "))
        .omniglot_configuration_file(Some(
            PathBuf::from("./libsodium.omniglot.toml")
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
        .write_to_file(out_path.join("libsodium_bindings.rs"))
        .expect("Couldn't write bindings!");
}
