use std::env;
use std::path::PathBuf;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        std::path::Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("./og_brotli_lfi/brotli_native/install/lib")
            .display()
    );
    println!("cargo:rustc-link-lib=static=brotlienc");
    println!("cargo:rustc-link-lib=static=brotlidec");
    println!("cargo:rustc-link-lib=static=brotlicommon");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(option_env!("NIX_CFLAGS_COMPILE").unwrap_or("").split(" "))
        .omniglot_configuration_file(Some(
            PathBuf::from("./brotli.omniglot.toml")
                .canonicalize()
                .unwrap(),
        ))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("brotli_bindings.rs"))
        .expect("Couldn't write bindings!");
}
