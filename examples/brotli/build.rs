use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=brotlienc");
    println!("cargo:rustc-link-lib=brotlidec");
    println!("cargo:rustc-link-lib=brotlicommon");

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
