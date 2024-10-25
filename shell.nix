let
  pinnedNixpkgsSrc = builtins.fetchTarball {
    # `release-25.05` branch of 2025-06-14T18:29:16.000Z
    url = "https://github.com/NixOS/nixpkgs/archive/fcfb773595d5d62a78304cdfe76fd0e6daf428e7.tar.gz";
    sha256 = "sha256:108p56y9vj4j8m955w0nf69g23kssyrn76qxanvn9gsfi9v02g0a";
  };

in
{ pkgs ? import pinnedNixpkgsSrc {} }:

  pkgs.llvmPackages.stdenv.mkDerivation rec {
    name = "encapfn-mpk-devshell";

    buildInputs = with pkgs; [
      # Base dependencies
      rustup clang pkg-config

      # Dependencies of the libsodium tests:
      libsodium

      # Dependencies of the sfml tests:
      csfml freeglut libGL.dev glew

      # Dependencies of the tinyfiledialog tests (other alternatives can work as well):
      kdePackages.kdialog

      # Dependencies of the brotli test:
      brotli

      # Dependencies of the OpenBLAS test:
      openblas

      # Dependencies of the libpng example:
      libpng

      # Dependencies for building the EF bindings / libraries in there:
      clang llvm qemu

      # Development tools:
      gdb

      # Dependencies of criterion for benchmarks:
      gnuplot

      # Evaluation reproduction script:
      jq bc nix
    ];

    shellHook = ''
      # Required for rust-bindgen:
      export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"

      # Required for dlopen:
      export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath buildInputs}"

      # Required for building Tock boards:
      export OBJDUMP="${pkgs.llvm}/bin/llvm-objdump"
    '';
  }
