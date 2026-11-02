# Copyright (c) Meta Platforms, Inc. and affiliates.
{
  stdenv,
  lib,
  cmake,
  ninja,
  pkg-config,
  clang,
  bison,
  flex,
  libbpf,
  elfutils,
  openssl,
  testers,
  zlib,
  zstd,
  pcre2,
  xxd,
  version,
}:

let
  fs = lib.fileset;

  # zerocallusedregs is invalid with -target bpf
  hardeningDisable = [ "zerocallusedregs" ];

in
{
  inherit hardeningDisable;

  package = stdenv.mkDerivation (finalAttrs: {
    pname = "bpfilter";
    inherit version;

    src = fs.toSource {
      root = ./.;
      fileset = fs.unions [
        ./src
        ./CMakeLists.txt
        ./tools/cmake
        ./tests/CMakeLists.txt
      ];
    };

    inherit hardeningDisable;

    nativeBuildInputs = [
      cmake
      ninja
      pkg-config
      clang # for building codegen BPF progs
      bison
      flex
    ];

    buildInputs = [
      libbpf
      elfutils
      openssl
      zlib
      zstd
      pcre2
      xxd
    ];

    cmakeFlags = [
      "-DWITH_DOCS=OFF"
      "-DWITH_TESTS=OFF"
    ];

    # We do not run the unit tests because the nix build sandbox doesn't
    # have access to /sys/kernel/btf/vmlinux.
    doCheck = false;

    meta.pkgConfigModules = [ "bpfilter" ];

    passthru = {
      tests.pkg-config = testers.testMetaPkgConfig finalAttrs.finalPackage;
    };

    preFixup = ''
      # workaround for https://github.com/NixOS/nixpkgs/issues/144170
      substituteInPlace $out/lib/pkgconfig/bpfilter.pc --replace-fail ''${prefix}/ ""
    '';
  });
}
