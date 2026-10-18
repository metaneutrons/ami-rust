//! RC0 design fixture: copied to the isolated application as build.rs.
//! SPDX-License-Identifier: MIT OR Apache-2.0
use std::{env, fs, path::PathBuf, process::Command};

fn selected(name: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed={name}");
    let path = PathBuf::from(env::var_os(name).expect(name));
    assert!(path.is_absolute() && path.is_dir(), "invalid {name}");
    path
}

fn run(command: &mut Command) {
    let status = command.status().expect("cannot execute native compiler");
    assert!(status.success(), "native compilation failed: {command:?}");
}

fn main() {
    assert_eq!(env::var("TARGET").unwrap(), "x86_64-aros");
    let host = env::var("HOST").unwrap();
    assert!(matches!(
        host.as_str(),
        "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu"
    ));
    let source = selected("AMI_SPIKE_SDK_SOURCE");
    let sdk = selected("AMI_SPIKE_CSDK");
    let toolchain = selected("AMI_SPIKE_TOOLCHAIN");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ami-native");
    fs::create_dir_all(&out).expect("native output");
    for unit in ["entry", "sdk", "layout"] {
        run(Command::new(toolchain.join("bin/clang"))
            .args([
                "--target=x86_64-unknown-aros",
                "-D__AROS__=1",
                "-D__AROS_VERSION__=1",
                "-DAMIGA=1",
                "-D_AMIGA=1",
                "-ffreestanding",
                "-fno-stack-protector",
                "-mno-red-zone",
                "-mcmodel=large",
                "-O2",
                "-g0",
                "-fno-ident",
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(format!("-ffile-prefix-map={}=/ami-rust", source.display()))
            .arg(format!("-I{}", sdk.join("include/aros/stdc").display()))
            .arg(format!("-I{}", sdk.join("include").display()))
            .arg("-c")
            .arg(source.join(format!("native/{unit}.c")))
            .arg("-o")
            .arg(out.join(format!("{unit}.o"))));
    }
    run(Command::new(toolchain.join("bin/llvm-objcopy"))
        .args(["--redefine-sym", "__startup_entry=ami_sdk_startup_entry"])
        .arg(sdk.join("lib/startup.o"))
        .arg(out.join("startup.o")));
    println!("cargo:rerun-if-changed={}", source.join("native").display());
    println!(
        "cargo:rustc-link-arg=--ami-native-objects={}",
        out.display()
    );
    println!(
        "cargo:warning=RC0 host={host}, C target=x86_64-unknown-aros; native objects generated inside Cargo"
    );
}
