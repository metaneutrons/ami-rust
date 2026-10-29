fn main() {
    println!("cargo::rustc-check-cfg=cfg(target_abi, values(\"abi1\", \"abi11\"))");
    if let Some(objects) = std::env::var_os("AMI_RUST_M3_NATIVE_OBJECTS") {
        let objects = std::fs::canonicalize(objects).expect("M3 native object directory");
        let oracle = std::env::var_os("AMI_RUST_M3_C_ORACLE")
            .map(std::fs::canonicalize)
            .transpose()
            .expect("M3 C oracle path")
            .expect("AMI_RUST_M3_C_ORACLE must name the ABI-specific C oracle object");
        println!("cargo::rerun-if-env-changed=AMI_RUST_M3_NATIVE_OBJECTS");
        println!("cargo::rerun-if-env-changed=AMI_RUST_M3_C_ORACLE");
        println!("cargo::rustc-link-arg=--no-gc-sections");
        println!(
            "cargo::rustc-link-arg=--ami-native-objects={}",
            objects.display()
        );
        println!("cargo::rustc-link-arg={}", oracle.display());
        return;
    }
    panic!("M3 qualification requires explicit native objects and a C oracle");
}
