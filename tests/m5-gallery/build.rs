fn main() {
    if let Some(objects) = std::env::var_os("AMI_RUST_M5_NATIVE_OBJECTS") {
        let objects = std::fs::canonicalize(objects).expect("M5 native object directory");
        println!("cargo::rerun-if-env-changed=AMI_RUST_M5_NATIVE_OBJECTS");
        println!("cargo::rustc-link-arg=--no-gc-sections");
        println!(
            "cargo::rustc-link-arg=--ami-native-objects={}",
            objects.display()
        );
        return;
    }
    panic!("M5 qualification requires explicit native objects");
}
