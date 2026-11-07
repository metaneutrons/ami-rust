fn main() {
    println!("cargo::rustc-check-cfg=cfg(target_abi, values(\"abi1\", \"abi11\"))");
    aros_native_build::prepare(Default::default()).expect("AROS native bridge");
}
