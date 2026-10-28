fn main() {
    aros_native_build::prepare(aros_native_build::BuildOptions { testing: true })
        .expect("AROS qualification native bridge");
}
