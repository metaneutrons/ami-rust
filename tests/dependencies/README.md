# ami-rust-dependencies

Native dependency-integration fixture covering Serde derive,
allocation-enabled JSON round trips and Ed25519 verification. It uses ordinary
Cargo with the pinned `aros-native-build` helper and the `x86_64-aros` target
libraries. The native test build enables the `bind.o` hooks. This is not a
standalone application or a publication artifact.
