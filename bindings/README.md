# AROS API binding inputs

`aros-api.json` is the reviewed public API allowlist. Maintainers generate the
Rust backends from two complete SDKs; generated sources and provenance are
committed. Consumers do not run the generator and do not need an AROS source
checkout.

The complete MUI class surface has a separate canonical model in
[`mui/`](mui/README.md). It is generated from pinned source commits because the
public class hierarchy and per-symbol metadata do not all exist in the binary
SDK headers.

The current pinned inputs are the ABI-v1 Developer SDK derived from AROS-NX
commit `e0d5e367d15cc7da4ebac8f9db17868756c79569` and the Deadwood ABI-v11
2026.09 Development SDK from release commit
`fbc242c1046cffb5e5827a4626ee62bdd45664e9`. `provenance.json` records the
actual consulted header bytes by SHA-256.

Generation uses the repository's Rust 1.98.1 formatter. Set `RUSTFMT` to an
equivalent executable when that toolchain is not the active rustup default.

```sh
cargo +1.98.1 run --manifest-path tooling/Cargo.toml -p aros-api-gen -- generate \
  --repository . \
  --abi1-sdk /path/to/abi1/Developer \
  --abi11-sdk /path/to/abi11/Development
```

Use `check` with the same arguments to compare the committed files without
modifying them. The generator verifies every selected function and vector
against both SDKs. Variadic APIs remain excluded. The reviewed seven-argument
`MUI_RequestA` signature uses an explicit ABI11 stack adapter; larger or
otherwise nonordinary call shapes require another reviewed adapter rather than
an inferred signature.
