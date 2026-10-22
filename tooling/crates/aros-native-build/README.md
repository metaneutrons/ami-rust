# aros-native-build

Development candidate for ordinary Cargo application builds targeting the pinned
x86-64 AROS ABI-v1 baseline. This crate is not yet release-qualified or published.
The complete RC2 matrix remains required on macOS Apple Silicon, Linux x86-64
and Linux ARM64. ARM64 input admission is still open.

The library compiles the existing native bridge from an application's additive
`build.rs`; the focused `aros-link` executable handles rustc's target-linker
interface, including collector linking, stripping, ELF section compaction and
ABI validation before Cargo receives the output. It does not invoke Cargo,
resolve packages, install SDKs, register rustup toolchains or modify projects.

```rust,ignore
fn main() {
    aros_native_build::prepare(Default::default()).expect("AROS native bridge");
}
```

The selected toolchain must contain the matching paired Cargo, precompiled target
libraries, unchanged target specification and pinned C-SDK/C compiler/collector.
Machine-local Cargo linker configuration points explicitly at its `aros-link`.
Do not put the whole toolchain bin directory ahead of rustup's proxies; that can
bypass project toolchain selection. The final configuration and package layouts
must pass the RC2/RC3 consumer qualification before release instructions are
advertised.
A prospective composed prefix must include the relative `target.json` and
host-specific `bin/aros-link` aliases for standard Cargo and rustc discovery after
relocation. The selected toolchain's paired Cargo must be used, and a non-empty
`RUST_TARGET_PATH` is rejected.

A bare-target compiler probe confirmed that this alias discovers the target
specification but does not make the existing `core` and `compiler_builtins`
usable: their target metadata is `x86_64-aros-10008448819653387821`, so rustc
rejects them with E0461. A prospective bare-target prefix requires newly
source-produced target libraries whose metadata matches the selected target; the
alias alone is insufficient. This source proposal changes no target libraries or
ABI baseline, does not implement prefix composition, and does not qualify an SDK
release.

`BuildOptions::testing` enables the retained qualification-only C hooks. It is
not an application feature or a separate package manager. Source obligations and
original component notices remain in the enclosing toolchain distribution.
The crate's own code is MIT OR Apache-2.0; see the bundled licence files.

The local checks trust the installed rustup and its normal `rustc` launcher as
prerequisites (including packaged Homebrew launchers). They verify the compiler
chosen by rustup, paired Cargo and the explicit target linker against the pinned
prefix. This is input consistency, not publisher authentication or a sandbox
for arbitrary project build scripts. Release observation must separately bind
the actual compiler/link processes and their effective inputs.

Each prepared native-object record includes the selected target-linker binary's
size and SHA-256; linking rechecks that identity. Publisher authentication of
that newly produced tool remains a distribution qualification requirement. A
self-reported local hash alone does not authenticate its origin.
