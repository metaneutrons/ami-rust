# aros-native-build

Internal build helper for ordinary Cargo application builds targeting the pinned
x86-64 AROS ABI-v1 baseline. It remains unpublished (`publish = false`). The
initial ami-rust release distributes it as part of the pinned toolchain rather
than through crates.io.

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
must pass the repository's consumer qualification before release instructions
are advertised.
A prospective composed prefix must include regular-file copies of the matching
`target.json` and host-specific `bin/aros-link` entries for standard Cargo and
rustc discovery after relocation. The host linker copy must match the root
source-built linker; legacy symbolic-link slots are refused. The selected toolchain's paired Cargo must be used, and a non-empty
`RUST_TARGET_PATH` is rejected.

A bare-target prefix requires source-produced target libraries whose metadata
matches the selected compiler and target specification; the alias alone is
insufficient. The pinned matching libraries and ABI baseline remain unchanged.

The public component view excludes debugger, editor and LLVM convenience files
that are not required for the supported Cargo application path. The versioned
`pins/public-view-v1.json` selects each file by component, path, byte length and
SHA-256. The crate derives its expected tree from the original pins, includes
the policy bytes in the input identity and rejects reintroduced paths.

The shared portable-view policy derives regular copies and rustup-compatible
permissions from the verified original inventories. Its source/output modes,
resolved link targets and omitted installer rows are recorded separately;
compiler and archive contents are unchanged. The five root LLVM convenience
aliases are unavailable in this view: all LLVM tools remain in their complete
`libexec/aros/llvm/bin` location so loader-relative library discovery remains
correct. The Cargo recipe uses that location directly. All supported hosts and
rustup must qualify the same resulting SDK before release.

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

The portable SDK places its pinned collector at
`libexec/aros/llvm/bin/collect-aros-sdk`, next to its fixed LLVM sibling tools.
Cargo selects this path; the historical root `bin/collect-aros` is refused.
Portable policy v2 and consumer identity v4 record this placement without
changing original component bytes or the LLVM component's legacy aliases.

The relocated SDK collector is invoked with `argv[0] = "collect-aros"` to retain
the pinned executable's alias mode and LLVM sibling discovery. Its bytes remain
unchanged; other command invocations keep their ordinary argument handling.
