# RC0 Cargo-to-native-ELF design probe

This is an internal feasibility result for [RC0 #70](https://github.com/metaneutrons/ami-rust/issues/70),
not a supported replacement CLI, RC0 acceptance or a new SDK release. The
[machine-readable results](rc0-results.json) bind source/input hashes, original
failures, timings, resource observations and remaining requirements.

## Observed macOS result

Using the existing pinned Cargo, nightly compiler, C SDK and collector, a
generated `hello-aros` application was changed from `staticlib` to a Cargo binary
with `#![no_main]`. Cargo called a small standard-library-only Rust linker
adapter through its normal `-Clinker` interface. That adapter invoked the native
collector and LLVM strip tool and performed the frozen, payload-preserving ELF
section-name finalisation in Rust. Cargo returned with the final native ELF;
there was no subsequent application link or finalisation step.

The final control artifact is 342,400 bytes, SHA-256
`46ef2b84c62d8c02b9088fba4e6638adebc40477f8a13a807cc49b222c9cb8cb`.
Two fresh Cargo output roots, one containing spaces, produced exactly these
bytes. This is a hello control program, not the separately qualified R1 SHA
utility/reference executable. No comparison with that different program is made.

The unchanged old ELF auditor independently accepted the ABI-v1 ET_REL header,
entry, allocated-section order, symbols and relocations. The old finaliser,
applied only to an isolated stripped intermediate as an internal test oracle,
produced exactly the same bytes as Rust. Neither Python oracle was part of
Cargo's link/finalisation process tree. These read-only/oracle checks remain
temporary internal test infrastructure.

The probe reused the four native bridge/startup objects from an existing
SDK-reference build. Each hash/size is bound to its original build receipt and
checked before and after the successful final probe. New Cargo `build.rs`
generation of those C objects is still required. The target compiler, C SDK and
qualified boot/ABI baseline were not changed. The Rust host adapter uses the
existing host bootstrap compiler 1.98.1, independently of the target nightly.

## Necessary linker translation and preserved failures

1. rustc's `gnu-lld` interface passes `-flavor gnu`. The collector already calls
   GNU ld.lld, which rejects that dispatcher option. The Rust adapter consumes
   exactly that GNU selector; other explicit flavors fail.
2. The native collector uses relocatable linking (`-r`); executable-style
   `--gc-sections` is incompatible with that link. A global `-Clink-dead-code=yes`
   experiment was rejected by `compiler_builtins` during sysroot compilation.
3. The successful route keeps the frozen Rust code-generation options and adds
   the explicit linker argument `-Clink-arg=--no-gc-sections`. This is a new,
   identified experimental recipe, not a silent update of a sealed SDK recipe.

All three failures remain failures in the evidence. The first attempt also used
a different source epoch and cannot serve as an equivalence test; subsequent
attempts use the SDK's pinned epoch 1791936000. The complete local campaign stayed
inside its declared 90-minute/resource contract without a budget exception.

## Source and verification scope

The standalone crate is [`tools/cargo-native-spike`](../../tools/cargo-native-spike/).
It has no external Rust dependencies. Host CI covers a valid synthetic native
ELF section-name fixture and malformed ABI/range controls on both host platforms;
that job does not reproduce the full Cargo/native-link experiment. Actual
two-host linking remains a separate RC0 requirement. The linked ELF's complete
Rust symbol/relocation auditor and compiler/input guard have not been implemented.
The current adapter trusts explicitly selected experiment paths and is not an
installation or security boundary.

No AROS runtime/memory test was performed for this experiment. Linux linking,
complete process-tree/no-Python enforcement, the C build-script route, new
contracts and release qualification remain outstanding. See the separate
[no-Python harness](no-python-harness.md) and
[consumer contract survey](consumer-contracts.md).
