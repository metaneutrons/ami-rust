# Cross-host Cargo application qualification

`native-cargo-qualification.yml` qualifies ordinary Cargo application builds on
macOS ARM64, Linux x86-64 and Linux ARM64 for the fixed **x86-64 AROS ABI-v1
target**. Rustc, Cargo, rustup and the linker execute on the development host.
The generated application executes on AROS. This workflow does not establish
that a compiler, Cargo or rustup runs on AROS.

The workflow authenticates the retained Cargo and target-library producer ZIPs
and the ARM64 C-SDK producer ZIP against their pinned GitHub run, source and
artifact identities. Downloaded component archives have fixed URLs, lengths
and SHA-256 digests. The private Rust maintainer command validates the staged
component profiles and uses the existing resource monitor and prefix composer.
The focused host linker is built from the current source
with the pinned host bootstrap. No producer is rebuilt merely to launch an
application qualification run.

For each host, the measured application phase links an isolated
`aros-0.2.0-dev` rustup selection and builds core, allocation, qualification,
dependency and SHA-256 examples in two fresh source roots. Complete ELF bytes
and native objects must agree between those roots. Missing-compiler and wrong
linker controls must produce the intended Cargo diagnostic with complete
capture, healthy resource measurement and no accepted ELF output. Offline
fixtures also reject malformed artifact inventories, incorrect publisher/run
metadata and modified original ZIP bytes before the corresponding input is
admitted.

Only protected `main` may launch the workflow manually. Each host job has a
90-minute total window, including five minutes for finalization. Measured
commands retain the existing RAM, workspace and log limits; the outer monitor
also covers the application driver. The initial trusted harness bootstrap is
recorded separately and is outside that application resource claim. Original
requests, command records, logs and output artifacts are retained within the
existing 64 MiB host-artifact policy. The workflow publishes no SDK.

`HOST_WORKSPACE_CARGO_PROOF_ONLY` is a host-local workspace/path-package result.
Full RC2 still requires cross-host comparison, independently versioned crate
application, relocation and the remaining specified controls, plus runtime and
memory evidence bound to the actual resulting AROS programs. RC3–RC5 and native
AROS tooling remain separate acceptance gates. The authoritative criteria are
in [the migration plan](rust-cli-cargo-migration-plan.md).
