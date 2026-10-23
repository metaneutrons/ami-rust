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
and native objects must agree between those roots. The pinned nightly compiler
receives `-Zunstable-options` together with the reproducibility path mappings
for its custom target. Fixed system programs are canonicalized before the
unchanged protected-executable checks, including merged `/usr` Linux systems. Missing-compiler and wrong
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

## Local checks before spending CI time

First run the inexpensive offline development gate on the actual host:

```bash
bash tools/check-native-cargo-offline.sh "$host_triple" "$pinned_bootstrap_prefix" "$fresh_work_root"
```

It verifies the current application and tooling locks against the separate
`native-cargo-vendor-inputs.json` material record, checks the archive identity,
resolves both complete graphs offline in a fresh Cargo home, and builds the
actual native `aros-link`. The 51-package union is independent of the sealed
legacy SDK vendor archive. A changed lock requires a new reviewed vendor input;
the old input and historical evidence remain intact.

Then exercise the same component staging and ordinary-Cargo proof as CI:

```bash
bash tools/qualify-native-cargo-local.sh "$host_key" "$pinned_zip_cache" "$pinned_bootstrap_prefix" "$rustup_binary" "$fresh_base"
```

The cache contains the exact retained producer ZIPs named
`native_cargo-HOST.zip`, `bare_target_libraries-HOST.zip`, and, for ARM64 Linux,
`linux_aarch64_csdk.zip`. The script verifies their pinned lengths and hashes,
copies the pinned bootstrap and a private rustup selector, builds the shared
qualification helper offline, and calls the existing measured staging and
application functions. It retains original records under the fresh base.
Bootstrap/helper preparation retains the same separate trust boundary as CI.
No user's rustup defaults, projects, registry cache or installed SDK are changed.

Use native macOS ARM64, Ubuntu 24.04 ARM64 in an isolated local VM/container,
and native Ubuntu 24.04 x86-64 on an available x86-64 machine. Keep machine names,
VM definitions, local cache paths and credentials outside the public repository.
Check effective RAM and disk capacity before starting large local work. The
shared runner also requires a hard open-file limit of at least 4,096 and raises
only its own inherited soft limit when needed. The pinned prefix assembler
anchors approximately 1,300 output directories; a 1,024-descriptor login default
is insufficient. This preparation does not change system-wide limits. Reuse
verified immutable inputs; keep failed attempts instead of resetting their clocks.
For a continuation in a new work root, retain the original
`NATIVE_CAMPAIGN_START_EPOCH`; the local runner accepts an inherited, bounded
clock and refuses one without a complete command window.

Local green results provide development feedback. They do not replace the
independent protected-runner qualification, cross-host output comparison, AROS
runtime/memory checks or RC2–RC5 acceptance. Launch the expensive protected
matrix after the affected local paths pass.
