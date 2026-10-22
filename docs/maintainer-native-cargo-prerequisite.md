# Native Linux Cargo prerequisite

The manually dispatched native-Cargo workflow produces a development host
prerequisite for Linux x86-64 and Linux ARM64. It does not publish an SDK or
package, admit a new SDK host, or accept RC2, RC4, RC5 or L1. The public interface
remains standard rustup and Cargo; these are internal maintainer tools.

The [platform roadmap](platform-roadmap.md#l1--linux-arm64-cross-development-host)
defines ARM64 host admission. Complete Rust/Cargo/rustup development on AROS
x86-64 and AArch64 remains the later N0–N4 initiative in that roadmap.

## Source and execution boundary

Run this workflow only from the protected `main` branch of this repository.
Both jobs use standard GitHub-hosted Ubuntu 24.04 runners, with native
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` host programs. No
emulation, private input repository or self-hosted runner is required.

Each job starts a fresh attempt directory, records source/run/host identities
and checks runner and retained-artifact capacity before downloading or building.
It shares the protected-build concurrency group with the other producers.

The pinned bootstrap compiler is an input, not the candidate AROS compiler.
The native Rust producer uses the Cargo source and narrow patches in
`host/cargo-repro/three-host-v2/`. The workflow checks the tracked bootstrap,
source, overlay, resource-policy and tooling-lock identities. Derived Cargo
binaries receive new receipts; existing producer records remain unchanged.

## Required checks and retained output

The producer executes the native qualification-helper tests and its intentional
nonzero-exit control before using the helper for production phases. Source
preparation, provisioning, overlay verification and Cargo production use typed
command records. The resulting Cargo must report the expected version, have the
correct native ELF architecture and usable loader/dependencies, and build and
run an offline host application. Wrong-host and changed-receipt copies must be
rejected for the expected reason.

Retained artifacts identify the exact source, patches, tools and native host,
include the produced Cargo and compressed command evidence, and report failures
as failures. A successful Cargo prerequisite is an input to subsequent SDK
qualification. It cannot substitute for the three-host ordinary-Cargo matrix,
AROS runtime/memory tests, authenticated SDK production or channel acceptance.

## Temporary resource supervision

This development workflow temporarily reuses the existing internal Python
supervisor around the Bash/native-Rust recipe. Python is not installed into the
consumer toolchain. This is an explicit intermediate dependency before RC4;
the complete production path must later be qualified without Python.

The inherited limits remain 4 GiB aggregate resident memory, 12 GiB managed
workspace, 16 MiB uncompressed logs, 1,200 seconds per tool phase and 5,400
seconds per campaign, with a 300-second review reserve. Native command requests
use at most 3.5 GiB, reserving 512 MiB for the outer driver and launcher
processes. Managed source, work and output roots must not overlap.

The outer supervision covers bootstrap downloads, vendoring, initial helper
compilation, native producer phases, smoke tests and Bash artifact packaging.
Checkout, GitHub upload and final supervisor-result serialization have separate
observation boundaries. These records must not be described as complete RC4
workflow qualification or proof that no Python descendant executed.

Each host artifact reserves 128 MiB, including upload framing, within the
existing shared 768 MiB retained-artifact pool. Capacity checks and actual
uploaded-size checks both remain mandatory. A failed or interrupted attempt
keeps its own identity and evidence; reruns use a new attempt root.
