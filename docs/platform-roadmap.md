# Host expansion and native AROS development — revision 1

Owner decision: Fabian Schmieder, 2026-10-21. The project remains **ami-rust**.
The versioned rustup name is `aros-<version>`, independently of host or target.
This document owns the platform-specific gates below; the
[migration plan revision 4](rust-cli-cargo-migration-plan.md) owns RC2–RC5.
Issues record execution state, not a second acceptance authority.
Cross-host expansion: [L1](https://github.com/metaneutrons/ami-rust/issues/129); native initiative: [epic](https://github.com/metaneutrons/ami-rust/issues/128).

## Outcomes and scope

| Stage | Compiler runs on (host) | Application target | Delivery boundary |
| --- | --- | --- | --- |
| Next cross-development release | macOS 26 Apple Silicon | x86-64 AROS ABI-v1 | RC2–RC5 |
| Next cross-development release | Ubuntu 24.04 x86-64/glibc | x86-64 AROS ABI-v1 | RC2–RC5 |
| Added host for that release | Ubuntu 24.04 ARM64/glibc | x86-64 AROS ABI-v1 | L1 and RC2–RC5 |
| Subsequent AArch64 target | Each qualified cross host | AROS AArch64 | N1 |
| Subsequent native development | AROS x86-64 | AROS x86-64 | N0/N2/N3/N4 |
| Subsequent native development | AROS AArch64 | AROS AArch64 | N0/N1/N2/N3/N4 |

The existing 0.1.0 release, RC0/RC1 evidence and component identities remain
immutable. Adding a planned matrix row does not qualify it. Linux ARM64 is
required for the upcoming migration release. Native AROS development is a later
initiative; it does not silently redefine historical RC1 or turn RC5 into a
claim of native compiler support. Completing RC5 leaves that native initiative
open until its own gates pass on both architectures.

Host package names use their host triple, such as `aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. APT calls the last
two `amd64` and `arm64`. Target specifications/manifests record CPU, OS, ABI,
calling convention, libraries and supported baseline. The existing custom target
name is `x86_64-aros`; `aarch64-aros` is a provisional future name, not an
upstream support claim or a qualified ABI decision.

On each cross host, rustc/Cargo, build scripts, proc macros, C compiler and link
utilities run natively for that host and generate AROS-target code. Linux ARM64
binaries are not AROS AArch64 binaries. Host CPU settings must not leak into the
target CPU/ABI. Future project-controlled native production/test/release paths retain the RC5
no-Python requirement; invoking an upstream dependency generator does not exempt
that execution from the owned pipeline. N0 must identify that closure.
No public ami-rust/cargo-ami CLI or replacement SDK manager is
introduced; standard rustup/Cargo interfaces and focused crates remain the design.

## L1 — Linux ARM64 cross-development host

Execution: [L1](https://github.com/metaneutrons/ami-rust/issues/129).

Dependency: unchanged x86-64 AROS application baseline and historical RC1
mechanisms. L1 is a required platform dependency of prospective RC2/RC3;
development of shared components may continue before L1 closes. L1 uses the
per-host RC2 test results, not an already accepted RC2 milestone, so this does
not create a milestone dependency cycle.

- **L1-A1 — inputs:** pin the Linux ARM64 Rust compiler/rust-src, paired Cargo
  source/patch/build, C compiler/runtime, collector and their complete file,
  licence/source and producer inventories. Reuse target C-SDK/vendor bytes only
  after checking their actual host independence. Published ARM64 prerequisites
  are candidates, not authenticated/qualified merely because an asset exists.
  Do not substitute x86 Linux executables or modify old receipts.
- **L1-A2 — native host and resources:** execute actual ARM64 binaries on a
  native Ubuntu 24.04 ARM64 host. Use the standard GitHub-hosted ARM64 runner
  after a recorded capacity/tool/image preflight; no new private repository or
  self-hosted/temporary runner is implied. Keep the inherited command/campaign,
  RAM/workspace/log budgets. Record cold/warm costs and actual storage capacity;
  an infeasible job needs a prospective measured resource/design change, not
  suppressed measurements or emulation presented as native qualification.
- **L1-A3 — build and observation:** pass every applicable RC2 criterion on this
  third host: selected paired tools, normal Cargo, two roots/five variants,
  spaces/relocation, dependency scripts and Serde host proc macros, offline,
  retry/failure cases, exact canonical/native-code comparisons and separately
  qualified host metadata. Port the native no-Python observer/measurement
  backend for ARM64 and prove its positives and direct/transitive/embedded
  controls. An x86-only syscall adapter or a cross-compile is insufficient.
- **L1-A4 — delivery preparation:** qualify candidate direct and `arm64` Debian
  package layouts and local install/register/build/upgrade/reinstall/remove/
  recovery on ARM64. This is pre-release candidate testing before RC2 acceptance,
  not public channel publication or accepted RC3. Actual authenticated direct
  and public APT readback/consumer acceptance remains RC3-A1–A3 after RC2.
  Wrong host/target, missing/changed tools and cross-version selection must fail
  safely. Preserve user projects, defaults, unrelated toolchains and the old
  qualified release. Homebrew remains the macOS route; Linuxbrew is not added.

Initial survey, 2026-10-21: aros-toolchains v0.1.4 publishes
`aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz` and aros-tools
v0.3.19 publishes `aros-tools_0.3.19_arm64.deb`. Their observed public SHA-256
values are respectively `8d9be3b71eb02f60177c77ed62931caf4ebedd9c34b6ca9312b57157685c572e`
and `c2efbbf524e339993ace08aa2ee851e092c666a0f4893d41c5f8a55f1b3bd1d2`.
These read-only asset observations are not pinned input admission, signature
verification, extraction or execution evidence. See the
[toolchain release](https://github.com/metaneutrons/aros-toolchains/releases/tag/v0.1.4)
and [tools release](https://github.com/metaneutrons/aros-tools/releases/tag/v0.3.19).

## Native initiative sequence

The required end state is actual Rust development entirely on AROS x86-64 and
AROS AArch64: upstream-derived rustup installs/selects/updates authentic native
toolchains; native Cargo builds crate-based applications; native rustc and the
link tools produce runnable AROS programs. Merely linking a prefix on Linux or
cross-compiling a `rustup --version` executable does not satisfy that outcome.

N0 selects and qualifies the feasibility inputs. N1 adds the AArch64 application
target. N2 supplies the required AROS standard-library/OS layer. N3 proves native
rustc/Cargo per architecture. N4 proves complete native rustup/distribution and
the supported lifecycle. N1/N2 design can proceed independently; native x86-64
need not wait for AArch64 implementation, but the initiative cannot close with
one architecture missing. Native implementation/rollout follows the RC5 delivery;
planning now must not advertise or publish unsupported hosts.

## N0 — Native-host feasibility and dependency census

Execution: [N0](https://github.com/metaneutrons/ami-rust/issues/130).

- **N0-A1:** select exact rustc/LLVM/Cargo/rustup source revisions, host triples,
  dependency/features and source obligations; inventory OS/API requirements
  through their real transitive closure. Separate upstream source availability
  from an AROS port and maintain narrow upstream-oriented patches.
- **N0-A2:** pin bootable native test systems separately for x86-64 and AArch64,
  their ABI/C-SDK, filesystem and networking capabilities. Do not reuse the
  x86-64 baseline as proof of AArch64 ABI or boot support.
- **N0-A3:** measure compiler/linker and install/update resource needs, then set
  realistic native-host profiles and pass/fail campaigns before experiments.
  The 512 MiB application QEMU profile remains unchanged and is not assumed
  sufficient for native rustc/LLVM. Preserve all failed probes and recovery.
- **N0-A4:** a reviewed dependency/gap report classifies each required facility
  as implemented/proven, implementable with a concrete owner/task, or blocked.
  GO requires a testable path to the complete N1–N4 outcome on both architectures;
  no-go/defer leaves it explicitly open rather than substituting a smaller tool.

## N1 — AROS AArch64 application target

Execution: [N1](https://github.com/metaneutrons/ami-rust/issues/131).

Dependency: N0's selected AArch64 ABI, SDK and boot baseline.

- **N1-A1:** freeze target specification, ABI layouts/calling conventions,
  native startup/library vectors, C toolchain and runtime identities. Decide
  canonical target naming explicitly; do not assume x86 ABI-v1 is identical.
- **N1-A2:** build the public API/runtime/build/link crates from every qualified
  cross host, including Linux ARM64, with genuine target/host separation.
- **N1-A3:** qualify AArch64 reproducibility, loader/startup, task/resource
  ownership, allocation-free diagnostics, memory/failure/teardown and dependency
  cases against its own native baseline. No retuned golden hash alone is proof.
- **N1-A4:** publish only after exact package/source/provenance, compatibility,
  installation and rollback evidence passes; keep existing x86-64 releases usable.

## N2 — Standard library and operating-system integration

Execution: [N2](https://github.com/metaneutrons/ami-rust/issues/132).

Dependency: N0, plus N1's ABI decisions for AArch64. Gate separately per architecture.

- **N2-A1:** implement and test the Rust standard-library/OS interfaces actually
  required by the pinned native tools: allocation, filesystem/volume/path and
  permissions, environment, subprocess creation/wait/status/arguments, clocks,
  randomness, synchronisation/threads and required networking. Do not treat AROS
  as Linux or assume Unix fork/POSIX semantics that the chosen baseline lacks.
- **N2-A2:** prove filesystem extraction, atomic replacement, locking, concurrent
  access, interruption, permissions and path edge cases on supported native
  filesystems; preserve existing files and report unsupported facilities clearly.
- **N2-A3:** prove required DNS/TCP/HTTPS/TLS, trust roots/certificate validation,
  cryptographic verification and failure cases through actual native dependencies.
  No insecure transport, skipped verification or host-side network proxy is a
  substitute for complete native tool support.
- **N2-A4:** upstream-derived standard-library and tool dependency tests plus
  deliberate facility failures run natively, with measured resources and durable
  reports on both architectures. Compatibility work cannot hide in an umbrella CLI.

## N3 — Native compiler, Cargo and link tools

Execution: [N3](https://github.com/metaneutrons/ami-rust/issues/133).

Dependency: N2, and N1 for AArch64. Gate separately per architecture.

- **N3-A1:** authenticated native rustc/LLVM, rust-src/target libraries, Cargo,
  C SDK and link tools run on the selected AROS host. Cross-produced bootstrap
  binaries are allowed only with identified source/inputs and native execution.
- **N3-A2:** native Cargo resolves/fetches/checks/builds real crate applications,
  build scripts and host proc macros, including Serde derive. The resulting AROS
  binaries run on that same architecture. Test locked/offline and incremental
  builds, errors/retry and target/host tool selection without remote compilation.
- **N3-A3:** reproduce native outputs under the declared comparison rules;
  execute runtime/memory/cleanup tests and compiler process/interruption controls.
  State any remaining bootstrap/self-hosting limits explicitly; a help/version
  probe cannot qualify native development.

## N4 — Native rustup and complete distribution lifecycle

Execution: [N4](https://github.com/metaneutrons/ami-rust/issues/134).

Dependency: N3 on each advertised architecture; final acceptance requires both.

- **N4-A1:** port upstream rustup's actual host detection, proxies, process/path,
  filesystem, archive and network dependencies; use its standard interfaces and
  source-derived patch set. No replacement ami-rust installer/updater CLI.
- **N4-A2:** deliver real native compiler/components from an authenticated
  publisher through a reviewed standard distribution/channel arrangement. Official
  Rust distribution requires upstream acceptance; a local registration or custom
  manifest is not evidence of official `rustup target add` availability. Do not
  deploy new public distribution infrastructure merely by editing this plan.
- **N4-A3:** execute fresh install, version selection, component/target operations,
  update, rollback, reinstall, uninstall and documented recovery entirely on each
  AROS host, followed by a fresh Cargo build/run. Include rustup self-update and
  interrupted/tampered/wrong-host/download/TLS failures, offline use and multiple
  coexisting versions. Preserve unrelated toolchains, user projects and defaults.
- **N4-A4:** exact new artifacts pass licence/source, signatures/provenance,
  native reproducibility/runtime/resources, independent review and public consumer
  replay. Execute the native README verbatim. No native support claim or initiative
  closure before every required architecture and lifecycle case is evidenced.

## Sources and current limitations

Rust explicitly distinguishes targets from platforms with native host tools;
the current AROS SDK supplies a `no_std` application subset, not this host-tools
capability. Upstream rustup's current source depends on filesystem, concurrency,
HTTP/TLS and runtime libraries. Those are porting requirements to inventory,
not evidence that their dependencies already work on AROS:
[Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html),
[rustup source dependencies](https://github.com/rust-lang/rustup/blob/master/Cargo.toml).
These links are survey context, not pinned future build inputs.

GitHub lists `ubuntu-24.04-arm` as a standard public-repository ARM64 runner;
actual job capacity and dependency availability still require L1-A2 evidence:
[runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Protected AROS-NX/aros-tools checkouts remain unchanged; nxpk is excluded.
