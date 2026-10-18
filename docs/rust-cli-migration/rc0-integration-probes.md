# RC0 integration probes after the first feasibility slice

This is partial RC0 evidence, not a supported installer, RC0 acceptance or an
SDK release. The normative criteria remain in the revision 2 migration plan.
The new workflow is `.github/workflows/rust-migration-probes.yml`; it uses
standard Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon runners without publish
permissions. Hosted outcomes must be recorded after the exact run finishes.

## Cargo activation and C generation

`tools/rc0-native-probe.sh FRESH_ROOT HOST_PROFILE [EXISTING_SELECTION_JSON]`
is an internal experiment driver. With no existing selection it obtains the
hash-pinned immutable 0.1.0 payload and target prerequisites. Historical Python
sources in that payload remain inert. The script does not implement consumer
signature policy or establish a new distribution trust contract.

The separate host adapter compiler remains 1.98.1, commit
`48a229ceaefd4985c50990b14116b6d856af0985`. Target nightly, custom Cargo,
collector, C compiler and derived C-SDK identities remain unchanged. The Cargo
binary is checked against the accepted per-host producer report, rather than
the old source-template component inventory. The first local attempt stopped
at this distinction before compilation; that failure is retained.

Two isolated applications receive local `.cargo/config.toml` activation. This
selects the qualified Cargo unstable settings, target Rust, independent host
flags, target/linker flags and vendored sources. Normal `cargo metadata`,
`cargo check` and `cargo build --release` run with committed/generated locks
and offline selection. No global rustup default is changed. Ambient Cargo and
compiler overrides are rejected before creating output. CI includes a deliberate
`RUSTFLAGS` override and asserts refusal with exit 2 and no new output directory.
The supported activation/compiler guard and legacy state migration still need
RC1/RC2 implementation; this experiment is not that security boundary.

The owned application `build.rs` runs on the host, compiles entry/sdk/layout C
objects with the frozen target flags, adapts the pinned startup object and
passes their output directory to the Rust linker adapter. The adapter preserves
startup order, calls the native collector and LLVM strip, and performs Rust
section-name finalisation inside Cargo's link step. The old read-only Python
ELF audit runs separately as transitional internal test infrastructure.

Local macOS result: both roots, including `root b with spaces`, passed all
three normal Cargo commands. The final control program is 342,136 bytes,
SHA-256 `abfb4585d08b18b117218d0df8c3330bd99c74bb739b46cfd85d55db576fe472`.
Both independent ELF audits passed. All four regenerated native object hashes
match the original receipt-bound objects from the first design experiment.
This control has a different package identity from the earlier hello probe;
its changed Rust output is not presented as equivalence to another program.
Linux results remain outstanding until the workflow is executed and inspected.

## macOS loader enforcement and independent kernel observation

The standalone no-Python probe adds an allowlisted C-embedding control. It may
start under a separate sandbox policy, while the resolved libpython mapping is
explicitly denied. The unconfined C fixture must first execute Python and emit
its marker. Under the loader policy it must fail, name libpython in the loader
error and emit no Python marker. This control passed locally. It supplements
the original unlisted-executable refusal; it does not detect static interpreter
semantics in an arbitrary binary. All new accepted executable inputs still need
reviewed source/build provenance and a declared dependency closure.

`--observe` starts Apple's independent `fs_usage -w -f exec` kernel trace in UTC
using noninteractive sudo. Case reports bind start/end timestamps to trace
windows. The observer must see the four positive routes, all ten case routes
and four kernel EPERM refusals. The code rejects a missing or failing observer;
a successful sandbox-only control run cannot establish observer qualification.
Raw traces contain process paths, so they stay in reviewed qualification
artifacts rather than being pasted into issues. No argv/environment dump from
EndpointSecurity is used. The hosted runner's actual sudo/trace availability
still requires its own observed result.

Retained exploratory failures: filtering fs_usage by the target executable name
missed events attributed to the caller; unfiltered capture observed the native
positive control. EndpointSecurity eslogger refused access because its caller
lacked Full Disk Access; no security setting was changed. The first timed
harness run observed control paths but could not match the overlong interpreter
path, which fs_usage truncates even in wide mode. It failed closed. A short
owned copy of the same pinned CPython runtime is used for the next local probe;
A second run exposed a few milliseconds of difference between the kernel
trace clock calibration and wall-clock timestamps. The observer now records a
10 ms uncertainty bound, separates cases by at least 25 ms and refuses
overlapping correlation windows. The next run independently observed all ten
case routes, the four positive routes and four kernel EPERM refusals. CI already
provisions a short private runtime path. Whole-file interpreter and
library identities remain the same, with all negative and positive controls.

The OS dyld shared-cache and reproducible source/loader closure boundaries, and
Linux enforcement results, remain explicit RC0 review work. No AROS runtime or
memory qualification, SDK publication, protected checkout change, or RC1–RC5
acceptance is claimed by these experiments.

## First hosted run and corrections

PR #78's first integration run, 39169664621, is retained as **FAIL**. The macOS
native design stage passed two audited fresh roots within 248.4 seconds, about
1.71 GB peak observed descendant RSS and 3.58 GB managed workspace. The later
observer step stopped when the runner account could not read the setuid
`/usr/bin/sudo` for hashing. The probe now obtains the digest for that exact OS
path through the existing noninteractive privileged OS hash helper; the test
program and interpreter controls remain unprivileged. Host fixture release
profiles explicitly disable the optional strip tool, which was warning about
an absent optional LLVM library in the minimal host compiler installation.

Linux metadata/check reached the native link, where the collector correctly
refused missing physical sibling tools. A symlink pointed back into the input
capsule. The adapter now copies the unchanged collector binary into its owned
sibling-tool directory and checks that the copied bytes match. Both original
inputs and their qualified identities remain unchanged.

The Linux policy controls actually refused the intended Python routes, but two
assertions failed. A descendant refusal diagnostic echoed the execution marker
as a label, and the embedding checker read the outer stderr although its child
stderr was encoded inside wrapper stdout. The diagnostics and nested-stream
checker are corrected, with regression fixtures; neither Landlock nor seccomp
permissions were relaxed.

The first hosted macOS ELF and the original local ELF differed in 55 symbol-name
bytes, with identical size and no local absolute path strings. The experiment
had referenced SDK path dependencies outside the portable project. The recipe
now places the SDK Rust sources inside each generated application, as the
existing project generator does, and restores the declared project workspace
package fields and complete source-prefix mappings. This is source/configuration
normalisation before compilation, not rewriting compiler metadata or finished
ELF symbols. The resulting candidate has its own identity and needs the next
hosted comparison. The local retry passes both fresh roots; all prior results
and setup failures are retained.

The independent review also required integration to rerun on all consumed pin,
source and helper changes, and to bind each kernel EPERM event to the intended
exact control target. Both checks are now explicit; decoy paths and wrong errno
values fail their fixtures. The host dependency lock/license/API review remains
a separate RC0-A2 task. No milestone acceptance is inferred from these repairs.

## Corrected hosted qualification

[Run 39170474195](https://github.com/metaneutrons/ami-rust/actions/runs/39170474195)
passed all three integration jobs for candidate
`5a1ad03bd50cdf0484c32efea03dfa614024c838`; PR #78 merged at
`b16a025a7b3b1d072b1633e1f5cbd4d927fdd80e`.
The machine results, independent ELF audit summaries, original report digests and an artifact file/digest
inventory are retained in [the evidence directory](evidence/rc0-integration-39170474195/index.json).

All four fresh host/root combinations produce the identical 342,136-byte final
native executable, SHA-256
`f43ba62f560fbca46f11486a95c433cabba83a24ba52bd8ed130cfa025524acd`.
This matches the latest local colocated-source recipe, superseding the earlier
external-path experiment while preserving its results above.

| Host | Native command duration | Observed peak descendant RSS | Managed workspace | Result |
| --- | ---: | ---: | ---: | --- |
| Ubuntu 24.04 x86-64 | 139.156 s | 1,834,442,752 bytes | 4,382,713,573 bytes | Two roots and independent ELF audits PASS |
| macOS 26 arm64 | 171.516 s | 1,709,998,080 bytes | 3,585,602,688 bytes | Two roots and independent ELF audits PASS |

Both fit the prospectively selected 4 GiB descendant RSS, 12 GiB workspace,
16 MiB logs and 1,200-second command bounds. These are hosted experiment limits,
not AROS application allocation limits. Internal resource orchestration and the
independent ELF oracle still use Python, outside the experimental Cargo process.
Their retirement belongs to RC4; this campaign cannot establish RC5.

Linux's 12 interpreter-policy controls pass. macOS's ten controls pass, with
independent observation of all ten routes, four positive interpreter routes and
four exact-target kernel EPERM refusals. Its complete-source-closure status
remains PARTIAL; controlled-route evidence does not identify interpreter
semantics hidden inside arbitrary allowed binaries. Selected executable source
and build provenance remain part of the acceptance boundary. No new AROS
runtime, complete consumer implementation or release is accepted here.
