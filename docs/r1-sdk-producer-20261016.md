# Protected SDK producer attempt — 2026-10-16

[Protected run 38887318378](https://github.com/metaneutrons/ami-rust/actions/runs/38887318378)
at source `3d0c33a698d00a5399991fc78f25ef7d997edfdb` failed on both standard
hosted runners. Cargo prerequisite compilation succeeded. Source SDK packaging
then refused the source-frozen Cargo reports because they bound the earlier
resource-policy digest. SDK native compilation, assembly, signatures and clean
consumer verification did not run. R1-A6 remains open; no SDK was published.

The correction replaces each frozen report with the complete, unmodified Cargo
report from that run. The previous reports remain in Git history. Downloaded
artifact ZIP hashes matched the hashes returned by the GitHub API. Both cleanup
receipts report zero remaining managed work and Python runtime bytes.

| Host | New raw report SHA-256 | Current Cargo binary SHA-256 |
| --- | --- | --- |
| macOS ARM64 | `e57b8c1d1729aa5efba584906316125a26454e26de675b6e807a9398f530f13f` | `41c55876551dd15a41f183b70bc481265de211c886fca9e6b77b4b10ca3e23e8` |
| Linux x86-64 | `ff23ac7d16ea758b5067acae3af590d4051e25b1f4371b5028c6a968e8166ca6` | `938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db` |

Linux Cargo retains its previous exact bytes. macOS Cargo is 39,348,872 bytes,
16 bytes smaller than the previous Cargo-only workflow output. This is a new
prospective component identity, not evidence that the old and new executables
are equivalent. Failure cleanup retired the executable, so the underlying byte
difference is not classified. Another clean SDK-workflow build must match the
new frozen artifact exactly; native linkage and licence review remain required.
No compiler metadata or finished binary has been rewritten.

The producer now validates both frozen reports against the current tracked
inputs, resource policy and helper identities before compiling Cargo. Source CI
exercises the real two-host reports and a stale-policy counterexample. Fresh
Cargo must match its selected host report before further SDK provisioning. The
strict packager and component checks remain in place. The distribution SBOM
binds the current Cargo artifact and raw receipt for each host; its complete
asset checksum is updated without changing source/licence records.

The 32 GiB local free-space policy applies to development storage only. It does
not relax hosted-runner limits or AROS runtime, ABI, stack or heap criteria.


## Installer log collision in the next attempt

[Protected run 38890929579](https://github.com/metaneutrons/ami-rust/actions/runs/38890929579)
at source `20e56ebe052b4dbb2c71c7cd9a7afe020f2448d2` reproduced both frozen
Cargo binaries exactly and passed source-SDK packaging. Both hosts then stopped
before SDK Rust installation: Cargo bootstrap and SDK installation used the
same exclusive `install-rust-rustc.stdout.log` path in their shared work logs.
Both cleanup receipts report zero remaining work/Python bytes. Assembly,
signing and production consumers were skipped. No SDK/native qualification or
publication follows from this failed attempt.

SDK Rust installation now uses `sdk-install-rust-{component}` log labels;
Cargo bootstrap labels and source identities are unchanged. The regression
fixture runs all four SDK installers through the real supervisor with existing
Cargo log sentinels and verifies their exact preservation. All 29 focused SDK
fixtures pass; an independent source review found no further concrete blocker
in the immediate producer interfaces. Native production still requires a fresh
successful campaign.


## Cargo scratch retirement before C-SDK derivation

The later [paired Cargo qualification](https://github.com/metaneutrons/ami-rust/actions/runs/38946497526)
passed in two independent build contexts on each host. The qualified macOS
Cargo binary is 39,348,200 bytes, SHA-256
`4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d`;
the Linux Cargo identity remains `938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db`.
These later results supersede the unresolved macOS identity in the first
attempt above, without changing its recorded failure.

The [complete SDK proposal run 38954096259](https://github.com/metaneutrons/ami-rust/actions/runs/38954096259)
at source `8e98f230483af5e4785e233c74a68099b97fe2ca` produced the Linux
candidate successfully. Its independent readback verified the two-root maps,
all 104 canonical outputs, the five retained native files and the reproduced
SDK archive. This is host-local build evidence, without guest or release
acceptance. The macOS producer reproduced its qualified Cargo, then failed
while deriving the portable C-SDK: the aggregate command reached its 1,200-second
ceiling (1,222.565 seconds including termination). Failure cleanup succeeded,
and the retained macOS artifact contains metadata only. Signing and final
consumer qualification did not run.

The SDK supervisor recursively measures the whole managed work tree. Keeping
completed Cargo source, vendor, bootstrap and build trees through hundreds of
short header-generation commands adds repeated filesystem scans. The recorded
elapsed times include this monitoring work; they do not isolate its exact
share. A separate complete macOS C-SDK component run took 564.213 seconds,
so the hosted timeout does not establish a compiler incompatibility.

The correction stages and verifies the exact Cargo component before C-SDK
derivation, then retires an explicit set of completed Cargo scratch trees.
It retains the staged component, raw producer report, logs, records, downloaded
input archives and overlay receipt. Retained bytes are rechecked; linked or
out-of-scope cleanup roots are refused before deletion. Resource sampling,
previously observed peaks and every resource ceiling remain in force. Pinned
originals, compiler inputs, derived C-SDK identities and the qualified AROS
baseline are unchanged. Fresh complete production on both hosts remains
required before this correction supplies SDK qualification evidence.
