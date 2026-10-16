# Hosted native reference proposal, 2026-10-16

Run [38896047098](https://github.com/metaneutrons/ami-rust/actions/runs/38896047098)
used source `42459cc60d95ef4d22701dcaf51d7ec69f64f0a8` on standard GitHub-hosted
macOS and Linux runners. It failed and provides no accepted native reference,
SDK release, or R1 decision. The remaining macOS producer was cancelled after
the shared inventory defect was established. Both jobs retained metadata and
reported zero remaining managed work and Python runtime bytes.

Both newly built Cargo binaries match the frozen host identities:

| Host | Bytes | SHA-256 |
| --- | ---: | --- |
| macOS ARM64 | 39348872 | `41c55876551dd15a41f183b70bc481265de211c886fca9e6b77b4b10ca3e23e8` |
| Linux x86-64 | 48110632 | `938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db` |

Linux also completed the protected portable C-SDK derivation. Its archive is
5619304 bytes with SHA-256
`942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b`, matching
the pinned derived component. The boot/ABI baseline was unchanged. A completed
protected macOS C-SDK derivation is still required; cancellation metadata does
not establish its result.

The first Linux native build reached its artifact check. Frozen `host/build.py`
writes `AMIRUST.map`, `AMIRUST.unstripped`, and `AMIRUST.stripped` alongside the
canonical target artifacts. These are construction byproducts; the accepted
104-output comparison deliberately covers the final executable and canonical
objects, archives, and target libraries. The new producer incorrectly required
the whole directory to equal the canonical map, rejecting those three regular
byproducts. The original check failed before completing both cold roots.

The correction requires exactly the canonical files plus those three named
regular, nonlinked byproducts. It records their sizes and hashes separately,
rejects unknown, missing, or linked files, and retains full canonical byte/hash
and reference matching. It does not change `host/build.py`, the native code,
the 94-file SDK source inventory, accepted reference maps, or compiler metadata.

A fresh two-host proposal and actual guest qualification are required after
this source fix. The failed run's clock and results remain unchanged. No
native guest or SDK authentication/publication was performed by this attempt.
