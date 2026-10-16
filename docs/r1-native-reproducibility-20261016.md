# Native reference reproducibility follow-up — 2026-10-16

The [second protected reference proposal](https://github.com/metaneutrons/ami-rust/actions/runs/38901681227),
at source `aceebfbe61463817a51ad9bae39db50f29e9615b`, failed on Linux
with `cold-root native outputs differ for dependencies`. The Linux job completed
at 13:08:20 UTC. Its fresh Cargo and portable C-SDK prerequisite receipts are
retained, but they do not establish SDK or R1 acceptance. Cancellation was
requested for the remaining Mac job after the concrete Linux failure.

The producer compares every canonical output as well as the native executable.
The error does not identify which member differed. The original failure path
retained only short SDK failure metadata and prerequisite receipts, then retired
working trees and partial payloads. Therefore the exact differing members and
bytes from this attempt are unavailable; no cause or native-byte difference is
inferred from the message alone. The Linux artifact ZIP was retained and checked
against its provider digest:
`ab66e15c393f0ff11f82544581380206e09aa25361fd6cf247dad61c9289fbfa`.

## Diagnostic preservation

The next producer keeps the first cold root's canonical files in managed scratch
until comparison with the second root. Aggregate admission includes checkout,
output and pinned Python bytes before the snapshot is copied. Matching snapshots
are retired after comparison.

On a mismatch, both complete maps and the differing-member list are retained
before the same strict comparison fails. Exact original bytes from each root
are retained subject to both raw-evidence and total artifact capacity; every
omission has an explicit per-member reason.
Failure cleanup preserves validated diagnostics and removes partial release
payloads before retiring scratch. The existing 32 MiB host artifact limit still
applies; raw diagnostic bytes have 24 MiB available before receipt/output
headroom. Reaching either the 24 MiB raw-evidence bound or the remaining
32 MiB artifact capacity produces an explicit omission record. Missing bytes never become a successful comparison.
Linked or altered diagnostic files are rejected. This is hosted evidence
retention, not an SDK application-memory limit.

Host fixtures cover identical roots, a changed `.rlib`, raw-byte omissions,
aggregate capacity admission, diagnostic survival through the actual workflow
cleanup, and rejection of linked files. They qualify the adapter only. New
actual two-host byte comparison, metadata review and native runtime/memory
qualification remain required before release; the boot/ABI baseline is unchanged.


## Local host-path isolation experiment

A separate macOS diagnostic ran two cold dependency builds with all component
roots relocated. With the original configuration, exactly three of the 35
canonical files differed: the `curve25519-dalek`, `ed25519-dalek` and `serde`
archives. The actual host build-script/proc-macro compiler invocations lacked
the prefix mappings already supplied to the target compiler.

Two further fresh builds applied those same five prefix mappings through
Cargo's `-Zhost-config`, `-Ztarget-applies-to-host`,
`target-applies-to-host=false` and the selected `[host.<triple>].rustflags`.
All 35 canonical files then matched byte for byte between the two layouts.
The captured commands showed only the five remaps on all ten host helper
compilations; the twenty target compilations retained their five code-generation
options and five remaps. No finished archive or compiler metadata was edited.

The new native executable is identical between layouts, SHA-256
`e9282cb51537e141f22c3e7d22059e64292e79679865d63f9499a63ad0342bb9`.
It differs from the original diagnostic executable,
`0afdb04f02910265ba32446bf2eaba815988265e56b2ea5f4e714852538ff6af`.
The experiment used development Cargo
`e463b22d514cf3cbe9b36dc874869331c33a1cb53187225db07d63bfeb394e54`
and the original qualified C-SDK. It does not establish the cause of the
unavailable Linux bytes, final hosted-Cargo reproducibility or native acceptance.
The production fix therefore requires fresh protected prerequisite reports,
complete two-host SDK builds and the affected runtime/memory qualification.
See [Cargo prerequisite refresh](cargo-prerequisite-refresh.md).
