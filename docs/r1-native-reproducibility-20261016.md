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

On a mismatch, both complete maps, the differing-member list and exact original
bytes from both roots are retained before the same strict comparison fails.
Failure cleanup preserves validated diagnostics and removes partial release
payloads before retiring scratch. The existing 32 MiB host artifact limit still
applies; raw diagnostic bytes have 24 MiB available before receipt/output
headroom, with explicit per-member omission reasons if the actual artifact
cannot hold every byte. Missing bytes never become a successful comparison.
Linked or altered diagnostic files are rejected. This is hosted evidence
retention, not an SDK application-memory limit.

Host fixtures cover identical roots, a changed `.rlib`, raw-byte omissions,
aggregate capacity admission, diagnostic survival through the actual workflow
cleanup, and rejection of linked files. They qualify the adapter only. New
actual two-host byte comparison, metadata review and native runtime/memory
qualification remain required before release; the boot/ABI baseline is unchanged.
