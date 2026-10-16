# Hosted Cargo prerequisite refresh

Changing `host/build.py` changes the producer helper identity recorded in
`release/ci-bootstrap-inputs.json` and in each Cargo producer report. Until the
protected producer runs against those new inputs, the checked-in reports are
historical receipts and cannot pass the strict SDK preflight.

During that interval, `release/ci-cargo-producers-pending.json` records a
versioned source state. It binds the current inputs, resource policy and host
supervisor, along with the raw hashes and prior input/helper identities of both
reports. The source fixture verifies those bindings, confirms that both old
reports are stale, and confirms that the real preflight still refuses them.
The marker is test-only evidence of a pending refresh. It does not qualify a
Cargo build or authorize SDK production.

Merge the helper and pin change with the pending marker after its source CI
passes. Then dispatch the protected `Hosted Cargo producer` workflow on `main`
for both supported hosts. Commit each complete, unmodified `producer.json`
report from that run and refresh the SBOM references to the raw report and
Cargo artifact hashes. Remove the pending marker in that receipt update. The
ordinary strict-preflight test then resumes and both receipts must validate
against the current inputs before normal SDK qualification proceeds.

## Refresh outcome (2026-10-16)

The protected [Hosted Cargo producer run](https://github.com/metaneutrons/ami-rust/actions/runs/38914054466) completed on both hosts and passed strict canonical producer validation against the tracked inputs. The complete producer reports were copied byte for byte. Linux report SHA-256 9a771203242c7afb26cc3719efb27477a78935465ad2e4a62c598816f1a5daa9; canonical producer SHA-256 5f3226c43feac152b0b505178c8426769c429a3eacf09c3b6b6f91ad9f9796c6; Cargo artifact SHA-256 938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db (48,110,632 bytes). macOS report SHA-256 024dd4c2276e6536876934617b50a4792fd7d0ce653a2430d23cc4f1b098ed85; canonical producer SHA-256 570b6f738636683f9ee74efc08f5db196c558933e0708344a6fe07ab536061d0; Cargo artifact SHA-256 7f15bb7b7c9fe143315cd23b5c32de5ebd5a0f1c8c6b75a1e51990bef6c5bfbc (39,348,888 bytes). The pending marker was removed after the report and SBOM receipt refresh. The run did not execute QEMU or accept the SDK/R1 qualification.
