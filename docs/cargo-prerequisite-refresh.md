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
