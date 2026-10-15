# Protected hosted Cargo prerequisite producer

The manual `Hosted Cargo producer` workflow runs on protected `main` in the
`release` environment on standard `macos-26` ARM64 and `ubuntu-24.04` x86-64
runners. It builds the pinned host Cargo prerequisite from source. It does not
produce, distribute or qualify an AROS SDK. Only bounded producer and cleanup
JSON receipts are uploaded; no Cargo binary or SDK archive is uploaded.

`release/ci-bootstrap-inputs.json` is the normative public input list. Official
Rust 1.98.1 compiler, standard library and Cargo archives have exact URLs, sizes
and SHA-256 digests; compiler and bootstrap Cargo commits are checked separately.
Cargo source, lockfile, two-file metadata patch and OpenSSL overlay are pinned.
The selected vendor tree is reconstructed from the locked registry checksums.
No additional input repository, operator path or machine credential is needed.

## Prospective resource contract

`release/ci-resources.json` defines this new hosted phase: at least 6 GiB physical
RAM and 24 GiB free disk; at most two build jobs, 4 GiB observed aggregate process
RSS, 20 minutes per build, 12 GiB managed workspace and 16 MiB logs. Existing
sealed campaigns keep their original limits and results. Guest, ABI, application
memory and code-size limits are unchanged. Resource admission is not a build
qualification result.

The protected producer concurrency group admits one two-host workflow at a
time. Each job includes its checkout, archives, bootstrap, sources, dependency
copies, caches, targets, logs and managed HOME/temp paths in workspace accounting.
The managed work tree must be removed before metadata upload. Local checkout
plus metadata is bounded to 32 MiB per job; 64 MiB per job is conservatively
reserved for checkout, metadata and provider logs. Uploaded metadata also counts
against a separate 512 MiB retained artifact pool checked before production.
Any future SDK producer must use the same concurrency and artifact-pool gates.

Run failures and cleanup failures remain failures. A successful helper receipt
only proves the host prerequisite build and its measured bounds. SDK packaging,
native-output equivalence, authenticated distribution, full SDK licence/source
closure and final independent R1 acceptance remain separate gates.

## Verification

PR CI runs the legacy installer fixtures and isolated positive/counter-probes
for capacity admission, verified downloads, safe extraction, process-group
termination, output schema validation and aggregate artifact retention. Real
archive installation, vendoring, builds and observed resource use are checked
by the protected manual workflow. Fixture tests are not a substitute for that
execution.
