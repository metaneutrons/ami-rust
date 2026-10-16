# Hosted Cargo context diagnostic

This maintainer-only workflow investigates Cargo build-context differences. It
does not install user tooling, select a new reference hash, qualify an SDK, or
publish a release.

Protected SDK proposal [38922417085](https://github.com/metaneutrons/ami-rust/actions/runs/38922417085)
completed all five variants in two fresh Linux roots. Its macOS job stopped
before the SDK builds: the freshly built Cargo was 39,348,872 bytes with SHA-256
`41c55876551dd15a41f183b70bc481265de211c886fca9e6b77b4b10ca3e23e8`,
whereas the frozen Cargo-only receipt recorded 39,348,888 bytes with SHA-256
`7f15bb7b7c9fe143315cd23b5c32de5ebd5a0f1c8c6b75a1e51990bef6c5bfbc`.
Both reported the same Cargo version. The failing run did not preserve the Mac
binary, so those records cannot establish the binary-level cause.

The manually dispatched `cargo-context-probe.yml` runs only on protected main in
the designated repository. One admission job reserves both exports before the
two standard hosted jobs start. Each host calls the unchanged pinned Cargo
producer twice, sequentially, in `ami-rust-cargo-work` and `ami-rust-sdk-work`
directly beneath the runner's temporary directory. Inputs and resource policy
remain unchanged. The exact compiler, linker and SDK identity commands are
retained with their bounded output and sanitized environment policy.

Before retiring each completed work tree, the driver preserves its original
Cargo binary in a verified compressed archive, its raw producer receipt, and
its command/build diagnostics. Different binary bytes produce a failing job
after both snapshots have been preserved. A failed second build keeps the first
snapshot; recorded cleanup retires only the owned remaining work roots.

The final export adds the existing hash-pinned Cargo corresponding-source
capsule, source inventory and accompanying licence texts. It retires the fixed
Python runtime, inventories the uploaded bytes, and limits the complete export
to 32 MiB per host within the existing 512 MiB artifact pool. A matching result
is explicitly diagnostic only. Any source/build-recipe fix still needs review,
fresh two-host producer receipts, complete SDK qualification and the native
runtime/memory matrix before R1 acceptance.
