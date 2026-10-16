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

## Retained comparison and correction

[Diagnostic run 38933076655](https://github.com/metaneutrons/ami-rust/actions/runs/38933076655)
preserved both original binaries on each host. Linux produced the same frozen
Cargo bytes in both work roots. On macOS the two roots reproduced exactly the
previous prerequisite and failed SDK identities listed above. All four raw
producer reports passed the pinned input, helper and resource validation.

The Apple linker generated twelve `N_OSO` debug-map entries containing absolute
paths to the installed bootstrap Rust archives. These entries are outside the
compiler's source-path remapping. An independent inspection found identical
contents and sizes for all eighteen Mach-O sections; every symbol name, type,
section, descriptor and value agreed after mapping only the twelve exact
bootstrap prefixes for diagnostic comparison. The original full binaries remain
unequal and are not accepted through this comparison. The [compiler documentation](https://doc.rust-lang.org/nightly/rustc/remap-source-paths.html#paths-generated-by-linkers)
describes this separate linker limitation. The Darwin prerequisite build now
passes `-C link-arg=-Wl,-oso_prefix,<bootstrap>/` so the linker generates relative
`lib/rustlib/...` entries. Linux flags and the existing compiler remaps are
unchanged. Finished binaries and Rust metadata are never rewritten.

The macOS driver also failed its separate 256 MiB self-memory guard after both
snapshots were retained. Its measured 296,517,632-byte peak covers the Python
driver's lifetime, not compression alone. The driver now records that measurement
as `driver_peak_rss_bytes` and uses the selected producer resource policy's
`build.rss_bytes` limit, unchanged at 4 GiB. Both phases must report the same
selected limit. The archive, byte-comparison, work-space and export checks remain
in force. The historical workflow failure is retained; this source correction
requires fresh protected builds before any reference replacement.

## Fresh paired result

[Run 38946497526](https://github.com/metaneutrons/ami-rust/actions/runs/38946497526)
completed successfully on both hosts after the correction. Independent readback
confirmed complete raw same-host byte equality for both root contexts and no
private host/build-root markers. macOS now produces 39,348,200-byte Cargo
binaries with SHA-256
`4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d`;
Linux retains its previous raw executable bytes. Both report pairs pass strict
canonical input/helper/resource validation. The [prerequisite refresh](cargo-prerequisite-refresh.md)
records selected report identities. This closes the Cargo context blocker only;
it does not qualify SDK, AROS runtime/memory or release output.
