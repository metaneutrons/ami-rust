# Hosted Cargo prerequisite refresh

Changing `host/build.py` or the Cargo build recipe changes helper identities recorded in
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
passes. Then dispatch a protected producer workflow on `main` for both supported
hosts. The paired Cargo context workflow invokes the same pinned producer twice
in distinct work roots and additionally preserves the raw executables. For that
route, require both complete report pairs to pass canonical validation, full raw
same-host byte equality and private-path checks, followed by independent review.
Commit each complete, unmodified selected `producer.json` report and refresh the
SBOM references to the raw report and
Cargo artifact hashes. Remove the pending marker in that receipt update. The
ordinary strict-preflight test then resumes and both receipts must validate
against the current inputs before normal SDK qualification proceeds.

## Earlier refresh (2026-10-16; superseded)

The protected [Hosted Cargo producer run](https://github.com/metaneutrons/ami-rust/actions/runs/38914054466) completed on both hosts and passed strict canonical producer validation against the tracked inputs. The complete producer reports were copied byte for byte. Linux report SHA-256 9a771203242c7afb26cc3719efb27477a78935465ad2e4a62c598816f1a5daa9; canonical producer SHA-256 5f3226c43feac152b0b505178c8426769c429a3eacf09c3b6b6f91ad9f9796c6; Cargo artifact SHA-256 938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db (48,110,632 bytes). macOS report SHA-256 024dd4c2276e6536876934617b50a4792fd7d0ce653a2430d23cc4f1b098ed85; canonical producer SHA-256 570b6f738636683f9ee74efc08f5db196c558933e0708344a6fe07ab536061d0; Cargo artifact SHA-256 7f15bb7b7c9fe143315cd23b5c32de5ebd5a0f1c8c6b75a1e51990bef6c5bfbc (39,348,888 bytes). The pending marker was removed after the report and SBOM receipt refresh. The run did not execute QEMU or accept the SDK/R1 qualification.

## Current paired qualification (2026-10-16)

[Protected run 38946497526](https://github.com/metaneutrons/ami-rust/actions/runs/38946497526)
completed four fresh producer builds on source
`8fb15e1efbf648664fb1e31d685d24849ce4e8a2`: two work roots on each supported host.
An independent readback verified the provider archives, all four exact producer
reports, identical complete raw bytes within each host pair, canonical receipt
equality and absence of private host/build-root markers. The selected reports
are the unmodified `cargo`-work phase; each is corroborated by the `sdk`-work
phase. That phase name describes a work-root context, not a completed SDK build.

- `linux-x86_64`: Cargo 48,110,632 bytes, SHA-256 `938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db`; selected raw report SHA-256 `83e3ceaa34d98de43d42ef4fb8ff1ec3483325e1304a72b144ce734c978df25c`; canonical producer SHA-256 `78e6232c3e83e2fc637b1b7f218e937b8593331d7d9ccece093852f0fefc916d`.
- `macos-aarch64`: Cargo 39,348,200 bytes, SHA-256 `4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d`; selected raw report SHA-256 `8ab4c199b8bbde77b6d84c2ac27e1a68fa223234c12bd05659d58c224f8e0582`; canonical producer SHA-256 `f8c4f5ea8bf1a9f677665ce4a88e85ea473627eb22fbe3b85f149f4b317ab10f`.

The current input identity is
`5c3557a2696457d76562f8883efa2c7d2c4cfc583f4f5814a722907a1f639f81`.
The resource policy, Rust/Cargo source and compiler pins, and qualified AROS
boot/ABI baseline are unchanged. The protected finalizer completed with zero
reported work/runtime residual bytes; no separate cleanup receipt was exported.
The pending marker is retired with this report update. Complete SDK builds,
AROS runtime/memory qualification and release-trust gates remain open.
