# Cargo input guard patch

`cargo-guard.patch` adds an internal, opt-in callback boundary to the pinned
Cargo source. Apply these patches in order to upstream commit
`3efb1f477e99b42974b982d939fd100303cdf7db`:

1. `host/cargo-repro/cargo-metadata.patch`
2. `host/cargo-storage/cargo-storage.patch`
3. `host/cargo-guard/cargo-guard.patch`

`source.json` binds the upstream revision, patch digests, changed files, and
resulting source identity. Preserve upstream licences and notices.

The private `AMI_RUST_CARGO_GUARD` and `AMI_RUST_CARGO_OVERLAY` selectors must
be present together. Cargo sends bounded resolved configuration and command
records to the owned callback before relevant cache or build work. Refusal
stops the command; approval merges the self-contained overlay once. With the
selectors absent, stock Cargo behaviour is preserved.

This hook supplies observable inputs to the SDK's internal qualification
boundary. It does not authenticate publishers, select an SDK, compile target C,
or replace Cargo's parser. Records are bounded, callback execution times out,
and callback output is discarded. The selected component is built and tested
through the Rust maintainer tooling and protected qualification workflows.
