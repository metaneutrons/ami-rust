# Cargo storage patch

`cargo-storage.patch` separates Cargo's mutable cache from configuration and
credential discovery. Apply it after `host/cargo-repro/cargo-metadata.patch` to
upstream Cargo commit `3efb1f477e99b42974b982d939fd100303cdf7db`.
`source.json` records the exact source and patch identities.

`AMI_RUST_CARGO_STORAGE_ROOT` selects an existing canonical cache directory on
supported Unix hosts. The directory must be absolute, owned by the effective
user, and not writable by group or others. The selector does not create the
directory. Registry and Git data, locks, the global-cache database, cache
templates, and analysis logs follow the selected root; configuration,
credentials, and executable lookup retain normal Cargo semantics.

The selector is checked before storage work and after configuration merging. A
conflicting configured value refuses. With the selector absent, stock Cargo
behaviour is preserved.

The internal Rust qualification tasks exercise storage routing, lifecycle,
registry, nested invocation, concurrent GC, and Git-helper behaviour against
the original and patched Cargo binaries. The patch is an implementation input,
not a public interface or a general sandbox.
