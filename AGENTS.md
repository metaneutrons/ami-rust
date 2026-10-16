# Repository working memory

## Portability patches

Owner decision, 2026-10-16: small, maintained patches are permitted when needed
to keep ami-rust packages portable and buildable on every supported platform.
Routine patches within the authorised work do not require another permission
request merely because they modify an upstream input in an owned checkout.

- Keep patches narrow, versioned and suitable for upstream submission. Record
  the reason, original source revision, patch digest and resulting component
  identity. Preserve original notices and licence terms.
- Patch source, generators and build recipes. Generate relative provenance
  comments and relocatable `pkg-config` files; use compiler prefix mapping for
  build-path-dependent diagnostics. Preserve compiler metadata and binary
  archive integrity instead of rewriting finished binaries to conceal paths.
- Apply patches in ami-rust-owned checkouts or staging trees. Preserve pinned
  originals and the qualified boot/ABI baseline; keep protected AROS-NX and
  aros-tools checkouts unchanged. Give derived SDK inputs their own identities.
- Verify affected behaviour, relocation and builds on all supported hosts.
  The initial supported hosts are macOS Apple Silicon and Linux x86-64; the
  initial target is native PC x86-64 AROS ABI-v1. Broader platform support
  requires its own evidence.
- Requalify affected release criteria before shipping changed inputs. Retain
  failed results and the original evidence. Remove downstream patches when an
  upstream fix has passed compatibility qualification.

These patches serve the independent ami-rust SDK release. nxpk remains outside
the current scope.
