# Public source CI and SDK provenance

This repository has a clean public source history. Original private development
history and raw guest qualification records remain preserved separately. The
normative release plan identifies inherited evidence and its acceptance limits.

The ordinary source CI runs synthetic regression fixtures on Ubuntu x86-64 and
macOS Apple Silicon. It has read-only repository access, no protected environment
and no OIDC signing permission. Fixture keys and signatures do not identify the
publisher or establish SDK release acceptance.

The manual protected Cargo prerequisite workflow builds the pinned host tool
from source and uploads bounded receipts. Its producer identity is separate from
the SDK's. The [protected SDK workflow](hosted-sdk-producer.md) regenerates its
C-SDK, builds native SDK artifacts and checks actual provenance/signatures and
clean consumers. Only authenticated candidate jobs have the necessary OIDC
permissions. Every manual producer requires protected main and the release
environment. No SDK publication is performed by these qualification workflows.

The C-SDK prerequisites, complete corresponding source and Rust vendor archive
are normal repository inputs. Rust/compiler/collector artifacts retain their
independent pinned public producer identities. No private companion repository,
self-hosted runner or operator-owned build path is required. Original historical
build paths in frozen recipes are counterproof data only, never live source roots.
