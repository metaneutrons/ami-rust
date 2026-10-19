# Native package format and root discovery

This RC1 contract addendum defines native package inputs, inventory and proof
index records. The [machine-readable contract](native-package-contract-v2.json)
owns their exact fields and profiles. It extends the frozen RC0 recipe with
the native payload shape needed to replace `cli.py`, `worker.py` and the outer
Python launcher; no RC1–RC5 acceptance condition is removed.

`ami-rust-package-inputs-v2` preserves the SDK's source/tree, producer run,
manifest, transport, six outer assets and four proof-subject pins. It adds the
independent CLI version, selected package host, two native frontend rows and
static core digest. Both frontends contain the same binary bytes and core.
SDK source identity and CLI version remain separate: a tooling update is not
permission to rewrite an existing SDK release.

The native inventory has explicit CLI/SDK/package/host identity and exact
path/length/digest/mode rows. It excludes its own `inventory.json` to avoid a
self-hash cycle; the reader retains those original bytes, measures them and
checks their actual file separately. The versioned proof index binds the four
subjects to the complete pinned proof-identity sets. A shared proof file has
one identity; duplicate/case aliases refuse. These records establish package
consistency. They do not authenticate the publisher, accept licenses or mark
an SDK state ready.

## Owned payload

```text
PACKAGE_ROOT/
  bin/ami-rust
  bin/cargo-ami
  pins.json
  inventory.json
  proofs.json
  assets/...
  proofs/...
  LICENSE-MIT
  LICENSE-APACHE
  THIRD-PARTY-NOTICES.md
  licenses/...
  README.md                 (optional)
```

Only the two frontend files are executable, mode 0755; data is mode 0644.
License and notice text must be nonempty. The full dependency/license audit
remains a release gate; a placeholder test notice cannot satisfy it. Inputs
outside these roles, including active Python helpers, refuse even if listed.
Inner payload links and special files refuse. Empty extra real directories
preserve the historical package verifier's decision within the host traversal
bound. This differs from the separate publisher bundle's exact-directory rule.

The package reader validates both inventories and actual regular-file bytes,
modes and payload ownership. It keeps a descriptor for the root and original
control bytes. Later copy/read operations accept only listed files and recheck
their contents before returning immutable bytes. The reader does not freeze a
live package installation against its owner or administrator, and distribution
authenticity remains a separate prerequisite. No cryptographic claim follows
from editing both a payload and its self-contained inventory.

Native header admission rejects scripts and the wrong host architecture:
Linux ELF64 little-endian x86-64 executable/PIE with a nonzero entrypoint in
a bounded executable load range, or macOS arm64 Mach-O executable. Ordinary
shared objects without that entry/load structure refuse.
It is a header check, not an OS-loader test or a proof of no embedded interpreter.
Actual execution and runtime closure still need their own observed tests.

## Relocation and frontend names

The owned executable always resides in `PACKAGE_ROOT/bin`. Relative records
therefore remain portable across these routes:

| Route | Example owned root |
| --- | --- |
| APT | `PREFIX/libexec/ami-rust/PACKAGE_VERSION` |
| Homebrew | `CELLAR/FORMULA/VERSION/libexec/ami-rust/PACKAGE_VERSION` |
| Retained state | `STATE/retained/libexec/ami-rust/PACKAGE_VERSION` |

Public entrypoints outside that root may be links to its two binaries. Root
discovery uses the actual executable path obtained from the operating system,
resolves that entrypoint, then checks the canonical owned payload. It never
searches PATH, the current directory, an ambient installation or a legacy
Python package for fallback metadata. Resolving the actual image is separate
from reading argv[0]: Cargo's `cargo-ami` dispatch name must survive an alias.

This lookup serves package-managed and retained adapter operations. Direct
explicit-bundle/policy or SDK-lock operations have their own validated inputs;
they must not silently acquire an ambient package dependency. A bare binary
cannot satisfy `verify-package`. The current development help/version behavior
is unchanged, and no new consumer command is activated by this delivery.

## Profiles and qualification

The metadata profile is 2 MiB. Assets retain the historical 128 MiB per file /
256 MiB total profile; each frontend may use that same 128 MiB file profile.
Proof files allow 16 MiB each / 64 MiB per distinct path. Counting distinct
paths rather than only unique digests also accounts for repeated physical
copies. The complete package, including its self inventory, is bounded at
512 MiB. Existing packaging.2 assets are about 27 MiB; prerequisites such as
compiler/C-SDK trees remain separate private-state acquisitions. The 16,384
entry traversal bound includes empty directories. These are host container/work
profiles, never limits on AROS applications or their native output.

Pure record parsing, filesystem consistency, native header admission and actual
host/CLI execution are separate claims. Both-host fixtures, paired historical
refusal evidence where applicable, native relocation/retention and the integrated
resource/no-Python observer remain required before accepting consumer paths.
Immutable v1 packages, releases and evidence are preserved; they are never a
native execution fallback.
