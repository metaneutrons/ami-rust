# Native installation and externally pinned removal

The development Rust frontends share these explicit-bundle operations:

```text
ami-rust install --bundle BUNDLE --policy EXTERNAL_POLICY --prefix ABSOLUTE_FRESH_PREFIX [--receipt-pin ABSOLUTE_FRESH_FILE]
ami-rust uninstall --prefix ABSOLUTE_PREFIX --receipt-sha256 SHA256
```

`cargo ami` accepts the identical arguments and shares the implementation.
Bundle/policy paths are resolved before admission. Mutation destinations remain
normalized absolute paths with protected, existing user-owned parents. Existing
prefixes/pins, unsafe aliases and overlap with the bundle refuse without
replacement. No ambient package or historical executable driver is selected.

Installation authenticates the exact retained release-v2 bundle, then verifies
and retains the complete SDK-v2 payload. One cooperative SIGTERM guard spans
verification, extraction, staged publication and external pin creation. Every
SDK file uses the archive reader's normalized 0644/0755 mode. All outer assets
are retained as data, except the exact signed current-host launcher, which is
admitted as a native host executable and installed with mode 0755. The other
host's launcher is retained with mode 0644. Header admission does not prove
runtime behavior or compiler correctness.

## Receipt and publication

The new `ami-rust-install-receipt-v3` binds the publisher report and external
policy digest, raw release and SDK manifest identities, complete installed file
inventory, current host and static CLI/core identity. Direct serialization
preserves workflow-counter decimal lexemes. The receipt is excluded from its
own inventory and is independently pinned by the returned SHA-256; the
transaction engine validates its real file separately.

The exact SDK/archive files, all outer assets, raw release manifest and retained
authenticated Cosign bundle are written to an exclusively created staging tree.
The complete staged inventory and parent identity are checked before exclusive
publication. The native publication helper is crate-private; callers of the
public native installer cannot substitute a self-authored receipt for publisher
authentication. The generic historical transaction primitive retains its
separate already-authenticated-input contract.

Successful installation emits one LF-terminated `ami-rust-install-result-v1`
JSON object with status `installed`, prefix, receipt digest and optional external
pin, and exits 0. A failure before publication exits 2 and reports any retained
staging recovery location. A failure after publication emits status
`installed_with_error`, the surviving installation identity and reason, and
exits 1. It never deletes the published installation to disguise the error.
Only a successfully written external pin is reported as present.

UTF-8 output paths are JSON strings. A valid non-UTF-8 Unix path is represented
exactly as `{ "encoding": "unix-path-bytes-v1", "bytes": [47, ...] }` instead.
This applies to installation/removal prefixes and receipt-pin paths. These are
new native result schemas; a lossy display string is not an actionable path.
No extra path refusal is introduced to hide an encoding limitation.

## Removal authority and preserved data

Removal first checks the explicit external receipt digest, then the closed
receipt schema, bound release manifest, SDK/archive identity, selected native
host launcher, normalized modes and exact receipt-to-release inventory. The
transaction engine rechecks real ownership, files and complete directory
membership before moving the prefix to an owned tombstone. Missing, changed,
linked or additional files refuse before deletion; unrelated installations,
global Rust configuration and external receipt pins remain intact. Partial
removal failures report the surviving owned recovery location and never restore
a partially deleted tree under its original name.

Historical v1/v2 receipts are removal/inspection inputs only. Removing an
externally pinned historical installation does not authorize its Python driver
or produce native installation capability. Removal launches no verifier,
interpreter or archive driver.

Successful removal emits `ami-rust-uninstall-result-v1`, status `uninstalled`,
the prefix and receipt digest, and exits 0. Refusals exit 2. The removed prefix
is not used as a current working directory during mutation.

## Container profiles

The prospective native release-v2 publisher profile allows 64 MiB total bundle
bytes, including proofs, and 512 physical files. Its manifest admits at most
512 asset rows and 16 MiB per asset. SDK archive limits remain 16 MiB compressed
and decoded, with the existing XZ decoder memory bound. Native receipt-v3
inventories and the installed tree, including the receipt, have a 128 MiB
aggregate profile. Legacy release-v1 inspection remains 32 MiB and historical
v1/v2 installation/removal remains 64 MiB. An unknown or malformed receipt does
not select the larger removal profile.

The immutable released asset inventory already totals 30,612,374 bytes. An
initial optimized macOS native CLI measured 1,502,616 bytes; the new bundle
needs both host binaries plus provenance. The Linux binary had not yet been
measured when selecting this prospective profile. These measurements show
that retaining the old 32 MiB aggregate would leave little room; they do not
prove an exact final candidate size. Preserve source/licence obligations rather
than deleting them to fit the historical container. The 128 MiB installed
profile accommodates retained assets, decoded SDK, raw manifest, signature and
receipt. Both profiles remain bounded, with exact-limit and over-limit controls.

These are new container profiles for new native format identities, not changes
to immutable historical evidence, AROS application allocation limits or the
qualified 512 MiB guest. Host resource and verifier timeout/capture contracts
remain unchanged. Final signed candidate sizes and both-host behavior still
require measurement before release acceptance.

## Portable host binary build

`tools/build-native-cli.sh` builds the locked host workspace with explicit
pinned Cargo/rustc/rustdoc and an existing registry cache. Compiler prefix maps
replace checkout and registry paths, including paths with spaces. The release
profile strips debug-origin records while preserving ordinary symbol names;
this prevents the macOS linker from retaining absolute prebuilt standard-library
object paths. On macOS the explicit build process also receives the pinned
sysroot's `lib` directory as its library search path: the pinned `rust-objcopy`
otherwise cannot load its own `libLLVM.dylib`. The setting is local to that build
invocation and does not append ambient library search paths. No target compiler,
`.rlib` metadata or completed distribution artifact is patched. The build checks that its checkout, registry and sysroot
prefixes are absent, and an isolated corrupted-copy control must fail.

## Evidence boundary

Synthetic Rust tests exercise actual staged publication, external pin creation,
exact pinned removal and preservation of edited/additional user data. The
transaction matrix additionally covers genuine SIGTERM boundaries, exclusive
renames and post-publication pin failure. Frontend tests execute both names and
real Cargo for parsing/refusal parity and absence of mutation on malformed trust
inputs. Synthetic receipt/header fixtures do not authenticate a publisher.

Exact signed native-v2 installation/removal on both supported hosts, full
no-Python observation, preparation, retained lifecycle and native build/runtime
qualification remain required for RC1. None of those gates is replaced by
these tests, and no SDK release is published by this implementation.
