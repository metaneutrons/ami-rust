# Consumer command enforcement

This is a maintainer qualification tool, excluded from the installed SDK and
public CLI. It runs an actual supported consumer command under an inherited
execution policy. Internal test coordination remains separate from the consumer
process tree. The full Python-retirement acceptance criteria remain in
[`docs/rust-cli-cargo-migration-plan.md`](../../docs/rust-cli-cargo-migration-plan.md).

Build with the selected pinned host Rust inputs and an isolated environment:

```text
cargo build --manifest-path tools/consumer-enforcement-adapter/Cargo.toml --locked --offline --release
consumer-enforcement-adapter --policy POLICY --report-dir NEW_EVIDENCE_DIRECTORY --run -- /absolute/consumer-command ARG...
```

Policy paths identify the actual selected test inputs and owned output roots.
The child receives only declared environment values. Keep the report directory
disjoint from every child-writable tree; the adapter rejects overlap in either
direction. Captures retain at most 1 MiB per stream while draining the remainder.
Evidence failures return 125 and preserve the original child status where a
report can be written. The existing outer Supervisor must enforce deadlines,
process cleanup and resource limits; this tool cannot attest to its caller.

On macOS the backend uses `/usr/bin/sandbox-exec`, deny-default execution,
literal executable paths, and only explicitly declared private derived-output
subtrees. It grants process-info operations for native resource sampling.
Policy read-file entries
include required ancestor and home-directory metadata. Source/SDK/component
reads and owned writes are explicitly selected. Deferred exact executable paths
must be inside a declared writable root; transient generated tools additionally
require reviewed source/build closure evidence. `read-library PATH SHA256`
grants a separate, hash-checked library-mapping allowance: macOS permits file
data reads and `file-map-executable` for that canonical regular file, without
granting `process-exec`; Linux permits `READ_FILE` only. The adapter verifies
the declared SHA-256 before and after the command. A library mapping cannot
overlap an explicitly denied library, an executable allowance, or a writable
tree.

For output roots that do not exist before a fresh command, the policy directive
is `exec-derived-tree ROLE EXISTING_EMPTY_PRIVATE_PARENT SOURCE_CLOSURE_SHA256`
and accepts only `consumer-state-parent` or `consumer-build-parent`. Its parent must
already be empty, canonical, owned by the current user, mode 0700, and a strict
descendant of a declared `work`, `state`, or `target` write tree. It permits
execution only below that parent. The source-closure digest is recorded as
declared policy data and is not verified by the adapter; the caller must bind
the reviewed compiler, vendor/build-script inputs, and source recipe. This
does not contain malicious build sources or detect every runtime.

Use `read-directory PATH` for an existing canonical directory when only its
directory entry is needed. macOS grants `file-read*` on that literal directory,
without a subtree grant; Linux grants Landlock `READ_DIR` below that path, which
can reveal descendant directory names but grants no file data or execution.
Reports list these directory allowances separately. Keep `read-file` for paths
that need file contents: unlike `read-directory`, it can make a denied library
readable under Linux Landlock.

macOS refuses the setuid system
`/bin/ps` even in an allow-default sandbox, so accepted consumer observation
must use native process sampling rather than exempting that command.

The [Linux backend](LINUX.md) uses Landlock execution/read rules and seccomp.
Future executable paths require a narrowly reviewed existing staging or generated
build-script subtree. Deferred expected hashes are post-run output observations,
not proof that those bytes were the executed bytes. Neither backend identifies
the semantics of arbitrary opaque or statically embedded runtimes: input/source,
build-script and dynamic-loader closure evidence remains necessary.

Positive native commands and direct, descendant, absolute-shebang and embedded
interpreter refusal controls must pass on each actual supported host before the
adapter is used as qualification evidence. A cross-compilation check alone
cannot qualify Linux kernel enforcement.
