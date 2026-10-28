# Consumer command enforcement

This is a maintainer qualification tool, excluded from the installed SDK and
public toolchain. It runs an actual supported consumer command under an
inherited execution policy. Internal test coordination remains separate from
the consumer process tree. Protected release qualification owns the production
acceptance boundary.

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

Use `write-null /dev/null` when the reviewed command needs output redirection
to the null device, such as the cold upstream installer or a build-script
compiler probe using `Stdio::null()`. The consumer observer selects it for cold
preparation and builds; other command phases keep their existing policy. The parser accepts only
that exact canonical character device, checks its OS device identity before
launch and after completion, and records both identities without hashing device
contents. Linux binds only `WRITE_FILE` and, on Landlock ABI 3 or later,
`TRUNCATE` to the opened null-device inode. macOS adds `file-write*` for the
literal `/dev/null` path. The rule is rejected when a broader writable tree
would already cover the device.

The imported macOS `system.sb` already permits null-device writes. Omitting
this directive does not revoke that operating-system allowance; the native
omission probe records successful writing on macOS and refusal on Linux.
Both hosts additionally reject a directive naming `/dev/zero` before child
launch. A declared macOS rule adds explicit identity evidence, rather than
claiming that it introduced the system profile's existing permission.

macOS runtime discovery uses `read-lookup-metadata PATH` for validated selected
host-tool aliases. This rule grants only literal `file-read-metadata` at the
unresolved lookup prefixes. It never grants data access or execution at the
resolved target. Separate exact canonical `read-file` and `read-directory`
rules retain the original data authority even if an alias changes later.
This host-specific directive is not emitted for Linux, where Landlock does not
restrict path metadata lookup. It does not establish atomic identity validation.

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
granting `process-exec`; Linux permits `READ_FILE` only. The policy path is the
normalized absolute lookup spelling (no `.` or `..` components or repeated
separators), which can contain genuine symlink components. The adapter retains
that spelling and separately hashes the canonical regular-file target. On
macOS, when the lookup spelling differs from the canonical target, the profile
adds only exact `file-read-metadata` permission for the lookup path and the
lookup prefixes whose spelling differs from their canonical target. This
library rule grants file data and executable mapping only for the canonical
target, and never adds the alias to `process-exec`. Independently declared
`read-file` and `read-tree` scopes keep their own data-read permissions; an
alias inside such a scope is not subject to a policy-wide metadata-only
guarantee. Library hash/target checks and explicit deny rules still apply.

Before and after the command the adapter resolves the lookup spelling and
checks the canonical target path, target device/inode, and content hash. A
retargeted lookup path or changed target identity is an evidence failure. Two
distinct lookup spellings may map to the same canonical target when their
expected hashes agree; duplicate spellings and inconsistent hashes are
rejected. Lookup aliases are rejected when they overlap a child-writable tree
or explicit denied library/executable paths, just as canonical targets are.
The input and symlink lookup graph must remain trusted and immutable while the
command runs. Before/after checks report persistent changes; they do not prove
an atomic race-free lookup.

The Linux backend is unchanged: Landlock `READ_FILE` applies to the canonical
target and does not restrict metadata lookups, so the macOS alias-only metadata
rule is not needed there. The adapter verifies the declared SHA-256 before and
after the command. A library mapping cannot overlap an explicitly denied
library, an executable allowance, or a writable tree.

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

Positive native commands and unauthorized-executable controls must pass on each
actual supported host before the adapter is used as qualification evidence. A
cross-compilation check alone cannot qualify Linux kernel enforcement.
