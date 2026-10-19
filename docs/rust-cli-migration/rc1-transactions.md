# RC1 filesystem transactions

This is a partial delivery for [RC1](https://github.com/metaneutrons/ami-rust/issues/71)
under migration plan revision 2. It supplies native host filesystem operations;
it does not activate a consumer command or establish RC1 acceptance.

## Boundary

`tooling/crates/core/src/transaction.rs` receives immutable installation files
and receipt bytes after upstream authentication and semantic validation. It
does not verify publisher signatures, provenance, a release policy or the
receipt's binding to that policy. Likewise, removal receives an inventory
already extracted from a semantically validated, externally pinned receipt.
The filesystem layer independently checks the raw receipt digest and actual
tree; it cannot replace that upstream validation.

The CLI capability ledger continues to refuse unfinished commands. No target
crate, native compiler, C-SDK, released asset or AROS baseline changes here.

## Publication and interruption

Ownership validation retains shared no-follow directory handles. Installation
creates a fresh private sibling, writes exact file modes, verifies the complete
file and directory set, syncs files and attempts directory syncs, then publishes
with the host's exclusive atomic rename. It never falls back to replacing an
existing destination. A changed parent pathname refuses publication; cleanup
still uses the original retained handle.

SIGTERM handling is cooperative. The handler records an atomic request; normal
transaction code checks safe points. Calling-thread masks protect creation and
publication bookkeeping. The guard restores the previous handler and thread
mask. This does not promise to interrupt arbitrary blocking operations, mask
other threads or snapshot changes by another writer with access to the same
inode. Process/child supervision belongs to a later consumer integration slice.

A pre-publication failure removes only the owned stage. A cleanup failure
reports its recovery location. That location includes the last-known parent,
entry name and observed parent device/inode; it asserts a pathname only if the
parent still matches its retained handle. A detached parent is explicitly
reported rather than pointing at a replacement directory.

After publication, a failed/interrupted receipt-pin write retains the SDK and
reports the prefix, receipt digest and whether the pin was published. This is
status 1; a pre-publication refusal is status 2. Pins are fresh, external,
exclusive atomic writes with mode 0600. They cannot overwrite unrelated files.

## Removal and recovery

Removal checks safe prefix ownership, the separate raw receipt pin, exact
contents/directories, current-user file ownership and write permissions. It
moves the prefix to a fresh hidden sibling and rechecks before deletion. A
failed second check attempts an exclusive rollback. If the original name is
occupied, it preserves both that occupant and the tombstone and reports recovery.
Once deletion begins, a partial tree is never restored under the original name.
The external pin and source bundle remain outside the removed tree.

## Host resource profile

The existing installer profile supplies 2,002 content files, a 4 MiB receipt and
64 MiB of installed bytes. New publication counts the receipt within that total
so it cannot produce a tree that the installed-tree reader immediately refuses;
the old writer checked its content total before adding the receipt. This only
tightens that inconsistent boundary. Modes are normalized to 0644/0755 for SDK
files, 0644 for payloads and 0600 for the receipt. Paths reuse the publisher's
portable ASCII path rules and reject case/ancestor collisions before creation.

Tree work/cleanup bounds derive from the exact file and ancestor set. Iterative
cleanup avoids recursive call-stack growth. Unsupported exclusive rename or
no-follow chmod fails closed. Directory sync remains best effort, matching the
historical installer. These are bounded host metadata/operation profiles, not
size or memory quotas on AROS applications.

## Evidence scope

Focused tests exercise exclusive collisions, mode enforcement under umask 0777,
symlink substitution, descriptor anchoring, bounded/deep cleanup, real SIGTERM,
post-publication pin failure, changed stage contents, detached-parent recovery,
pre/post-move uninstall checks, rollback collisions and partial deletion.
Isolated child fixtures execute signal/umask controls without changing the
parallel test process. Each parent test asserts its child's successful exit.

Independent review found and corrected the detached-parent recovery-path error;
its regression deliberately makes cleanup fail after moving the parent. Typed
receipt parsing, complete authentication/acquisition, generic prerequisite
extraction, consumer activation, retained lifecycle and the five-variant native
build comparisons remain outstanding RC1 work. Local Rust tests or a green
filesystem CI run cannot close those gates.

The [local evidence](evidence/rc1-transactions-local-20261019/result.json)
records exact source hashes, Rust 1.98.1, 92 passing core tests and one actual
Cargo/frontend integration test, formatting and Clippy with warnings denied.
Two ignored child fixtures are explicitly executed and checked by their parent
tests; the restrictive-umask control also runs in its own process.

The [filesystem differential](evidence/rc1-transactions-local-20261019/filesystem-differential.json)
compares six tiny fixture cases with the pinned historical Python 3.12.15:
publication bytes/modes/pin, correct removal, occupied prefix, occupied pin,
altered file and an extra empty directory. It compares the filesystem API, using
the old receipt bytes unchanged. Rust receipt generation/parsing, public CLI
exit behavior, publisher authentication and the full native matrix are outside
this proof. SIGTERM and post-publication failures have Rust regression tests;
they are not included in this six-case differential. Both-host CI remains a
separate qualification step.
