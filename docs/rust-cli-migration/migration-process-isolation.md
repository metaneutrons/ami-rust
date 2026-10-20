# Legacy migration process isolation

The new Rust migration reads and hashes the interpreter named by the legacy
project lock as inert identity data. It must preserve this validation without
running the interpreter or loading its Python runtime. The old installation
remains available for an explicitly selected rollback outside the new
consumer process.

## Runtime and filesystem boundary

The qualification coordinator excludes the complete known historical runtime
from broad read-tree grants. It grants safe sibling inputs and literal ancestor
directories separately, then restores only the exact interpreter byte-read
needed by migration. The old `libpython` remains explicitly denied. All new
consumer operations after historical setup use this boundary, including
read-only inspection, migrated-lock verification, builds and retained replay.
Policy construction propagates listing/stat errors and refuses any write area
that overlaps the historical runtime. The adapter's generic overlap checks
remain unchanged.

macOS can deny process execution separately from file-data reads. Linux
Landlock cannot subtract a denied executable from an exact file-read grant;
its allowed ELF loader also makes a path-only execution claim insufficient.
The Linux CLI therefore installs an irreversible seccomp filter for both
`InspectMigration` and `MigrateProject`, after parsing and before rendering.
The filter denies `execve` and `execveat`, rejects the x32 syscall convention,
checks the syscall architecture, and synchronizes to existing threads. Failure
to install or synchronize the filter aborts the command before migration work.
The core migration APIs and other CLI commands do not install this process-wide
filter. The filter does not change SDK compiler, target ABI or link inputs.

This permits the qualification policy to grant the exact legacy interpreter
read on Linux without a colliding `deny-exec` entry for that one identity.
The reviewed CLI's process-wide denial replaces that path-only entry for
migration. Other interpreter denials, the old library denial and the absence
of derived execution grants remain in force. This exception is valid only for
the source-bound Rust CLI that installs the guard before processing migration
inputs. It is not a relaxation of the adapter for arbitrary commands.

The implementation follows the Linux kernel's [seccomp filter
interface](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
It supplements the existing filesystem, environment and reviewed-input closure;
it does not claim containment of arbitrary malicious or statically embedded
runtimes. Historical Python setup is a separate, explicitly labelled internal
oracle during RC1. RC4 must retire that active oracle as well.

## Required evidence

The Linux guard's isolated regression test first proves unfiltered `execve`
and `execveat` marker processes run, then checks that the installed guard blocks
both transitions, applies to a pre-existing thread and survives a fork while
ordinary file hashing still works. The parent test process remains unfiltered.
Native Linux execution is required; macOS compilation cannot establish this.

The published-state transition uses the exact pinned 0.1.0 packaging archive,
creates the actual historical state/project/build, and preserves those inputs
through native preparation, migration, activation, rollback, package removal
and retained native replay. Migration must reproduce the historical native
executable byte-for-byte. The existing two-root/five-variant matrix remains
required on both hosts. Local consistency-only packages and detector controls
are development evidence, not signed SDK or RC1 acceptance.

A stale signed SDK from before the required native producer inventory changed
cannot qualify the current frontend. Its source-inventory refusal must remain
a failure. Generate and authenticate a fresh source-bound SDK after candidate
integration, then run the complete supported-host lifecycle. Do not rewrite
older producer receipts or published release assets.
