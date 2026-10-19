# RC1 process ownership and resource measurement inputs

This partial delivery for [RC1](https://github.com/metaneutrons/ami-rust/issues/71)
provides three shared native primitives and uses the ownership primitive in
publisher command capture. It does not activate a CLI capability or establish
aggregate resource enforcement, no-Python observation or RC1 acceptance. The
[revision 2 plan](../rust-cli-cargo-migration-plan.md#rc1--rust-consumer-cli-with-equivalent-behaviour)
remains the acceptance authority.

## Ownership before signalling

The private `process_lease` module owns the actual `Child` handle, its derived
positive PID/group ID and its collected status. Every group/direct-child signal
attempt first observes that direct child through `waitid(WNOWAIT)`. An earlier
exit observation is insufficient: a fresh check must still detect an intervening
competing reap. `ECHILD` permanently disables signalling. The backend also
refuses the caller's own process group. Supported callers retain default
SIGCHLD behaviour, exclusive reaping ownership and unchanged credentials.

An observation retries interruptions at most eight times; exhaustion remains
an error, not permission to signal. Capture cleanup always attempts the
lease-guarded direct-child kill after the group kill, including an empty-group
result: the direct child may have moved out of its original group. If killing
fails and exit cannot be observed, cleanup reports failure instead of entering
a blocking wait for a still-live child. Destruction is best effort on observation
errors. Kernel process creation, signal delivery and waits are not hard real-time
operations.

The lease reserves only its original group through its unreaped direct child.
Cached process IDs from samples are never accepted as signal authority. This is
not universal descendant containment or cleanup of escaped sessions.

## Process samples

`process_snapshot` parses exactly four ASCII decimal columns from the existing
`/bin/ps -axo pid=,ppid=,pgid=,rss=` recipe. Callers select byte and row bounds.
Malformed/overflowing fields, duplicates and excess input refuse. A sampled
kernel PID zero may be retained, but zero cannot be a requested target.

Pure scope calculation preserves the historical parent/group closure, including
a previously observed parent whose own row disappeared during the table walk.
It returns current rows in source order, sorted identities/groups, missing prior
PIDs, root presence and checked RSS totals. Root absence is an observation, not
successful command completion. Adjacency indexes avoid repeatedly scanning the
whole table for each generation. A required caller-selected bound checks the
combined prior PID/group input lengths, including duplicates, before allocating
indexes. The caller must also bound cumulative sampling work in a running command.

The frozen [98 historical cases](../../tooling/crates/core/tests/fixtures/process_scope_oracles.json)
bind the original observer revision and source digest. A native Rust integration
test compares every decision without running Python. Development comparison
first exposed 19 disagreements in an earlier prototype; correcting missing-parent
linkage produced agreement on all 98 cases. Native unit controls additionally
cover 32,768 reversed generations, cycles, group closure and arithmetic failures.
These cases test sampling semantics, not the stability of numeric process IDs.

## Filesystem samples

`workspace_accounting` iteratively enumerates descriptor-anchored directories.
The caller supplies the intended validated root and explicit entry/work bounds.
Regular-file lengths are sampled with no-follow `fstatat`, without opening their
contents. Unreadable and growing regular logs therefore remain measurable.
Hard links count once per path. Only byte-exact `.log` suffixes enter the log
subtotal; symlinks and special entries contribute zero.

Root spellings ending in a slash, dot or parent alias refuse before opening;
the single filesystem root `/` remains valid. This prevents `link/` or `link/.`
from bypassing final-component no-follow semantics. The initial missing root
and entries removed between enumeration and lookup
contribute zero, matching the historical walker. Other errors remain failures.
Opened child directories must retain the observed device/inode/mode identity.
Totals use checked arithmetic. Concurrent mutation is not an atomic snapshot;
the caller must validate parent namespace/ownership separately. Entry/work
bounds protect the measurement operation and are not SDK application quotas.

## Local evidence

The [exact-source local result](evidence/rc1-resource-inputs-local-20261019/result.json)
passes formatting, 233 core unit tests and three integration tests (236 total),
plus Clippy with warnings denied. Two ignored fixtures are invoked by asserting
parent tests. The 29 registry identities and production lock are unchanged.
The [old-fallback counterprobe](evidence/rc1-resource-inputs-local-20261019/direct-child-fallback-counterprobe.json)
fails as expected: the moved-group child survived until its finite natural
exit rather than receiving SIGKILL. Restored candidate sources pass the same
regression. This is local host evidence; both-host CI remains separate.

## Integration still required

A consumer observer must combine bounded command capture, these samples and
the accepted RC0 execution policy around the actual consumer process tree. It
must aggregate all managed workspace/log roots, including earlier command logs;
preserve time/RSS/workspace/log peaks and actual exit/signal status; bound
cumulative history; retain cleanup failures; and refuse incomplete observation.
Platform-specific stable descendant identity and cleanup need their own controls.
The existing build and publisher profiles remain unchanged.

Acquisition, installation, state/project/build/replay activation, both-host
no-Python controls, differential lifecycle fixtures and the full RC1 build matrix
remain separate gates. No new AROS output or SDK release is produced here.
