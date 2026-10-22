# Internal one-command qualification

`ami-rust-xtask qualification-command` is a private maintainer task. It is not a
consumer CLI or SDK manager. Application development uses rustup and Cargo.

The task reads an explicit JSON request and writes fresh command evidence:

```text
ami-rust-xtask qualification-command --request REQUEST.json --record FRESH_DIRECTORY
```

The versioned request contains an absolute executable, argument vector, absolute
working directory, complete replacement environment, required managed roots, and
caller-selected time/RSS/workspace/log limits. Roots must exist, have no symlink
ancestors and be disjoint. A fresh record may be nested in exactly one root and
is counted once. Metadata binds request, executable, helper, arguments and
environment digests; environment values are not copied into it.

Raw stdout/stderr and the typed resource report are retained. A nonzero child
status is propagated only by this task; existing maintainer refusals remain 2.
Preparation errors refuse before running the command. Observation, resource,
cleanup or finalization errors cannot produce an authoritative success.

`result.pending.json` is always nonauthoritative. Its contents are synced while
SIGTERM observation remains active. The task then checks cancellation, rechecks
root/record/parent identity and atomically publishes `result.json` by an exclusive
rename. No fallible library operation follows publication. Directory-name crash
durability is not claimed. Supervising job status remains necessary: a committed
record alone does not prove that the encompassing workflow succeeded.

This observes one command, with sampled child resources and a conservative sum
of helper/child RSS high-water values. The helper's own sample precedes the final
workspace walk and result serialization. It is neither containment nor complete
campaign accounting. Setup/bootstrap, outer orchestration and final artifact
handling need their own qualification. Environment/script language alone cannot
prove that descendants never execute Python.

The [Mac component evidence](evidence/rc4-native-command-component-20261022.json)
records positives, deliberate refusals, original failed lint evidence, source
and executable identities and independent review. Its captured-log counter also
reports an EPERM cleanup error and zero samples; it qualifies refusal only.
Linux operation, complete setup/campaign instrumentation and Python retirement
remain open under [RC4](rust-cli-cargo-migration-plan.md#rc4--rust-maintainer-tooling-tests-and-component-production).
