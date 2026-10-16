# Local storage policy

**Owner decision — Fabian, 2026-10-16.** This policy applies prospectively to
maintainer/developer volumes used for ami-rust preparation, retained evidence,
staging, and backups. End-user installation requirements remain separate.

## Local capacity and admission

Use actual free disk space on every affected managed volume. For a large
operation—such as a build, recovery, or download—estimate its combined additional peak
footprint, including new inputs, temporary outputs, retained results,
and backup or compression overlap. Admit it only when each affected volume is
expected to retain at least **32 GiB free after that peak**.

The 32 GiB operating headroom is two existing 12 GiB build workspaces plus
8 GiB for recovery and backup. Routine editing and copying use one simple
aggregate free-space check at the start of a work session; they do not require per-file reservations or a
reservation/claim/release ledger. Keep estimates and checks proportional to
the operation.

There is no fixed cumulative local archive quota. There are no per-file or
per-subdirectory size caps for retained licences, source, or documentation.
Use volume-level headroom to decide whether the complete operation fits.

## Evidence and historical results

Preserve original evidence, failed attempts, hashes, and backups. This policy
does not delete or rewrite records, turn a previous failure into a pass, reset
a campaign clock, or retroactively change a result. Earlier 4 GiB incremental
and 6 GiB combined retained-archive quotas, and earlier per-file or
per-subdirectory caps, remain historical criteria for the work governed by
them; they do not govern new local work under this policy.

## Limits that remain in force

The following are independent operational or product limits and are unchanged:

- Standard hosted CI: 4 GiB observed aggregate RSS, 12 GiB generated workspace,
  16 MiB logs, 20 minutes per command, 90 minutes per campaign, and the
  512 MiB remote artifact pool.
- AROS boot, ABI, guest memory, stack, heap, and code-size limits.

This local policy does not qualify the native SDK for release. Existing release
acceptance gates still apply.
