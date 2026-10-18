# First SDK release versioning

The initial SDK version is 0.1.0. Release Please manages the version, changelog,
production tag and draft release. `release-please-config.json` selects the
simple strategy and updates the `Cargo.toml` workspace version together with
`version.txt`. For the first release, `initial-version` selects 0.1.0 when the
manifest has no package version; that setting does not itself assert that a
release exists. Later release state is recorded in `.release-please-manifest.json`.

Use Release Please 17.11.2, source commit
`05c6a4f71022304d4edad24ea90c1c16324503d5`, with Node 22 or newer.
PR creation and draft/tag creation are separate operator steps: `release-pr`
opens or updates only the release PR. Its dry run must propose exactly 0.1.0.
Only one release PR may be in flight. Keep the README current before merging
it. A version-changing release PR must update Cargo.lock with the selected Cargo
toolchain and pass locked-build CI before merge. The first release starts from
the existing 0.1.0 workspace and lockfile versions.

Qualify the exact merged release-PR commit under R1-A1 through R1-A7 before
running `github-release`. Its dry run must select that same commit and tag.
`draft: true` does not postpone tag creation: `force-tag-creation: true` makes
the actual command create the production tag as well as the draft. No workflow
in this change invokes either command automatically.

An app installation token restricted to this repository creates the release PR
so its pushes trigger ordinary CI. The CLI supports a private absolute token
file path; pass that path rather than placing the token value in command-line
arguments or logs. Credential custody and actual scoped access must be checked
before use. No credential is added by this configuration.

The existing staging controller fills only the release-please draft and checks
its peeled tag against the qualified publisher source. Draft readback and real
signature/provenance verification precede making the unchanged assets visible
as a prerelease. Public two-host consumer and guest replay under R1-A8 precede
stable/latest promotion. Failed qualification leaves the draft unpublished.

This procedure defines the release route. The dated [release status](release-status.md)
records the actual release and acceptance state for the selected source snapshot.

## Approved initial-version replacement exception — 2026-10-18

Fabian explicitly authorised the corrected release to retain `0.1.0` and
requested removal of the failed public candidate. The old release and tag have
been removed. See the [decision record](release-version-exception-20261018.md).

For this one-time replacement, freeze the exact corrected commit merged through
protected source CI and qualify that source under all existing R1 criteria.
The earlier release PR and its source are historical; do not let Release Please
select them again. Keep workspace, lockfile and package versions at `0.1.0`.
A repository-scoped App operation may explicitly create the replacement
`v0.1.0` tag and draft at the newly qualified commit, after checking that both
are absent and that the exact source has passed A1–A7. This exception replaces
only the normal release-PR selection/version step. It does not replace source
CI, qualification, draft byte readback, signatures/provenance, public replay or
the stable-promotion gates. Do not run normal version-bumping automation as
part of this replacement.
