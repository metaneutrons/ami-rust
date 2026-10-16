# First SDK release versioning

The first SDK version is 0.1.0. Release Please manages the version, changelog,
production tag and draft release. `release-please-config.json` selects the
simple strategy and updates `Cargo.toml` workspace version together with
`version.txt`. The empty manifest records that no release exists yet;
`initial-version` selects 0.1.0 for the first release rather than declaring it
already released.

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

This file prepares the route; it records no release PR, production tag,
publication, or R1 acceptance.
