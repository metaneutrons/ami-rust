---
title: Maintainer workflow
---

# Maintainer workflow

ami-rust separates ordinary source checks from expensive candidate and release
qualification.

## Local source check

`tools/build-maintainer-task.sh` authenticates the pinned host Rust components,
verifies both lockfiles and the offline vendor archive, and builds
`ami-rust-xtask` in a fresh directory. Run the tooling workspace tests with that
bootstrapped Cargo under the repository's contribution policy.

## GitHub workflows

| Workflow | Purpose | Trigger |
| --- | --- | --- |
| `ci.yml` | Rust producer checks on macOS and Linux | push and pull request |
| `toolchain-pr-check.yml` | Candidate-affecting pull-request checks | pull request or manual |
| `native-cargo-qualification.yml` | Internal cross-host application qualification | manual |
| `toolchain-qualify.yml` | Exact three-host release candidate | manual |
| `release-please-toolchain.yml` | Initial or subsequent release proposal | manual for mutation |
| `toolchain-release.yml` | Catalog review, non-publishing signed-candidate preparation, publication, and recovery | manual |

The release workflows require protected `main`, exact upstream workflow-run
identities, and protected environments. A successful development check does not
authorize publication.

## Initial release

The repository begins with `version.txt` at 0.1.0 and the release-please manifest
at 0.0.0. The first manually dispatched proposal advances the manifest
to the prepared 0.1.0 release. No tag or release is created by a normal push.

Before publication:

1. verify that README commands match the exact candidate;
2. run the supported-host qualification and native AROS runtime matrix;
3. review the generated two-file rustup catalog delta;
4. prepare and verify signed exact payloads without creating a release;
5. after explicit publication approval, attest and stage those bytes;
6. read every public asset back before promotion.

APT, Homebrew, AUR, and crates.io are outside the initial release.

## Prepared 0.1.0 candidate

The exact source candidate at
`95795520653aca959bb17b3b73cf025261d049a7` passed the three-host,
dual-target and native ABI1/ABI11 qualification in workflow run
[`40986442000`](https://github.com/metaneutrons/ami-rust/actions/runs/40986442000).
The reviewed catalog commit is
`bb5cc2e428b89685eeec2ae249701cc23fd135d7`; signed assets were prepared in
[run 40994382906](https://github.com/metaneutrons/ami-rust/actions/runs/40994382906).
The complete identities and acceptance mapping are in the
[M7 qualification record](https://ami-rust.metaneutrons.cc/m7-qualification/). These steps do not authorise
the `publish` workflow mode.
