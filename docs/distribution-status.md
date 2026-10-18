# Package channel status

Updated 2026-10-18. The original [SDK 0.1.0 release](release-status.md) is stable
and unchanged. APT and Homebrew are separate follow-up deliveries tracked by
[initiative #60](https://github.com/metaneutrons/ami-rust/issues/60).

| Gate | Current evidence |
| --- | --- |
| Package identities and ownership | [Delivery contract](distribution-package-contract.md); SDK 0.1.0, Debian 0.1.0-1, Homebrew revision 1 |
| Local cold adapter consumer | Preparation, new project, offline build, input check and R1-identical SHA utility passed in a fresh macOS 26 state; earlier failures retained |
| APT archive registration | [APT archive PR #26](https://github.com/metaneutrons/apt-archive/pull/26), merged after all required checks |
| Homebrew host policy | [Tap PR #70](https://github.com/metaneutrons/homebrew-tap/pull/70), merged after all required checks |
| Producer development preflight | Pinned verifier downloads, public SDK retrieval and deterministic package/metadata generation passed locally; exact publisher proof selection is frozen |
| Protected package production and staged readback | Pending |
| Actual package-manager lifecycle on both hosts | Pending |
| Attested formula PR, qualification and tap readback | Pending |
| Signed public APT metadata, SHA512 by-hash, exact package and real client | Pending |

Neither channel is accepted as available until its public client gate passes.
The additional packaging release does not replace the default/latest SDK release.
Prospective instructions: [APT](../packaging/INSTALL-APT.md),
[Homebrew](../packaging/INSTALL-HOMEBREW.md),
[explicit user preparation](../packaging/README.md).
