# Package delivery contract — revision 1

Owner authorisation: 2026-10-18. Implement D0, D1-APT and D1-BREW under the
[distribution plan](distribution-channels-plan.md). The [initiative](https://github.com/metaneutrons/ami-rust/issues/60)
and milestones [D0](https://github.com/metaneutrons/ami-rust/issues/61),
[APT](https://github.com/metaneutrons/ami-rust/issues/62) and
[Homebrew](https://github.com/metaneutrons/ami-rust/issues/63) record execution.
This contract defines the intended delivery; acceptance is recorded separately.

## Identities and publication order

SDK `0.1.0` remains exactly the R1-accepted six-asset release at source
`b4ebb9cce5decd01616b75acf451d0eba9995ee3`, producer `39121017959/1`.
The additional GitHub release/tag is `v0.1.0+packaging.2`: an independent,
protected-source packaging delivery, not a replacement SDK. Debian version is
`0.1.0-2`; Homebrew uses `version "0.1.0"`, `revision 2`. Never append package
files to the frozen SDK release, repoint its tag or change its original assets.
Publish the packaging release without making it the default/latest SDK release.

The package producer generates and verifies exact archives, Debian packages,
formula, SBOMs, provenance, signatures and checksums. The already accepted
publisher proof bytes are pinned alongside the six SDK assets; later attestations
on shared component digests cannot silently change package inputs. Qualify the final package
bytes and complete the staged public readback before promoting this packaging
release to stable. The Homebrew formula travels through the existing tap's PR
and required qualification. The central APT archive ingests only after stable
publication; SDK publication, Homebrew availability and APT availability are
distinct outcomes. A downstream failure does not mutate an accepted SDK.

## Layout and consumer implementation

The single inventory identifies every package control file, original SDK asset
and publisher proof by size/hash/mode. A neutral archive contains `usr/bin`,
`usr/libexec/ami-rust/0.1.0-2` and package documentation. Debian installs these
under `/usr`; Homebrew places the contents of `usr` in its versioned Cellar
prefix. The launcher resolves its own real location. Debian declares Python
3.10+, Git and CA certificates; Homebrew declares Python 3.14, Git, macOS 26+
and ARM64. The adapter checks the exact initially qualified OS profiles.
There is no compiler build during package installation and no maintainer script.

`ami-rust prepare` explicitly obtains the pinned source and prerequisites in a
fresh private user state. It invokes the original Python bootstrap, public
candidate verifier, consumer-input provisioner and production installer.
Packaged proofs avoid requiring user GitHub credentials. `new` invokes the
original generator and project-lock creator; `build` invokes the original host
driver with locked offline Cargo arguments. `check-inputs` runs the original
retained-input verifier. Neither Rust metadata nor native SDK code is changed.
The [installed instructions](../packaging/README.md) define the exact commands.

The package-manager-owned inputs remain read-only. Preparation retains a
versioned adapter/input snapshot, original source, private installed SDK and
pinned interpreter under the selected state. The retained launcher survives
package removal, Cellar relocation and interpreter cleanup. A package upgrade
does not select a newer SDK for an old state or change global Rust defaults.
Direct installations stay separate; preparation refuses existing/overlapping
destinations and never adopts or deletes unrelated user files.

## Qualification and resources

Reuse the measured R1 host requirement: 6 GiB physical RAM and 24 GiB free disk
for a cold state. The unchanged original provisioner keeps its existing command,
RSS, output and managed-work checks. Local work additionally keeps the repository
policy's 32 GiB operating headroom. Measure package bytes, retained snapshot,
source download/preparation and cold/warm build timings; report actual values.
There is no SDK application heap or ELF quota introduced by this packaging work.

Each named host lifecycle campaign receives a prospective 90-minute active-work
window, with execution ending by 85 minutes and five minutes for closure. Record
source/package identities and the clock before running it. Queue time and
pipeline preparation are reported separately; this is not a project deadline.
An attempt with changed executable inputs starts a separately named campaign,
retaining the earlier failure and clock. Routine offline fixture tests are
development checks, not a substituted lifecycle qualification.

Fresh Ubuntu 24.04 x86-64 and macOS 26 ARM64 hosts execute the delivered commands,
compare the rebuilt native SHA utility against its R1 hash, and check publisher
authentication, missing/altered components, project preservation and global
settings. Package-manager install, upgrade, removal, reinstall and retained-state
rebuild must succeed. Public APT checks include the signed metadata, strongest
by-hash index, exact package identity/bytes and a real client. Public Homebrew
checks compare the published formula bytes and install/test that formula.

For the first channel release there is no previous published package. Qualify
upgrade with a clearly labelled, isolated lower packaging-revision fixture,
followed by the exact final package/formula through the actual package manager.
The fixture is never signed as a release or published. Subsequent deliveries use
the previous actual public package for upgrade qualification. Corruption and
wrong-host probes operate on isolated copies and must fail before acceptance.

The immutable ABI-v1/QEMU baseline and all existing M1/M2/R1 results remain
unchanged. Matching component/native hashes support reuse of runtime evidence;
any changed compiler choice, Cargo/link flags, runtime or resulting native bytes
requires the affected qualification again. AROS-NX and aros-tools remain
unchanged; nxpk, AUR and rustup implementation remain outside this delivery.
