# Distribution channels — revision 4

Owner decision: 2026-10-18. D0, D1-APT and D1-BREW are accepted against the
criteria below without removing or weakening any criterion. APT and Homebrew are
available for the supported hosts recorded here. D2 AUR and D3 rustup remain
deferred. The acceptance record and criterion mapping are in
[`distribution-0.1.0.json`](evidence/distribution-0.1.0.json). Requirements
authority: this file in `metaneutrons/ami-rust`; the external master plan is a
derived summary.

## Outcome and sequence

APT and Homebrew now provide supported installation paths after R1. AUR remains
the next delivery, followed by rustup feasibility and qualification. GitHub
Releases remains the canonical artifact and recovery channel. These are
follow-up deliveries, not additional R1 gates. The accepted R1 release,
qualified baseline and sealed evidence remain immutable; these channels have
their own acceptance records.

| Delivery | Outcome | Initial host coverage | Depends on |
| --- | --- | --- | --- |
| D0 | Shared packaging and lifecycle contract | Existing macOS/Linux profiles | R1 published; read-only design can precede it |
| D1-APT | Signed APT archive delivers the qualified package | Ubuntu 24.04, `amd64` | D0 |
| D1-BREW | Owner tap delivers a qualified formula/bottle | macOS Apple Silicon, macOS 26 | D0 |
| D2-AUR | Reviewed AUR recipe installs qualified payloads | Arch Linux x86-64, newly qualified | D1-APT and D1-BREW accepted |
| D3-RUSTUP | Versioned toolchain selection through rustup | macOS 26 Apple Silicon; Ubuntu 24.04 amd64; D2-qualified Arch x86-64 | D2-AUR accepted; design investigation may precede it |

D1-APT and D1-BREW can be developed independently after the shared contract is
settled; neither has to wait for the other's implementation. Debian, older
Ubuntu/macOS, macOS Intel, Linux ARM64 and Homebrew-on-Linux are not advertised
as supported without their own host evidence. APT compatibility alone does not
establish Debian SDK compatibility. The target remains PC x86-64 AROS ABI-v1;
no new AROS CPU/ABI or physical-hardware claim is implied.

## Current baseline and boundaries

The current route downloads authenticated GitHub release assets, provisions
pinned prerequisites explicitly, and uses the existing verification,
installation, project-lock, project-generation and build entry points. Global
Rust defaults are preserved. The [release status](release-status.md) records
R1 qualification and publication evidence; this roadmap does not maintain a
second live R1 status ledger.

The package channels must reuse this implementation and the same qualified SDK
payloads. They may add a thin executable launcher and package layout adapters;
they must not introduce another dependency resolver, compiler fork, update
daemon, custom package manager or independent SDK build pipeline. Source
patches needed for portability remain small, versioned and requalified under
the repository portability policy. Finished Rust metadata is never rewritten.

Use the existing owner tap and shared APT archive. The surveyed destinations
are `metaneutrons/homebrew-tap` and `metaneutrons/apt-archive`, domain
`metaneutrons.cc`, public base `https://deb.metaneutrons.cc`. No new tap, archive,
signing key, AUR package or rustup distribution service is required. AROS-NX and aros-tools remain unchanged; nxpk is out of scope.

## D0 — Shared package and lifecycle contract

First measure the package layout and prerequisite costs. Freeze one inventory
that identifies SDK version, packaging revision, SDK payload digest, publisher
source/run, host profile, interpreter, Cargo/Rust/C-SDK inputs, licences and
corresponding sources. Package revision and SDK version are separate identities.
Do not retrofit new assets into the frozen R1 `0.1.0` inventory. Select the next
packaging/release version under the normal version policy; the one-time R1
version exception does not extend to these channels.

Use package-manager-owned, versioned, read-only SDK files and an explicitly
separate user-owned project/cache/preparation area. The package must provide a
working launcher and its declared interpreter; it cannot assume the developer's
Python or build paths. Heavy compiler prerequisites may continue to use the
existing explicit, verified user preparation flow. If so, the documentation
must say that `apt install`/`brew install` installs the SDK entry point and that
one separate preparation step is required before the first build. D0 freezes
that exact command sequence and compares it with packaging the prerequisites
as managed components. There are no hidden first-build downloads, root-time
network provisioning or builds in Debian maintainer scripts.

Common acceptance criteria:

- **D0-A1 — one implementation:** record the exact existing entry points reused
  by each package command, filesystem ownership and host selection. Any adapter
  contains packaging glue only. No global Rust/rustup/Cargo replacement or
  changes to shell startup files are required.
- **D0-A2 — integrity and provenance:** every package has its own complete
  inventory/provenance and a byte-level mapping to the qualified SDK/components.
  Wrong host, altered/missing input and wrong publisher/version fail before
  installation or execution. Preserve full licence texts and source obligations.
- **D0-A3 — lifecycle:** on fresh supported hosts, execute the delivered commands
  verbatim: install, explicit preparation if required, create a project, build
  offline, upgrade, remove and reinstall. Preserve projects, lockfiles,
  unrelated SDKs and global Rust settings. A locked old project remains usable
  through a documented retained version or explicit verified reprovisioning;
  an upgrade must not silently select the new compiler.
- **D0-A4 — recovery:** interrupted installation, failed integrity checks and
  package removal leave the prior working version usable or provide a tested
  documented recovery. Refuse conflicting package/direct-install ownership;
  migration never deletes the user's source or project snapshots.
- **D0-A5 — measured cost:** record download/installed/cache sizes, disk peaks,
  host prerequisites and cold/warm timings. Set concrete test-campaign budgets
  prospectively from those measurements. Do not impose a new overall project
  timer or revive historical SDK application memory quotas.

D0 is complete only when the layout, actual commands, upgrade/retention policy
and measured resource contract are reviewable. A statement that a package is
merely a wrapper does not satisfy it.

## D1-APT — Linux package and signed archive

Produce a canonical Debian binary package with the correct host architecture
(`amd64`, not the Rust target triple). The project builds and attests the `.deb`;
the existing owner-operated `metaneutrons/apt-archive` verifies it and publishes
signed repository metadata. Archive signing keys and storage write credentials
do not belong in the ami-rust producer repository.

The user-facing flow is documented repository setup followed by installation
of `ami-rust=0.1.0-2` from `https://deb.metaneutrons.cc`. Scope trust with a
dedicated keyring and `Signed-By`, and provide a deb822 `.sources` example.
Package installation must not broaden trust to unrelated repositories.

- **APT-A1:** inspect package contents/control data, canonical filename,
  architecture, dependencies, permissions and licence/source inventory; verify
  protected producer provenance for the exact `.deb`. A modified package,
  wrong architecture/version or missing attestation is rejected.
- **APT-A2:** a clean Ubuntu 24.04 client performs repository setup, update,
  install and the D0 build/lifecycle sequence using the actual signed archive.
  Verify the retrieved package bytes and native reference output. Missing
  signature, wrong key, tampered index/payload and expired metadata fail.
- **APT-A3:** a release upgrade and explicit version selection work through APT.
  A failed ingest/publish preserves the previous committed archive state and
  unrelated packages. Repository/key removal and package removal are documented
  separately; retained project data is not purged as package-owned content.

SDK prerelease tests use locally qualified `.deb` files. The shared archive
ingests stable GitHub releases only. Therefore SDK stable promotion precedes
archive ingest and live APT verification; promotion must not wait for an ingest
that itself requires a stable release. Track `SDK published` and `APT available`
separately. An archive failure retains the previous APT version and cannot be
reported as a successful all-channel rollout.

## D1-BREW — macOS package

Use one owner tap, not a new tap per project. A formula installs the qualified
host payload and launcher into a versioned Cellar layout. Prefer a bottle when
needed to avoid rebuilding compiler/C-SDK prerequisites on the user's machine.
The exact formula/bottle is generated from the frozen packaging inventory;
formula source, checksums and any bottle relocation are separately qualified.

- **BREW-A1:** formula syntax, audit and meaningful `brew test` pass. Install
  from the same formula/bottle bytes proposed for the tap; verify all declared
  upstream URLs/hashes. Reject unsupported host profiles explicitly.
- **BREW-A2:** a fresh macOS Apple Silicon host completes the D0 lifecycle,
  including real project generation/offline native build, `brew upgrade`,
  `brew reinstall`, `brew uninstall` and cleanup. Test version retention and
  Cellar/`opt` path changes; no absolute build path, broken receipt or stale
  launcher may survive relocation. Existing user projects remain recoverable.
- **BREW-A3:** publish through a reviewed tap pull request using narrowly scoped
  GitHub App credentials. Required tap CI passes before merge. Read the public
  formula back byte-for-byte and install from the actual public tap. A failed
  update leaves the previous qualified formula usable.

The initial Homebrew gate is confined to the approved host scope above. Other
Homebrew host/architecture combinations receive an explicit unsupported result;
they are not advertised merely because Homebrew itself runs on them. Any future
expansion needs its own positive installation/build evidence.

## D2-AUR — later delivery

Package the prebuilt, qualified payload through an `ami-rust-bin` recipe if the
eventual content meets Arch's binary-package convention. Survey package-name
ownership first; do not assume the name is available. Pin an actual Arch test
image and qualify its host ABI/prerequisites before claiming support.

- **AUR-A1:** build the package in a clean pinned Arch environment; generate
  `.SRCINFO` from the reviewed PKGBUILD and check the exact version/host/digests.
  Building a package around existing bytes must not rebuild Rust or the C SDK.
- **AUR-A2:** actual `makepkg`/pacman install, upgrade, remove and D0 project
  replay pass on Arch x86-64, including altered archive and unsafe install-hook
  counter-probes. Projects and global Rust installations remain intact.
- **AUR-A3:** publish by the maintainer's authenticated AUR Git path. Verify
  public PKGBUILD and `.SRCINFO` bytes and indexed version afterwards. AUR holds
  the recipe, not uploaded SDK binaries; immutable releases hold the payloads.

## D3-RUSTUP — later integration with explicit feasibility gates

D3 covers exactly three host profiles: macOS 26 on Apple Silicon, Ubuntu 24.04
on x86-64, and the Arch x86-64 profile accepted in D2. Arch qualification in D2
is a prerequisite, not a claim that the current R1 supports Arch. Test optional
rustup registration together with each profile's package-manager-owned files.

Distinguish two outcomes. A versioned `rustup toolchain link` can register an
authenticated ami-rust toolchain locally; that is the first implementation
candidate. Official `rustup target add` support is a separate upstream effort,
requiring an accepted target, distribution artifacts, CI and maintenance
commitments. It is not promised by local toolchain registration.

- **RUSTUP-A1:** compare local toolchain registration, a separately operated
  distribution service and upstream target support. Record required compiler/
  Cargo patches, target/sysroot/linker packaging, ownership and recurring costs.
  Prefer local registration/upstream standard interfaces; operate no custom
  distribution server unless a concrete benefit justifies its maintenance.
- **RUSTUP-A2:** on each of the three D3 host profiles, a versioned opt-in toolchain and
  project selection invoke the exact pinned Rust and Cargo. Never fall back
  silently to ambient Cargo when the custom toolchain lacks it. A plain
  documented Cargo build produces the qualified AROS reference executable;
  the required C SDK/linker/ABI inputs remain pinned and explicit.
- **RUSTUP-A3:** selection, coexistence, upgrade and uninstall preserve the
  global default and old locked projects. Missing compiler/Cargo, wrong target,
  wrong SDK and removed registrations fail clearly. Removal does not delete
  shared/package-owned compiler files or arbitrary user toolchains.
- **RUSTUP-A4:** advertise official rustup target distribution only after the
  upstream acceptance and real official-channel install/build are evidenced.
  If upstream adoption is unavailable, report that outcome as deferred; do not
  relabel a local link or private mirror as official rustup support.

## Release evidence and maintenance

Keep one versioned packaging inventory and shared verification/build logic;
generate channel metadata from it. Test affected channel behavior during
development, then qualify the exact release packages on their declared hosts.
Packaging-only changes may reuse unchanged native/runtime evidence through
exact component hashes. Changed compiler selection, flags, Cargo, linker or
runtime require the affected M1/M2/R1 checks again, including fresh AROS evidence
where native behavior can change. The qualified AROS baseline stays pinned.

Every channel acceptance records exact versions, hashes, source/producer runs,
host matrix, verbatim commands, positive/counter-probes, actual public readback
and documented limits. Preserve failures. A channel that fails stays unavailable
or retains its prior working version; it does not silently acquire a broader
credential or bypass a release gate.

The [distribution initiative](https://github.com/metaneutrons/ami-rust/issues/60)
and its linked D0/D1 milestone issues own execution status and evidence. This
document owns requirements, not a duplicate live CI status table.

The [package contract](distribution-package-contract.md) records the selected
layout, version identities, explicit consumer commands and qualification scope.
The immutable SDK release `v0.1.0` is preserved; the new packaging release is
`v0.1.0+packaging.2`, with Debian version `0.1.0-2` and Homebrew revision 2.
Packaging publication keeps the SDK release as `latest`; all new channel
artifacts have their own protected-source provenance and acceptance.

## D0 and D1 acceptance record — revision 4

All D0-A1–A5, APT-A1–A3 and BREW-A1–A3 criteria above passed. Their wording and
scope remain unchanged. This acceptance applies to SDK `0.1.0`, Debian
`0.1.0-2` and Homebrew revision 2 on the exact host profiles in this plan. The
criterion-by-criterion mapping, commands, measurements, run identities and
retained receipts are in [`distribution-0.1.0.json`](evidence/distribution-0.1.0.json)
and the [distribution status](distribution-status.md). The initial macOS
controller failure remains recorded there; it did not change the sealed
candidate or the acceptance criteria.

## Sources checked on 2026-10-18

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew bottles](https://docs.brew.sh/Bottles)
- [Debian third-party repository guidance](https://wiki.debian.org/DebianRepository/UseThirdParty)
- [Arch AUR submission guidance](https://wiki.archlinux.org/title/AUR_submission_guidelines)
- [rustup toolchains and custom toolchain registration](https://rust-lang.github.io/rustup/concepts/toolchains.html)

Recheck mutable package-manager policies and actual infrastructure during D0.
The architecture and gates above are ami-rust decisions; external documentation
does not establish that any channel has already been implemented or accepted.
