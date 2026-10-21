# Rust toolchain, Cargo crates and Python retirement — revision 3

Updated: 2026-10-21. Decision owner: Fabian Schmieder.

**Authority:** this repository document defines the migration and its acceptance
criteria. On 2026-10-18 Fabian authorised issue/milestone tracking and execution
of this plan in dependency order, including the bounded RC0 probes. Every
implementation, qualification and release gate remains required; authorisation
is not evidence that a criterion has passed.

Epic: [#69](https://github.com/metaneutrons/ami-rust/issues/69). The linked
milestone issues own execution status and evidence; this versioned plan owns
requirements. Native GitHub milestones group the corresponding delivery work. The accepted [R1](release-status.md) and
[APT/Homebrew delivery](distribution-status.md) remain closed on their original
inputs. This initiative is a subsequent SDK/tooling change.

## 1. Outcome and measured starting point

Developers install a versioned AROS cross-toolchain, select it through rustup,
and build with normal Cargo. AROS/Amiga APIs, runtime integration and necessary
host utilities are Rust crates. There is no public `ami-rust` CLI or `cargo-ami`
plugin. Package managers and rustup own installation/version selection; Cargo
owns project/dependency/build operations. Neither these paths nor internal
production may depend on Python at RC5.

On 2026-10-21 Fabian explicitly replaced the earlier CLI product decision and
instructed removal of its existing implementation. RC0/RC1 acceptance remains
historical evidence for revision 2, not a reason to ship their CLI. RC2–RC5 are
still required under the prospective criteria below. Previously qualified
releases, tags, input identities and evidence remain immutable.

Survey base: public source `8c5de39f26838d838b41dec5a89c9a888dbc20d5`.
SDK `v0.1.0` and package release `v0.1.0+packaging.2` are the regression anchors.
The tracked tree contains 104 Python files: 14 under `host/`, 29 under
`packaging/`, 59 under `release/`, and two under `qualification/`. This is a
path inventory, not a count of every script inside third-party source archives.

| Surveyed boundary | Implementation at the revision-1 survey | Migration responsibility |
| --- | --- | --- |
| Package CLI | `packaging/cli.py`, `worker.py` | Native launcher, preparation, package inventory and retained state |
| SDK verification/build | `host/cli.py`, `contracts.py`, `build.py` | Shared Rust contract validation and build adapter |
| Native finalisation | `host/compact_sections.py`, `elf_audit.py` | Rust linker/finalisation boundary and ELF validation |
| Direct install/project generation | `release/install_publisher.py`, `new_project.py` and their helper closure | Rust consumer implementation; these are public dependencies despite their directory name |
| Compiler/C-SDK preparation | `release/consumer_inputs.py`, `ci_cargo.py`, `ci_csdk.py`, `csdk_*.py`, `host/cargo-repro/*.py` | Separate consumer acquisition from internal component production; ultimately replace both Python paths |
| Production and acceptance | Other `release/*.py`, `packaging/*.py`, tests and qualification helpers | Rust maintainer tasks and integration tests |

At the measured starting point Cargo produces an application `staticlib`. `host/build.py` subsequently
compiles C bridge objects, adapts startup, calls the AROS collector, strips,
finalises and audits ELF. A Rust replacement of the launcher alone therefore
does not establish Cargo integration or remove Python. The pinned Cargo also
contains the existing reproducibility patch and uses explicit unstable options;
stock stable Cargo is not an established equivalent.

## 2. Fixed boundaries and definitions

- Hosts remain Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon. Target remains
  native PC x86-64 AROS ABI-v1 on the unchanged qualified QEMU baseline.
- Keep target Rust nightly-2026-09-18, its paired source, Cargo source/patches,
  native compiler, collector and portable C-SDK identities from
  [compatibility](compatibility.md) as initial inputs. Retiring a patch or
  changing a compiler requires its own identified and qualified change.
- No AROS-NX or aros-tools checkout changes, nxpk, other CPU/ABI support, native
  AROS-hosted compiler, full `std`, AUR delivery or official rustup target
  distribution. Existing external tools remain pinned dependencies.
- Do not modify, replace or delete `0.1.0` assets, tags, receipts or evidence.
  New tooling/payloads receive new identities and a normal future release;
  the initial version-reuse exception does not apply.
- **Public Python-free (RC3):** every supported new installation, explicit
  preparation, verification, project generation, build, migration and retained
  replay path has no direct or transitive Python execution, embedded Python,
  interpreter download or Python package dependency. Internal tests and release
  scripts may still use Python temporarily. This claim covers the new release
  and its migrated/retained Rust states, not an unchanged 0.1.0 rollback state.
- **Project Python-free (RC5):** additionally, no active first-party Python
  implementation/test remains, and supported source builds, component derivation,
  CI, qualification, packaging, release and recovery replay execute no Python,
  including through dependencies. Tests and release helpers are not permanent
  exceptions.
- Historical Git history, immutable earlier release/source capsules and sealed
  evidence remain preserved and inert. Required upstream corresponding sources
  may contain Python files; they cannot be an executable dependency of a newly
  accepted pipeline. Unrelated Python installed on a runner/user machine and the
  upstream production of authenticated prebuilt rustc/LLVM are outside this
  project's executable boundary. Rebuilding those upstream tools would need a
  separate decision; do not claim that the entire upstream ecosystem is Python-free.

## 3. Standard toolchain and crate architecture

### Public surface

Ship a complete, versioned host toolchain for each supported host, including its
paired rustc and Cargo, target libraries/specification and the required C-SDK and
link tools. APT, Homebrew and authenticated downloads provide those bytes.
Explicit per-user `rustup toolchain link` registers an installed prefix; a
project's `rust-toolchain.toml` selects its exact version. Do not change the global
default, create a custom updater or operate a new distribution server. Local
registration is now part of RC2/RC3 for the existing macOS/Ubuntu hosts; it no
longer waits for AUR. Official `rustup target add` distribution remains a separate
upstream goal, not a claim made by a local registration.

Use the actual selected Cargo interface for `metadata`, `check` and `build`.
Do not make a copied application CLI masquerade as Cargo or require a mandatory
`cargo ami` command. Include paired Cargo so rustup cannot silently choose an
unrelated installed release. Evaluate every downstream Cargo/compiler patch for
necessity against the standard interfaces; retain only narrowly justified,
versioned and qualified changes. Removing a patch is an input change and needs
equivalence evidence, not an assumption that stock stable Cargo already works.

There is no new public SDK manager: no `ami-rust prepare/new/build/install/doctor`
or `cargo-ami` entry. Existing active Python and Rust CLI entrypoints and their
launchers are retired. Preserve released source in immutable Git/release history,
not as an executable fallback. Existing general validation, extraction, resource
measurement and ELF libraries may be reused by crates or private maintainer tasks;
keep no dispatcher or separate application build engine merely for compatibility.

### Crate boundaries

- **Target libraries:** use the existing `amiga-sys`, `amiga-os`, `amiga-alloc`
  facade and `aros-*` implementation crates as the starting inventory. Preserve
  ABI, ownership, task-affinity and optional-allocation contracts. Registry names
  and publication eligibility are not assumed from workspace directory names.
- **Runtime/build integration:** provide ordinary dependencies and `build.rs`
  integration for startup, C bridge objects and native link directives. Compose
  with developer build scripts; do not overwrite their source or implement a
  second package/feature resolver. Crates must not download SDKs or tools during
  builds. Cargo's normal explicit dependency fetch supplies crate sources; an
  offline build uses the previously fetched/qualified dependency set.
- **Necessary host tools:** expose narrowly scoped Rust binary crates for actual
  AROS tasks, such as native link adaptation/finalisation/audit if still needed.
  They are tools called through Cargo's target-linker/build interfaces, not a
  general SDK CLI. Authenticate any prebuilt tool in the toolchain from that same
  crate source; qualify source installation with `cargo install --locked` where
  advertised. No host crate may leak host settings into target libraries.
- **Maintainer operations:** internal `cargo xtask` and Rust integration tests
  reuse relevant libraries for production, signatures, inventories and evidence.
  They are not required public build commands.

Cargo owns dependency resolution, features, package selection, compilation,
incremental state and artifact discovery. An AROS linker tool performs any
required collection/finalisation/audit during Cargo's link operation. A normal
build returns the final native ELF; there is no separate post-Cargo finishing
engine. Preserve nonconflicting Cargo configuration and credentials and fail
clearly on conflicting compiler, target/sysroot or linker selection. Keep the
existing local trust/concurrency model; do not invent an arbitrary-code sandbox.

### Installation, project configuration and migration

Package installation provides complete usable components without root-time network
provisioning or compilation. Any separate acquisition step must use existing
standard tools, be explicit and documented before the first build, and have
measured costs and authentication evidence. A first `cargo build` must not hide
SDK provisioning. Toolchain registration is opt-in and per-user; package removal
must not delete arbitrary rustup registrations or user projects.

Use portable project configuration and versioned crate dependencies. Machine-local
paths are local configuration, not committed into portable locks or templates.
Migration from a staticlib/CLI project is a documented reviewed project edit:
select the toolchain, add the runtime/build crates and configure the target/linker.
Preserve original source, lockfiles and working versions. Do not supply a new
migration CLI, silently rewrite locks, or execute an old Python launcher.

Crate delivery requires real package manifests, versioned dependencies (no escaping
workspace-only paths), preserved licences/source obligations, a verified registry
publisher/name and a tested release order. Qualify `cargo package` archives and
fresh consumers of the exact delivered crates; a local workspace build is not
registry-distribution evidence. Do not publish while these gates are unmet.

Rustup registration selects tools; it does not authenticate SDK contents, provide
a C SDK or install arbitrary third-party toolchains from a name. Reuse existing
qualified package/signature mechanisms rather than inventing cryptography. Host
Rust and dependencies remain pinned separately from target Rust.

## 4. Deliveries and acceptance

Dependencies below refer to stable milestone IDs. RC0/RC1 below retain the
revision-2 contracts for historical acceptance; they do not require a new CLI
release after the owner decision. RC2–RC5 define the current delivery. Each
future acceptance maps every criterion
to exact source/input hashes, commands, outcomes and durable evidence.

### RC0 — Contracts, dependency closure and Cargo design

Execution: [#70](https://github.com/metaneutrons/ami-rust/issues/70); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/1).

Dependencies: accepted R1/D0/D1 inputs; implementation authorisation before any
experiment. Deliver a reviewed contract and bounded integration design first.

- **RC0-A1:** inventory every public command and transitive consumer helper,
  every internal Python task, and every dependency that can execute Python.
  Assign each to RC1–RC5 with a replacement and removal condition. Inspect the
  actual Cargo/C-SDK producer dependency closure, including generators and source
  archive contents; directory names and file-extension counts are insufficient.
- **RC0-A2:** freeze CLI options/exits, current state/lock/receipt schemas,
  validation rules, trust roots, ownership and compatibility fixtures. Give both
  frontends one capability list and explain any intentional difference. Select
  a host Rust compiler, locked libraries and bootstrap trust path; no trust may
  depend on an unauthenticated download of its own verifier.
- **RC0-A3:** qualify a minimal Cargo-to-final-AROS design on both hosts using
  the pinned tools: C startup, library order, host/target separation, linker
  adapter placement and portable activation. Record custom-Cargo requirements.
  If normal Cargo integration fails, retain the failure and revise the design;
  a renamed wrapper is not acceptance of RC2.
- **RC0-A4:** select and prove the no-Python observation/enforcement harness
  on both hosts. It must observe descendants and absolute-path/shebang/embedded
  interpreter routes, not merely remove Python from PATH. Demonstrate an ordinary
  native command passing and intentional direct/transitive Python probes being
  detected/refused. Unavailable runner observability is an explicit blocker.
  Deliberate detector controls run in isolated fixtures and are reported
  separately from the supported no-Python execution paths.

### RC1 — Rust consumer CLI with equivalent behaviour

Execution: [#71](https://github.com/metaneutrons/ami-rust/issues/71); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/2).

Dependencies: RC0. Port the existing validated recipe before changing its
native semantics. Python can temporarily remain only in internal tests/release
execution, not behind any newly accepted Rust consumer command.

- **RC1-A1:** one shared Rust implementation covers package/direct verification,
  acquisition/authentication, extraction, installation, state/locks, project
  generation, build supervision, finalisation and input recheck. All compatibility
  commands pass their contract fixtures on both hosts without a Python subprocess,
  embedded runtime or downloaded interpreter. Internal Python test orchestration
  is distinguished from the observed consumer process tree.
- **RC1-A2:** run Rust and historical Python implementations against isolated
  copies of the same valid/invalid fixtures. Compare decisions, exits, ownership,
  receipts' semantic fields and preserved user data, documenting deliberate new
  schema fields. Cover altered/missing files, duplicate JSON keys, unsafe archive
  paths/links, wrong host/publisher, interrupted preparation and stale receipts.
- **RC1-A3:** two fresh roots per host reproduce the five qualified build
  variants with unchanged compiler/flags/link inputs. Compare canonical outputs
  under the existing R1 rules; host-specific proc-macro metadata stays separately
  qualified, including Serde derive. Never rewrite `.rlib` or compiler metadata.
- **RC1-A4:** versioned retained Rust tooling survives package removal/upgrade;
  old state, projects, global Rust configuration and unrelated SDKs remain
  intact. A conflicting owner, incompatible state or legacy executable-driver
  contract fails clearly without silently invoking the historical Python driver.

### RC2 — Cargo owns the complete application build

Execution: [#72](https://github.com/metaneutrons/ami-rust/issues/72); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/3).

Dependencies: historical RC1 evidence and the RC0 Cargo findings, with the
revision-3 architecture above. Remove the public CLI/plugin and independent
build engine; preserve relevant library mechanisms and historical evidence.

- **RC2-A1:** normal selected Cargo `metadata`, `check` and `build` work through a
  versioned opt-in rustup-linked toolchain on both hosts, with the paired Cargo
  and rustc. Project configuration selects the AROS target and crate integration. `build --locked --offline`
  produces the final native ELF through Cargo's link operation; no post-build
  Python or separate manual linking/finalisation step is required. Record the
  exact command recipe and returned artifact path. Target `cargo test/run` and
  rust-analyzer support are not claimed without separate evidence.
- **RC2-A2:** the target/runtime/build and necessary host-tool crates provide one
  target/link/validation implementation through standard Cargo interfaces. No
  public `ami-rust`/`cargo-ami` entrypoint or copied-CLI Cargo launcher remains.
  Crate manifests/package archives work outside this workspace with versioned
  dependencies; source-installed advertised tools pass their locked build. Features, package selection, dependency build scripts and host
  proc macros work; incremental rebuild and failed/retried build cases pass.
  Wrong Cargo/rustc/sysroot/linker, ambient conflicting configuration and stale
  target data fail. No fallback to ambient Cargo or global rustup modification.
- **RC2-A3:** repeat canonical comparisons across two fresh roots per host,
  relocation to a different path containing spaces, and the existing host
  metadata/Serde checks. Compile/link commands expose the actual selected tool
  identities. Direct Cargo cannot bypass required input validation/ELF checks;
  failed checks leave no successful final artifact/receipt for that invocation.
- **RC2-A4:** qualify changed native output against the full inherited AROS
  runtime/memory matrix on the unchanged baseline, including allocation-free
  diagnostics, loader/startup, failure cleanup and teardown. Start by comparing
  against the R1 reference. Any intentional byte difference needs an explained
  source/input change, a new candidate identity and independent acceptance;
  updating a golden hash alone cannot establish equivalence.

### RC3 — Publish a Python-free public SDK/tooling release

Execution: [#73](https://github.com/metaneutrons/ami-rust/issues/73); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/4).

Dependencies: RC1 and RC2. This is the first independently releasable migration
outcome, not completion of the medium-term Python-retirement objective.

- **RC3-A1:** deliver signed/attested versioned toolchains and a new SDK inventory
  on both hosts, plus the qualified library/build/tool crates. Verify registry
  namespace ownership, publisher authentication, licences, exact package archive
  identity and dependency publication order before crate publication. No public
  umbrella CLI/plugin or package-manager entrypoint for it is shipped. No active consumer Python files, CPython bootstrap, libpython,
  package-manager Python dependency or Python-based compiler/C-SDK preparation
  remains. The no-Python harness passes the complete cold/warm consumer path,
  with its direct/transitive negative controls. Historical 0.1.0 source capsules
  are inert references, never an execution fallback or the new active SDK payload.
- **RC3-A2:** qualify direct install plus actual APT/Homebrew install, explicit
  per-user rustup registration, a fresh crate-based project, offline build,
  upgrade, reinstall, removal, retained replay and documented recovery on both
  hosts. Test exact tool selection, missing paired Cargo, moved/removed
  registrations and preservation of global defaults and unrelated toolchains. Test package-owned versus user
  state, Cellar relocation, version coexistence and fresh project migration.
  Deny network during the documented offline build, including dependency scripts.
- **RC3-A3:** complete the inherited release integrity/provenance, licence/source,
  native reproducibility/runtime/memory and independent acceptance gates for the
  exact new candidate. Preserve all old release assets/latest state until normal
  promotion. Stage the candidate, publish stable without changing `latest` when
  required for APT ingest, then perform actual public APT/Homebrew readback and
  client acceptance before final SDK/latest promotion. A channel
  failure is reported separately and leaves its previous qualified version usable.
- **RC3-A4:** execute the new README/quickstart verbatim on fresh supported hosts;
  publish the required host tools, downloads, installed/cache sizes, cold/warm
  times and migration/rollback instructions. Documentation explicitly states that
  internal Python retirement is still outstanding. The ordinary version process
  selects a new version; no retroactive 0.1.0 replacement.

### RC4 — Rust maintainer tooling, tests and component production

Execution: [#74](https://github.com/metaneutrons/ami-rust/issues/74); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/5).

Dependencies: RC3 for rollout; design and isolated internal ports may proceed
after RC0 without changing the public candidate. Move active maintainer tasks
to `cargo xtask`/Rust integration tests, reusing the host core.

- **RC4-A1:** replace every active first-party Python test, fixture generator,
  resource/storage monitor and AROS/QEMU measurement/capture driver. Port tests
  by behaviour and failure coverage, not line count; retain original reports as
  historical evidence. Include process-group timeout/cancellation and intentional
  memory/measurement controls so a broken measurement cannot produce a false PASS.
- **RC4-A2:** replace SDK/Cargo/C-SDK production, patch application, metadata/
  licence inventories, packaging, staging, publisher verification, distribution
  and consumer replay with Rust tasks or established non-Python tools. Generate
  channel metadata from one inventory; keep current trust/permission boundaries
  and positive/counter-probes. No parallel Rust/Python production paths remain
  after this milestone, and no source-built component hides a Python generator.
- **RC4-A3:** new component producer reports bind the Rust helpers and all new
  dependencies; rebuild changed Cargo/C-SDK inputs on both hosts before SDK
  acceptance. Old Python-bound producer receipts remain historical and are not
  edited to look current. Verify source obligations, path portability and the
  existing reproducibility contracts before switching CI to the new producers.
- **RC4-A4:** all required CI, protected qualification and staging workflows use
  the new tasks. Each replaced production stage passes a successful fixture and
  a deliberately failing one, plus the relevant real protected workflow. An
  unsigned fixture or local Rust rewrite cannot replace real producer evidence.
  Retained historical documentation links to immutable old source where its
  helpers have been removed from the active tree.

### RC5 — Demonstrate complete active Python retirement

Execution: [#75](https://github.com/metaneutrons/ami-rust/issues/75); [delivery milestone](https://github.com/metaneutrons/ami-rust/milestone/6).

Dependencies: RC4. This milestone is mandatory for initiative completion.

- **RC5-A1:** a reviewed tracked-file/dependency/workflow inventory has zero
  active first-party `.py`, Python entry points, interpreter artifacts or Python
  execution dependencies, including extensionless scripts, indirect generators,
  shared actions and recovery instructions. Historical exceptions are enumerated
  by identity and remain inert; there is no unowned "internal helper" exception.
- **RC5-A2:** reproduce the supported source/component build, full Rust tests,
  protected SDK/package production, AROS runtime/memory acceptance, staging and
  consumer replay without Python execution on both supported hosts. Linux also
  uses a Python-free build environment; macOS uses the RC0-qualified enforcement/
  observation harness. Merely hiding `python` in PATH or finding no `.py` files
  fails this criterion. Re-run the harness's positive and negative controls.
- **RC5-A3:** publish the next exact accepted release through the existing direct,
  APT and Homebrew routes and verify public bytes and fresh-client lifecycle.
  Preserve rollback to the prior qualified version. Bind the no-Python evidence
  to these exact producer and package identities, not an earlier local prototype.
- **RC5-A4:** update contributor/build/release/recovery documentation so a new
  maintainer can execute the supported process without Python. Independently
  review the complete RC0–RC5 mapping, outstanding dependencies and historical
  exclusions before declaring this initiative complete.

## 5. Compatibility, migration and rollback

Toolchain, crate/tool version, SDK version, package revision and manifest/receipt schema are
separate fields. Add new typed/versioned contracts; do not reinterpret a legacy
hash that explicitly bound Python helpers as if it authenticated Rust binaries.
Read legacy state only through reusable validation or documented inspection
needed to explain migration. The migration guide records old/new SDK, compiler
and contract identities; reviewed edits create separate configuration/selection
and preserve the original project, lock and receipts. It never automatically upgrades the compiler.
Neither inspection nor migration executes the legacy launcher, interpreter or
Python-bound build driver. Preserved 0.1.0 bytes are rollback evidence/state,
outside the new release's no-Python execution claim.

Where unchanged compiler/native inputs permit reproduction, the new state must
reproduce the old project's native result. If a project requires an incompatible
legacy recipe, return a specific migration-required/unsupported result and keep
the old version usable. Never claim that a deliberately retained 0.1.0 Python
environment has itself become Python-free. After migration, the new path must
not invoke it. Reject unknown future schemas before mutation.

Upgrade/rollback is side-by-side and versioned. Changing the selected toolchain/crates does not
delete user state, rewrite shell startup files, replace global Rust installations
or retire older working SDKs. Package removal only removes owned files; retained
toolchain and versioned crates contain the components needed for documented replay.

## 6. Verification sequence, risks and cost

Execute RC0, RC1, RC2, RC3, then RC4 and RC5. Integrate one dependency-complete
slice at a time. During the temporary dual-language period use differential
fixtures as an internal oracle; remove the oracle from active CI at RC4. Do not
maintain two independent production implementations indefinitely.

Use cheap host-side Rust fixture/lint checks for portable changes; use native
macOS/Linux checks when platform behaviour changes. Run four clean build roots
and the complete native matrix at the named integration/release gates, not after
each prose or parser change. Execution is now authorised; run the named probes and qualification only when
their dependencies and prospectively recorded inputs are ready. Existing realistic [memory](memory-policy.md),
[storage](local-storage-policy.md) and hosted resource contracts apply; measure
new binary/preparation costs and agree any necessary prospective revision before
a campaign. There is no new overall project timer or arbitrary application cap.

The high-risk work is authenticated toolchain delivery, the staticlib-to-Cargo
link transition, crate packaging/publication, migration and transitive producer
dependencies.
Rust does not make these disappear. Prefer established libraries and tools,
bound untrusted parsing/extraction, and preserve failures. An upstream build
dependency that still needs Python blocks RC5 until removed, replaced or
substituted by a reviewed authenticated prebuilt input; it is not silently waived.

No calendar or total runner-cost promise is established by the current survey.
RC0 produces estimates per delivery after dependency/design closure; RC1/RC2 and
RC4 are substantial engineering work. RC3 and RC5 require separate release
qualification. Closure is based on evidence, not the amount of code translated.

## 7. Decisions and sources

- 2026-10-18: Fabian requested the Rust public CLI/Cargo migration plan, limited
  transitional Python to internal tests/releases, and made complete medium-term
  Python retirement the intended outcome. Revision 1 was planning only.
- 2026-10-18: Fabian authorised the epic/milestone tracking and instructed execution.
  Revision 2 adds the actual issue/milestone links and execution authority;
  all 24 acceptance criteria and the qualified input boundaries are unchanged.
- 2026-10-21: Fabian rejected a separate public CLI, selected standard rustup/Cargo
  use with AROS/Amiga libraries and tools delivered as crates, and explicitly
  instructed removal of existing CLI code. Revision 3 supersedes the CLI surface
  in revision 2 prospectively; it does not invalidate or edit old acceptance
  evidence. RC2-A1/A2 and RC3-A1/A2 now require the toolchain/crate delivery instead
  of dual CLI compatibility. Native reproducibility, runtime/memory, integrity,
  lifecycle and complete Python-retirement requirements remain required.
- Local rustup selection on the existing hosts is now a core migration dependency.
  [Distribution plan revision 5](distribution-channels-plan.md) separates it from
  deferred AUR/Arch and official upstream rustup distribution. Accepted R1/D0/D1
  identities and historical criteria remain unchanged.

Primary interfaces checked on 2026-10-18; rustup/Cargo interfaces rechecked on
2026-10-21:
[Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html),
[Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html),
[Cargo external commands](https://doc.rust-lang.org/cargo/commands/cargo.html),
[custom rustc targets](https://doc.rust-lang.org/rustc/targets/custom.html), and
[rustup toolchains](https://rust-lang.github.io/rustup/concepts/toolchains.html).
These documents inform the design; they do not qualify AROS integration.
