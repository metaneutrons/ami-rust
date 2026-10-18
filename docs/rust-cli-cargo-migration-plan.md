# Rust CLI, Cargo integration and Python retirement — revision 1

Date: 2026-10-18. Decision owner: Fabian Schmieder.

**Authority:** this repository document defines the proposed migration and its
acceptance criteria. Fabian requested this plan, including complete medium-term
Python retirement. Implementation, qualification runs, tracking setup and
publication are not authorised by that request. No migration criterion has
passed merely because this plan exists.

Epic and milestone issues: pending; no GitHub objects have been created for this
proposal. After tracking is authorised, issues own execution status and evidence;
this versioned plan owns requirements. The accepted [R1](release-status.md) and
[APT/Homebrew delivery](distribution-status.md) remain closed on their original
inputs. This initiative is a subsequent SDK/tooling change.

## 1. Outcome and measured starting point

Developers install a native host binary, prepare an authenticated SDK explicitly,
and use Cargo to build native AROS applications. Neither the CLI nor its
preparation, verification, linking or retained-project path requires Python.
The medium-term completion condition also removes Python from the project's
active tests, qualification, dependency preparation and release production.
Keeping Python indefinitely as an internal implementation language is not the
target architecture.

Survey base: public source `8c5de39f26838d838b41dec5a89c9a888dbc20d5`.
SDK `v0.1.0` and package release `v0.1.0+packaging.2` are the regression anchors.
The tracked tree contains 104 Python files: 14 under `host/`, 29 under
`packaging/`, 59 under `release/`, and two under `qualification/`. This is a
path inventory, not a count of every script inside third-party source archives.

| Existing boundary | Current implementation | Migration responsibility |
| --- | --- | --- |
| Package CLI | `packaging/cli.py`, `worker.py` | Native launcher, preparation, package inventory and retained state |
| SDK verification/build | `host/cli.py`, `contracts.py`, `build.py` | Shared Rust contract validation and build adapter |
| Native finalisation | `host/compact_sections.py`, `elf_audit.py` | Rust linker/finalisation boundary and ELF validation |
| Direct install/project generation | `release/install_publisher.py`, `new_project.py` and their helper closure | Rust consumer implementation; these are public dependencies despite their directory name |
| Compiler/C-SDK preparation | `release/consumer_inputs.py`, `ci_cargo.py`, `ci_csdk.py`, `csdk_*.py`, `host/cargo-repro/*.py` | Separate consumer acquisition from internal component production; ultimately replace both Python paths |
| Production and acceptance | Other `release/*.py`, `packaging/*.py`, tests and qualification helpers | Rust maintainer tasks and integration tests |

Today Cargo produces an application `staticlib`. `host/build.py` subsequently
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

## 3. Architecture to implement after authorisation

Use one host-side Rust core for manifests, locks, inventories, safe extraction,
component selection, process supervision, build receipts and ELF checks. Keep it
separate from target `no_std` crates. A small CLI crate exposes `ami-rust` and,
where useful, Cargo's external-command entry point `cargo-ami`. Both call the
same core. Internal `xtask` tasks reuse that core rather than growing another
consumer implementation. Start with these three logical components; split more
crates only for a demonstrated boundary.

Cargo owns dependency resolution, features, compilation, incremental state and
artifact discovery. It remains the existing qualified Cargo until a replacement
passes equivalence. Generate project-local Cargo configuration and use normal
`build.rs` integration for target C objects/link directives where appropriate.
A small Rust linker adapter may perform AROS collection, required finalisation
and audit during Cargo's link operation. It must not implement another resolver
or require a Python/post-Cargo finishing command. Host build scripts and proc
macros must use host settings; target flags must not leak into them.

RC0 freezes the exact activation/configuration recipe; it must select the pinned
Cargo and rustc explicitly without changing global rustup defaults. Normal Cargo
build/check/metadata commands are the RC2 goal. `cargo ami build` is a convenient
frontend, not evidence by itself that normal Cargo builds the final executable.
Local rustup registration remains a later distribution feature, not a dependency
of this migration. Neither custom targets nor a plugin imply official
`rustup target add` support.

The proposed direct-Cargo route is explicit SDK preparation, input preflight,
then the verified Cargo binary from the selected state with generated
project-local configuration. That configuration selects the paired rustc,
target/sysroot, isolated Cargo cache and Rust linker adapter; machine-local
activation paths are regenerated after relocation, not committed into portable
locks. RC0 must prove the exact environment/config precedence and reject
conflicting ambient overrides. `metadata` produces a dependency graph, not an
SDK-authentication result. `check` validates the selected compiler/SDK through
the Rust compiler guard but has no final ELF to audit. `build` additionally
revalidates link inputs and audits final ELF through the linker adapter. A
`cargo-ami` plugin cannot provide those hooks for unrelated Cargo commands.
These checks retain the existing local trust/concurrency model; they are not a
sandbox against a user deliberately replacing the tools or overriding the recipe.

Consumer commands proposed for the compatibility contract:

| Surface | Contract |
| --- | --- |
| `ami-rust --version`, `verify-package` | Report separate CLI, SDK and packaging identities; verify owned package bytes |
| `prepare --state`, `new --state --project`, `check-inputs --state` | Preserve the current explicit lifecycle; no hidden first-build acquisition |
| `build --state --project --output-dir [--package] -- …` | Preserve supported package CLI options and offline/locked selection |
| `verify --sdk-lock`, `build --sdk-lock --output-dir -- …` | Preserve direct SDK operations for compatible contracts; legacy schemas are handled as below |
| `ami-rust verify --bundle --policy`, `install --bundle --policy --prefix --receipt-pin`, `lock --prefix --selection --project --output`, `uninstall --prefix --receipt-sha256` | Rust replacements for the direct release-bundle installer; RC0 maps exact current options and receipts before implementation |
| `cargo ami …` | Optional Cargo entry point to the same declared capabilities and core |
| Normal Cargo `metadata`, `check`, `build` | After documented preparation/activation, use the qualified tools and produce the native executable without a subsequent finishing step |
| `ami-rust migrate --dry-run`, then explicit migration | Proposed addition: inspect a legacy project, report identity changes and create a separate reviewed selection; never rewrite a lock silently |

These are future interface requirements, not instructions that work in 0.1.0.
RC0 records exact options, output schemas, supported Cargo arguments and exit
mapping, including interrupted child processes. Unsupported/conflicting options
fail before mutation. Do not broaden the current CLI into a general tool manager.

New CLI binaries are built for both hosts and distributed through the existing
direct, APT and Homebrew routes. No end-user Rust compiler is needed to install
the launcher. Authentication reuses qualified standard tooling such as the
existing pinned GitHub/Sigstore verifiers where appropriate; replacing Python
does not justify implementing new cryptographic verification protocols. Freeze
the Rust host compiler and dependencies separately from the target compiler;
prefer the existing authenticated bootstrap compiler initially. Commit its exact
selection and Cargo.lock before implementation builds, after licence/security review.

## 4. Deliveries and acceptance

All execution issues are pending. Dependencies below refer to milestone IDs,
not uncreated GitHub issue numbers. Each future acceptance maps every criterion
to exact source/input hashes, commands, outcomes and durable evidence.

### RC0 — Contracts, dependency closure and Cargo design

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

Dependencies: RC1 and the RC0 Cargo design. Preserve the compatibility build
command as a thin facade over the new path; retire the independent build engine.

- **RC2-A1:** normal selected Cargo `metadata`, `check` and `build` work after
  explicit preparation/activation on both hosts. `build --locked --offline`
  produces the final native ELF through Cargo's link operation; no post-build
  Python or separate manual linking/finalisation step is required. Record the
  exact command recipe and returned artifact path. Target `cargo test/run` and
  rust-analyzer support are not claimed without separate evidence.
- **RC2-A2:** both CLI frontends and direct Cargo share one target/link/validation
  implementation. Features, package selection, dependency build scripts and host
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

Dependencies: RC1 and RC2. This is the first independently releasable migration
outcome, not completion of the medium-term Python-retirement objective.

- **RC3-A1:** deliver signed/attested native CLI binaries and a new SDK inventory
  on both hosts. No active consumer Python files, CPython bootstrap, libpython,
  package-manager Python dependency or Python-based compiler/C-SDK preparation
  remains. The no-Python harness passes the complete cold/warm consumer path,
  with its direct/transitive negative controls. Historical 0.1.0 source capsules
  are inert references, never an execution fallback or the new active SDK payload.
- **RC3-A2:** qualify direct install plus actual APT/Homebrew install, explicit
  preparation, new project, offline build, upgrade, reinstall, removal, retained
  replay and documented recovery on both hosts. Test package-owned versus user
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

CLI identity, SDK version, package revision and manifest/receipt schema are
separate fields. Add new typed/versioned contracts; do not reinterpret a legacy
hash that explicitly bound Python helpers as if it authenticated Rust binaries.
Read legacy state only to validate, explain and propose a migration. Dry-run
reports the old/new SDK, compiler and contract identities without mutation;
explicit migration writes a fresh state/selection and preserves the original
project, lock and receipts. It never automatically upgrades the compiler.
Neither inspection nor migration executes the legacy launcher, interpreter or
Python-bound build driver. Preserved 0.1.0 bytes are rollback evidence/state,
outside the new release's no-Python execution claim.

Where unchanged compiler/native inputs permit reproduction, the new state must
reproduce the old project's native result. If a project requires an incompatible
legacy recipe, return a specific migration-required/unsupported result and keep
the old version usable. Never claim that a deliberately retained 0.1.0 Python
environment has itself become Python-free. After migration, the new path must
not invoke it. Reject unknown future schemas before mutation.

Upgrade/rollback is side-by-side and versioned. Changing the active CLI does not
delete user state, rewrite shell startup files, replace global Rust installations
or retire older working SDKs. Package removal only removes owned files; retained
Rust tooling contains the binaries/manifests needed for its documented replay.

## 6. Verification sequence, risks and cost

Execute RC0, RC1, RC2, RC3, then RC4 and RC5. Integrate one dependency-complete
slice at a time. During the temporary dual-language period use differential
fixtures as an internal oracle; remove the oracle from active CI at RC4. Do not
maintain two independent production implementations indefinitely.

Use cheap host-side Rust fixture/lint checks for portable changes; use native
macOS/Linux checks when platform behaviour changes. Run four clean build roots
and the complete native matrix at the named integration/release gates, not after
each prose or parser change. No new native tests or CI runs are part of this
planning task. Existing realistic [memory](memory-policy.md),
[storage](local-storage-policy.md) and hosted resource contracts apply; measure
new binary/preparation costs and agree any necessary prospective revision before
a campaign. There is no new overall project timer or arbitrary application cap.

The high-risk work is consumer trust/bootstrap parity, the staticlib-to-Cargo
link transition, receipt migration and transitive producer dependencies.
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
  Python retirement the intended outcome. Implementation remains unauthorised.
- This proposal neither reopens accepted R1/D0/D1 nor changes the deferred
  AUR/rustup delivery gates in [the distribution plan](distribution-channels-plan.md).
  The migration does not depend on their implementation.

Primary interfaces checked on 2026-10-18:
[Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html),
[Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html),
[Cargo external commands](https://doc.rust-lang.org/cargo/commands/cargo.html),
[custom rustc targets](https://doc.rust-lang.org/rustc/targets/custom.html), and
[rustup toolchains](https://rust-lang.github.io/rustup/concepts/toolchains.html).
These documents inform the design; they do not qualify AROS integration.
