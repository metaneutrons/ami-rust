# ami-rust production installation recipe

This recipe documents consumer preparation and use for the initial PC x86-64
AROS ABI-v1 SDK version, `0.1.0`, under the host and target profiles below.
Consult the [dated release status](https://github.com/metaneutrons/ami-rust/blob/main/docs/release-status.md) before treating any
version as supported; support requires recorded R1 acceptance and public replay.

Select the exact 40-character publisher source and workflow commits through the
trusted public source/release channel, independently of this downloaded bundle.
Use a clean checkout of `https://github.com/metaneutrons/ami-rust.git` at that
source commit. Do not select these trust anchors only from `release.json`.
For the first release the workflow commit equals the source commit. The source
checkout includes the complete pinned C-SDK and vendor inputs. It remains a
read-only prerequisite; the commands below do not modify global rustup or Cargo.

On macOS Apple Silicon or Linux x86-64, start with Git, a working Python 3.10+
and an empty private STATE directory on a volume with at least 24 GiB free and
6 GiB physical RAM. Linux uses glibc; the qualified hosted profile is Ubuntu
24.04. macOS uses the qualified macOS 26 runner profile. Choose STATE outside
source/bundle trees and any `.cargo/config` ancestry. Set these paths and the
independently selected commit explicitly in your shell; these are local choices,
not paths embedded by the publisher:

```sh
SOURCE=/absolute/path/to/clean-publisher-source
SOURCE_COMMIT=REPLACE_WITH_INDEPENDENTLY_TRUSTED_40_CHARACTER_COMMIT
WORKFLOW_COMMIT="$SOURCE_COMMIT"
BUNDLE=/absolute/path/to/downloaded-candidate
STATE=/absolute/path/to/empty-private-state
PYTHON_BOOTSTRAP="$STATE/ami-rust-python-bootstrap"
PREP="$STATE/preparation"
PREP_OUTPUT="$STATE/preparation-output"
WORK="$STATE/project"
mkdir -m 700 "$WORK"
```

Run this preparation command from the trusted source instructions. It downloads
and verifies the pinned standalone CPython 3.12.15 into a fresh local prefix:

```sh
python3 -I -B "$SOURCE/release/ci_python.py" --prefix "$PYTHON_BOOTSTRAP" --inputs "$SOURCE/release/ci-python-inputs.json"
```

Select that interpreter and prepare the remaining prerequisites. The same code
is used by the independent CI consumer on both hosts:

```sh
PREP_PYTHON="$PYTHON_BOOTSTRAP/runtime/python/bin/python3.12"
PYTHON="$PREP_PYTHON"
"$PREP_PYTHON" -I -B "$SOURCE/release/ci_verify.py" prepare-inputs --bundle "$BUNDLE" --work "$PREP" --output "$PREP_OUTPUT" --python-bootstrap-root "$PYTHON_BOOTSTRAP" --source-commit "$SOURCE_COMMIT" --workflow-commit "$WORKFLOW_COMMIT" --selection "$WORK/selection.json"
POLICY="$PREP/trust/publisher-policy.json"
```

Preparation obtains pinned GH/Cosign executables and trusted roots from the
trusted source policy. It authenticates every release asset using real GitHub
attestations and Cosign bundles before extracting bundled Cargo. It explicitly
provisions Rust, Cargo, the native toolchain, collector, C-SDK and vendor tree,
checks every declared file/symlink and writes `WORK/selection.json`. The policy
pins the publisher, exact source/workflow commits, protected main ref, OIDC
issuer, certificate identity, input manifest and verifier/root hashes. A bundled
policy or disposable test signer cannot establish trust. Preparation does not
install the SDK. It admits 24 GiB free space on the STATE volume after the
Python bootstrap; a separate read-only source volume needs no build reserve.
In CI the entire preparation invocation must finish within 20 minutes; each
inner command retains that same ceiling. A slower attempt fails and must be
repeated explicitly in a fresh STATE. RAM, workspace and log ceilings are not
increased for preparation. Downloads happen here; the subsequent builds use locked offline
inputs. Network, pin or inventory errors stop preparation and preserve previous
installations. Use a fresh STATE for another attempt; do not bypass a mismatch.

The following commands are the delivered recipe for both documented host
profiles. Use the variables established above; WORK is the fresh private project
directory.

The qualification driver supplies those paths explicitly and runs every command
below without alteration. `receipt.sha256` is saved outside the installed prefix.
`selection.json` is the explicitly provisioned host profile.

```sh
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" verify --bundle "$BUNDLE" --policy "$POLICY"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" install --bundle "$BUNDLE" --policy "$POLICY" --prefix "$WORK/sdk-0.1.0" --receipt-pin "$WORK/receipt.sha256"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/sdk-0.1.0/sdk" --output "$WORK/utility.lock.json"
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/utility-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-sha256sum --release --locked --offline
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-noalloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline --no-default-features
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-alloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline --features alloc
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/qualification-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-qualification --release --locked --offline
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/dependencies-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-dependencies --release --locked --offline
"$PYTHON" -I -B "$BUNDLE/new_project.py" --sdk "$WORK/sdk-0.1.0/sdk" --output "$WORK/hello-aros" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/hello-aros" --output "$WORK/hello.lock.json"
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/hello.lock.json" --output-dir "$WORK/hello-build" -- build --manifest-path "$WORK/hello-aros/Cargo.toml" --package hello-aros --release --locked --offline
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" uninstall --prefix "$WORK/sdk-0.1.0" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"
```

After uninstall, recheck the retained prerequisites and selection without
reinstalling or silently replacing anything. This command verifies the bundle
again and checks all six complete inventories. Rechecking retained inputs is
not a new cold build admission: it needs 6 GiB physical RAM and 560 MiB free
scratch space on STATE (512 MiB bounded source-SDK expansion plus the existing
16 MiB log and 32 MiB output bounds). It keeps the 4 GiB observed RSS, 12 GiB
managed-work and 20-minute command ceilings:

```sh
"$PREP_PYTHON" -I -B "$SOURCE/release/ci_verify.py" check-inputs --bundle "$BUNDLE" --work "$PREP" --output "$PREP_OUTPUT" --python-bootstrap-root "$PYTHON_BOOTSTRAP" --source-commit "$SOURCE_COMMIT" --workflow-commit "$WORKFLOW_COMMIT" --selection "$WORK/selection.json"
```

Keep STATE while you need its projects or prerequisites. A missing/altered input
requires explicit preparation in a fresh STATE. Do not remove another SDK,
shared Rust installation or global rustup configuration to recover this state.

The installation command saves the receipt pin outside the installation. SHAUTIL is the prebuilt native reference utility. Verify that the
fresh utility build has the declared SHAUTIL digest before staging either file
into the qualified guest. In AROS Shell, with the utility and a known fixture
present on the test medium, run:

```text
SHAUTIL "fixture with spaces.bin"
Echo $RC
Echo "shell remains usable"
```

Compare the output with a host-generated SHA-256 and expect status 0. A missing
file must produce a diagnostic and nonzero status. The prior R3 records cover
the full runtime/error/diagnostic/loader-memory matrix only for exact matching
executable bytes; a different executable requires fresh affected evidence.

The new-project helper copies the complete receipt-verified SDK source snapshot
into `hello-aros/sdk-source/` (at most 8 MiB and 1,000 regular files). Relative
path dependencies keep all Rust sources below the project root; no compiler,
C SDK, vendor tree or native payload is copied. The project retains its source
snapshot and original licence/modification files after uninstall. Regenerate
or explicitly review that snapshot when selecting a new SDK version.

Use SDK `amiga-sys` only at the unsafe ABI boundary; prefer the task-affine
`amiga-os` API. Tasks, library lifetime, buffer ownership and callbacks remain
bounded by the delivered `SDK-API.md`. A fallible allocation operation such as
`Vec::try_reserve` can report refusal in its own error type; `amiga_os::ErrorKind`
has no out-of-memory variant. The global allocator returns null on native
refusal. If an infallible allocation reaches Rust's allocation-error handler,
the installed entry hook follows the nonreturning native fatal path and ends the
current application with status 20. Rust `Drop` does not unwind on this path;
native registry cleanup runs separately. Actual memory exhaustion and checked
size, accounting or ownership refusals remain possible. `std`, networking, a
compiler running on AROS, other ABI/CPU/OS combinations and physical hardware
are excluded. No arbitrary crate compatibility is claimed.

Install versions side by side. Verification failures and interrupted staging do
not replace an old installation. SIGTERM/ordinary exceptions clean the private
stage; SIGKILL or power failure may leave a private `.<selected-prefix>.stage-*` sibling which
can be inspected and removed without changing another version. Uninstall refuses
modified/extra files, symlinks or a wrong externally pinned receipt; move personal
files out first, then restore the exact installed bytes if removal is intended.
It retains projects, shared prerequisites, sibling SDKs and rustup configuration.
The owner must exclude concurrent writes by the same user while verifying,
building or uninstalling. This is not a hostile same-user sandbox. To restore a
removed version, reuse the same authenticated `BUNDLE` and external `POLICY`,
verify and install again at the same prefix, and provide a fresh unused external
`--receipt-pin` path. Keep the prior receipt pin; it remains outside the
installation and is not overwritten by uninstall or restoration.

Missing or altered prerequisites: prepare a fresh STATE against the
authenticated host profile. An ambient Cargo configuration: choose a private output
root outside its ancestry. Unsupported host/compiler/profile: stop; do not
override the compatibility gate. Fabian Schmieder owns maintenance and upgrade
qualification; no support duration or public security endpoint is promised.
