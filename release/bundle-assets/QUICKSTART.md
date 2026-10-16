# ami-rust production installation recipe

This recipe applies to the first PC x86-64 AROS ABI-v1 SDK candidate, version
`0.1.0`. A protected CI candidate is not an accepted public release. Use a
version as supported only after its R1 acceptance and public replay are recorded.

Obtain the installer/verifier digests and an external publisher policy from an
independently trusted source. Keep the policy, GH/Cosign verifier executables
and trusted roots outside the downloaded candidate. The policy pins the exact
`metaneutrons/ami-rust` source and `.github/workflows/sdk-qualify.yml` commit,
protected `main` ref, Actions OIDC issuer, certificate identity, input-manifest
digest, supported host profiles, verifier executables and trusted roots.
The installer checks real GitHub attestations and Cosign bundles offline before
installation. A bundled policy or disposable test signer cannot establish trust.

Provision the six exact host prerequisites and the selected Python before these
commands. A local `selection.json` declares `python`, `components` (rust, cargo,
toolchain, collector, csdk, vendor), and the profile's Cargo/collector paths.
It contains consumer-local paths; no development-machine paths are shipped.
Provisioning is explicit and separate from offline build replay. The installer
verifies all declared release assets, archive members, publisher signatures and provenance before
extracting. Project-lock verification additionally checks the complete declared
prerequisite inventories and interpreter identity.

The following commands are the delivered recipe on both supported hosts. Use
the pinned interpreter path as PYTHON; WORK is a fresh, private, user-owned
directory outside any `.cargo/config` ancestry. Set the four paths explicitly
in your shell (no global environment or rustup setting is changed):

```sh
PYTHON=/absolute/path/to/pinned/python
BUNDLE=/absolute/path/to/verified-candidate
POLICY=/absolute/path/to/independently-pinned-publisher-policy.json
WORK=/absolute/path/to/fresh-private-working-directory
```

The qualification driver supplies those paths explicitly and runs every command
below without alteration. `receipt.sha256` is saved outside the installed prefix.
`selection.json` is the explicitly provisioned host profile.

```sh
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" verify --bundle "$BUNDLE" --policy "$POLICY"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" install --bundle "$BUNDLE" --policy "$POLICY" --prefix "$WORK/sdk-0.1.0" --receipt-pin "$WORK/receipt.sha256"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/sdk-0.1.0/sdk" --output "$WORK/utility.lock.json"
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/utility-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-sha256sum --release --locked --offline
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-noalloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-alloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline --features alloc
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/qualification-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-qualification --release --locked --offline
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/dependencies-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-dependencies --release --locked --offline
"$PYTHON" -I -B "$BUNDLE/new_project.py" --sdk "$WORK/sdk-0.1.0/sdk" --output "$WORK/hello-aros" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/hello-aros" --output "$WORK/hello.lock.json"
"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/hello.lock.json" --output-dir "$WORK/hello-build" -- build --manifest-path "$WORK/hello-aros/Cargo.toml" --package hello-aros --release --locked --offline
"$PYTHON" -I -B "$BUNDLE/install_publisher.py" uninstall --prefix "$WORK/sdk-0.1.0" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"
```

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
bounded by the delivered `SDK-API.md`. Panic aborts the current
application path; allocation failure is an explicit error where the API exposes
it. `std`, networking, a compiler running on AROS, other ABI/CPU/OS combinations
and physical hardware are excluded. No arbitrary crate compatibility is claimed.

Install versions side by side. Verification failures and interrupted staging do
not replace an old installation. SIGTERM/ordinary exceptions clean the private
stage; SIGKILL or power failure may leave a private `.<selected-prefix>.stage-*` sibling which
can be inspected and removed without changing another version. Uninstall refuses
modified/extra files, symlinks or a wrong externally pinned receipt; move personal
files out first, then restore the exact installed bytes if removal is intended.
It retains projects, shared prerequisites, sibling SDKs and rustup configuration.
The owner must exclude concurrent writes by the same user while verifying,
building or uninstalling. This is not a hostile same-user sandbox.

Missing or altered prerequisites: repeat explicit provisioning against the
signed host profile. An ambient Cargo configuration: choose a private output
root outside its ancestry. Unsupported host/compiler/profile: stop; do not
override the compatibility gate. Fabian Schmieder owns maintenance and upgrade
qualification; no support duration or public security endpoint is promised.
