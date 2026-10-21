# ami-rust package installation

> **Historical 0.1.0 interface.** These commands describe the immutable released
> packages, not the current development tree. Their CLI implementation has been
> retired here. Use the [released source](https://github.com/metaneutrons/ami-rust/tree/v0.1.0)
> for historical replay. The next release uses rustup, normal Cargo and crates;
> see the migration plan and issue #72.


This package delivers SDK 0.1.0, packaging revision 2, for native PC x86-64
AROS ABI-v1. The supported development hosts are Ubuntu 24.04 x86-64 and macOS
26 on Apple Silicon. APT and Homebrew availability is recorded in the
repository's distribution status; building this package is not publication.

Installation puts the launcher, original SDK release assets and publisher proofs
under package-manager ownership. It runs no compiler build or network download
as root. The first use needs one explicit preparation step as your normal user.
Allow 6 GiB physical RAM and 24 GiB free disk on the preparation volume.

Choose a fresh state directory and fresh project/build destinations. The state
parent must exist; all paths below are ordinary user choices. For example:

```sh
STATE="$HOME/ami-rust-0.1.0-state"
PROJECT="$HOME/hello-aros"
BUILD="$HOME/hello-aros-build"
ami-rust verify-package
ami-rust prepare --state "$STATE"
ami-rust new --state "$STATE" --project "$PROJECT"
ami-rust build --state "$STATE" --project "$PROJECT" --output-dir "$BUILD"
```

Preparation fetches the exact pinned publisher source and standalone Python,
authenticates the original SDK assets with the original GitHub/Sigstore verifier,
and provisions the pinned compiler, Cargo and C SDK through the unchanged SDK
helpers. Publisher proofs are included: no GitHub login/token is required.
The subsequent build uses locked offline inputs. The generator names the crate
`hello-aros`; choose another existing package with `build --package NAME`.
Additional Cargo feature options can follow `--` on the build command.

The native executable is `BUILD/artifacts/AMIRUST`, with the build receipt and
ELF audit beside the artifacts directory. It targets AROS; it is not a host
macOS/Linux executable. The qualified runtime is the fixed 512 MiB x86-64 ABI-v1
QEMU profile. No physical-hardware, other CPU/ABI, networking, GUI, full `std`
or AROS-hosted compiler support is added by package installation.

Package removal and upgrades preserve the state, projects and global Rust
configuration. Prepared states retain their own launcher and pinned interpreter:

```sh
"$STATE/retained/bin/ami-rust" build --state "$STATE" --project "$PROJECT" --output-dir "$HOME/hello-aros-rebuild"
"$STATE/retained/bin/ami-rust" check-inputs --state "$STATE"
```

This also keeps locked old projects usable after a package-manager Python or
SDK upgrade. A new SDK version needs a separate preparation state; it never
silently changes an old project's compiler. Removing user state is a separate,
deliberate user action. Failed preparation preserves its directory for diagnosis;
retry in a fresh state rather than modifying pins or replacing its components.

The adapter code is MIT OR Apache-2.0. The original SDK has its own complete
SPDX inventory, custom third-party licences, notices and corresponding-source
archives inside the preserved release payload. Those terms remain unchanged.
