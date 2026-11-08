# Contributing

Use a focused branch and a Conventional Commit title. Repository text, commit
messages, pull requests, and issues are English. Do not add AI attribution
trailers.

The public interface is rustup plus Cargo. Changes must not introduce an
`ami-rust` CLI, a Cargo wrapper, or a Python execution path. Preserve the AROS
x86-64 ABI-v1 baseline and keep AROS-NX and aros-tools outside this repository.

Substantial initiatives keep their normative requirements in `docs/plans/`.
The linked epic and milestone issues record execution state and evidence rather
than duplicating acceptance criteria.

Run the Rust maintainer workspace through the same pinned bootstrap used by CI:

```bash
set -euo pipefail
repo=$(pwd -P)
root=$(mktemp -d)
root=$(cd "$root" && pwd -P)
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
bash tools/build-maintainer-task.sh "$root/maintainer" "$host"
work="$root/maintainer"
toolchain="$work/bootstrap/toolchain"
mkdir -m 700 "$work/test-target"
env -i \
  HOME="$work/home" TMPDIR="$work/tmp" \
  PATH="$toolchain/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/test-target" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  RUSTC="$toolchain/bin/rustc" RUSTDOC="$toolchain/bin/rustdoc" \
  RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' \
  LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
  "$toolchain/bin/cargo" test --workspace --all-targets --locked --offline \
    --manifest-path "$repo/tooling/Cargo.toml" -j 2
```

Local success covers repository tooling only. Protected three-host production,
publisher provenance, native AROS execution, and exact-candidate acceptance are
independent release gates.

Do not commit credentials, private signing keys, local paths, generated SDK
archives, or local qualification output. New third-party inputs require their
licence, source identity, digest, and corresponding-source record.

## Test programs, scripts and release evidence

A test program or script that nothing builds, runs or checks looks like coverage and is not, so none may stay.

- **Programs.** Every program under `tests/`, `examples/` and `release/` (a directory with a `Cargo.toml`) is listed in `tests/programs.json` with how it is shown to work: the qualification fixture and its modes, the applications that run on AROS, the compile-fail fixtures, or a host check. A program that is not finished yet can be listed under `in_development` instead, with the open issue that owns it (`"issue": "#66"`) and the reason that the matrix cannot run it yet. The release evidence does not cover it, but CI and the release workflow check that its owning issue is still open: when the issue closes, the program is either finished and moves to `applications`, or it is deleted. A program builds with `aros_native_build::prepare`, reads no environment variable of a retired setup, and pins the `aros` crates to the current version, whether it is in development or not. Nothing sits loose in `tests/`, and there is no `scripts/` directory.
- **Scripts.** Every script in `tools/` is run by a workflow, called by another script, named in `tests/programs.json`, or is a test that `node --test tools/` runs. A workflow line that only lists a path filter does not count.
- **The check.** `node tools/check-orphans.mjs` enforces all of this. CI runs it on every change, and the release workflow runs it before it publishes. When you remove a feature, remove its program and scripts in the same pull request. A program or script that is no longer wanted is deleted, not parked.
- **Native evidence.** A release needs `docs/evidence/native-<version>.json`: every fixture mode on both ABIs, every application on both ABIs, every compile-fail fixture and every host check, each with the result the manifest expects. `node tools/native-matrix.mjs --toolchain NAME --runner PATH ...` builds and runs them with the installed toolchain of the release and writes the file; the runner is the emulator wrapper described at the top of the script. `node tools/check-orphans.mjs --evidence` verifies the file, and the release workflow refuses to publish without it. A new program, mode or check is therefore part of the next release's evidence as soon as it is listed.

## Documentation

The site lives in `website/` (Astro and Starlight) and publishes the pages
under `docs/`. Hand-written pages are listed in
`website/src/content.config.ts`; internal records such as the qualification
documents are deliberately not published.

- **Page rules.** The page title is the frontmatter `title`; do not add a
  leading `# Title`. Link to other pages with root-relative paths such as
  `/run-on-aros/`, never with the absolute site URL. Do not mention internal
  milestone names. `pnpm --dir website run check` enforces these rules.
- **API reference.** `docs/reference/` is generated from the crates' Rustdoc by
  `tools/generate-astro-api.sh` and is not committed. Fix wording in the Rust
  source. For generated MUI items that means `tooling/crates/xtask/src/
  mui_safe_codegen.rs`; then run `cargo xtask generate mui` and commit the
  result. Every published crate denies `missing_docs` and broken intra-doc links
  and has a guide page; `node tools/check-docs-policy.mjs` checks both.
- **Versions.** The site publishes one version per release plus `/next/`. A release's docs are built from its **release tag**, so they document what the release shipped. A mistake in them is corrected on a documentation branch (see below), never by changing the tag. Versions are discovered from the tags: a `vMAJOR.MINOR.PATCH` tag whose tree contains `website/` is published, and the newest is `latest`, served at the site root. There is no list to maintain. There are two exceptions, both in `website/versions.json`: `legacy`, for 0.1.0, whose tag predates the site and which is built from `release/0.1`, and `corrections` (below). Each entry needs a reason; a legacy entry is rejected if the tag does contain the site (`pnpm --dir website run test` covers the rules). The base path, version metadata and the version switcher are added at publication time by `website/scripts/assemble-site.mjs`, so old tags get them too.
  - *Publishing.* The Documentation workflow runs on `main` after the "Protected toolchain release" workflow succeeds, when the tag exists, and rebuilds every version. It can also be run manually.
  - *Release steps for the docs.* The release tag is created from `main`'s HEAD, so the docs must be right before the release is published. Docs name releases by tag and never by commit hash (a commit cannot contain its own hash): `tag = "vX.Y.Z"` in Cargo snippets, which `check` verifies. Update the version literals (`cargo +X.Y.Z`, `toolchain=`, `version=`, `channel =`, the tag links, the `catalog_commit` of the reviewed catalog, and the table in `docs/releases.md`) before publishing; `check` prints a warning for each literal that differs from `version.txt`. For example: `grep -rnE 'cargo \+[0-9]|toolchain=[0-9]|version=[0-9]|channel = "[0-9]|tag = "v[0-9]' docs`.
  - *A mistake in a published release's docs* is corrected on a branch `release/MAJOR.MINOR` that contains the release tag and changes nothing but documentation. Create it from the tag (`git switch -c release/0.2 v0.2.0`), cherry-pick the fixes from `main` (only `docs/`, `website/`, `README.md` and `CONTRIBUTING.md` may change), push it, and name it under `corrections` in `website/versions.json` with a reason, in a pull request to `main`. The tooling refuses a branch that lacks the tag or changes any other file, so the documentation still describes exactly what was released and the release's bytes and tag never change. Later fixes need only a push to the branch and a manual run of the Documentation workflow, because that workflow deploys from `main`. A mistake in shipped code or bytes is still a new patch release.
  - *Building every version locally*: `node website/scripts/assemble-site.mjs --out "$(mktemp -d)/site" --host "$(rustc -vV | sed -n 's/host: //p')"`, then `node website/scripts/check-assembled.mjs` on the result. The `/next/` build uses your working tree.
- **Formatting.** `cargo fmt --all --check` is clean for the root workspace and, with `--manifest-path tooling/Cargo.toml`, for the tooling workspace. The generated MUI sources are excluded with `#[rustfmt::skip]` on their `mod` declarations, because `check mui` compares them byte for byte.
- **ABI.** Items declared for only one ABI must say so in their docs
  (`Available on ABI-v1 targets only.`). The reference generator fails when
  that sentence disagrees with the two compiled builds.
- **Examples.** Rustdoc examples are written as `ignore` blocks that form the
  body of a function with `context: &aros::Context` in scope. Run
  `node tools/check-doc-examples.mjs WORK_DIR` with the toolchain of the
  release installed to compile them, and the complete programs in the guides,
  for both targets. The native evidence of a release includes this check.
- **Native bridge changes.** The bridge sources are `tooling/crates/aros-native-build/native/*`. The installed toolchain's `aros-link` refuses a bridge that differs from the copy it was built with, so a change cannot be tried with a released toolchain. For local work, copy an installed toolchain (`cp -Rc`), build `aros-link` from `tooling/` (`cargo build --release -p aros-native-build --bin aros-link`), replace both `bin/aros-link` and `lib/rustlib/<host>/bin/aros-link` in the copy, link it with `rustup toolchain link`, and build with `cargo +<name>`. A change of a target specification (`targets/*.json`) also needs the two files `lib/rustlib/<target>/<target>.json` and `target.json` of that target in the copy replaced, because `aros-link` checks them against its embedded pins. Delete the staged `ami-native` directories of earlier builds when the source changes. Such a change reaches users with the next toolchain release.
- **Updating the `std` patch.** `host/std-aros/std-aros.patch` is applied by the toolchain producer to its private copy of the pinned `rust-src`, in process, and every file must match `host/std-aros/source.json`. After a change: regenerate the patch as a git-style diff of whole files against the pinned `rust-src`; update `source.json` (the patch digest and the before and after digest of every changed file) and the digest in `host/std-aros/README.md`; update `bytes` and `sha256` of the two inputs `std-aros-patch` and `std-aros-source` in `release/rust-production-contract.json`. The libraries then change, so build them: the workflow "Target library check" builds them on the three hosts and uploads `proposed-pins` for each; commit the six pin files in `tooling/crates/aros-native-build/pins/` from those artifacts and never edit one by hand. Then update the digest constants of `tooling/crates/xtask/src/native_prefix_compose.rs` (`*_TARGET_LIBRARIES_SHA256`, and the `EXPECTED_*` constant of any source file that changed; the test `current_candidate_source_is_admitted` names the first stale one). To try a change on the local host, build the maintainer task with `tools/build-maintainer-task.sh`, acquire the inputs of the host from the contract, run `ami-rust-xtask toolchain-producer` as in `.github/workflows/toolchain-libraries-check.yml`, and run `node tools/check-target-libraries.mjs` on `bare-output-<target>/libraries` of its work directory.
- **Node.** The site tooling targets Node 26, the version CI uses (`engines` in `website/package.json`). `node --test` is given explicit files rather than a directory because directory arguments behave differently across Node versions.
- **Local build.**

  ```sh
  pnpm --dir website install --frozen-lockfile
  bash tools/generate-astro-api.sh "$(mktemp -d)/api" "$PWD/docs/reference" "$(rustc -vV | sed -n 's/host: //p')"
  pnpm --dir website run build
  pnpm --dir website run check
  pnpm --dir website run a11y
  pnpm --dir website run mobile   # needs Chrome; set CHROME_BIN if it is not on the usual path
  ```
