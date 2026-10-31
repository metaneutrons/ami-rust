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
  result. `aros` and `aros-mui` deny `missing_docs` and broken intra-doc links.
- **Versions.** The site publishes one version per release plus `/next/`. A release's docs are built from its **release tag**, so they document what the release shipped and never change afterwards. Versions are discovered from the tags: a `vMAJOR.MINOR.PATCH` tag whose tree contains `website/` is published, and the newest is `latest`, served at the site root. There is no list to maintain. The only exception is `legacy` in `website/versions.json`: 0.1.0, whose tag predates the site, is built from `release/0.1`. A legacy entry needs a reason and is rejected if the tag does contain the site (`pnpm --dir website run test` covers the rules). The base path, version metadata and the version switcher are added at publication time by `website/scripts/assemble-site.mjs`, so old tags get them too.
  - *Publishing.* The Documentation workflow runs on `main` after the "Protected toolchain release" workflow succeeds, when the tag exists, and rebuilds every version. It can also be run manually.
  - *Release steps for the docs.* The release tag is created from `main`'s HEAD, so the docs must be right before the release is published. Docs name releases by tag and never by commit hash (a commit cannot contain its own hash): `tag = "vX.Y.Z"` in Cargo snippets, which `check` verifies. Update the version literals (`cargo +X.Y.Z`, `toolchain=`, `version=`, `channel =`, the tag links, the `catalog_commit` of the reviewed catalog, and the table in `docs/releases.md`) before publishing; `check` prints a warning for each literal that differs from `version.txt`. For example: `grep -rnE 'cargo \+[0-9]|toolchain=[0-9]|version=[0-9]|channel = "[0-9]|tag = "v[0-9]' docs`.
  - *A mistake in a published release's docs* is fixed in the next release. If it cannot wait, cut a patch release; the tag is immutable, so the old docs are not edited.
  - *Building every version locally*: `node website/scripts/assemble-site.mjs --out "$(mktemp -d)/site" --host "$(rustc -vV | sed -n 's/host: //p')"`, then `node website/scripts/check-assembled.mjs` on the result. The `/next/` build uses your working tree.
- **Formatting.** `cargo fmt --all --check` is clean for the root workspace and, with `--manifest-path tooling/Cargo.toml`, for the tooling workspace. The generated MUI sources are excluded with `#[rustfmt::skip]` on their `mod` declarations, because `check mui` compares them byte for byte.
- **ABI.** Items declared for only one ABI must say so in their docs
  (`Available on ABI-v1 targets only.`). The reference generator fails when
  that sentence disagrees with the two compiled builds.
- **Examples.** Rustdoc examples are written as `ignore` blocks that form the
  body of a function with `context: &aros::Context` in scope. Run
  `node tools/check-doc-examples.mjs WORK_DIR` with the 0.1.0 toolchain
  installed to compile them, and the complete programs in the guides, for both
  targets.
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
