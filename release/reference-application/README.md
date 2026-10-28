# Native reference application release recipe

This is an internal Cargo consumer recipe for the separately shipped x86-64
AROS ABI-v1 SHA-256 reference application. It adds no host-side CLI or SDK
manager. The SDK's compiler, libraries, source identity and rustup catalog stay
unchanged.

`inputs.json` pins the Git/source and recipe hashes and the exact executable
already exercised by the native runtime/memory campaign. The release helper
uses the admitted SDK, fetches locked dependencies, builds offline with ordinary
Cargo and refuses a different executable. No finished binary is rewritten.

The private consumer package retains version `0.0.0`, the identity used for the
qualified Git-dependency application. This is a build identity, not the SDK's
release version or a crates.io publication. Program source comes from the
separately selected SDK source commit's `examples/sha256sum/src/main.rs`.

The host Cargo configuration, including its host-only prefix mappings, is part
of that recipe. `@WORK@` and `@SDK_PREFIX@` are substituted only into the private
build configuration. The application archive contains `SHAUTIL`, the project
MIT/Apache notices, the original SDK notice collection and source locators.
It has its own SHA-256, SPDX document, Sigstore signature and joint provenance
subject in the v3 release inventory. Historical v2 inventories remain readable
with their original 87-file meaning; new v3 candidates have 90 files.

Producing an archive does not authorize a release. Protected signing/staging and the
actual public consumer routes still have their own existing release criteria.
