# Target-facing Cargo metadata recipe

This recipe keeps target artifact identities reproducible across macOS ARM64,
Linux x86-64 and Linux ARM64 without rewriting compiler output.

For explicit cross builds, target symbol metadata consumes a sorted projection
of reachable native host-unit identities. The projection retains package,
source, version, features, profile, compilation mode, target kind, compiler
release and standard-library role. Target dependencies remain bound to their
actual target metadata. Native builds retain Cargo's upstream behavior.

Before using the recipe, the producer verifies every original and patched file
against `source.json`. Ambiguous projected native-unit descriptors fall back to
their original metadata under a separate domain. Cache identities continue to
bind the complete dependency graph and the recipe version.

The producer must still qualify build scripts, proc macros, relocation, cache
behavior and complete target bytes on every supported host. This recipe alone
does not establish release acceptance.
