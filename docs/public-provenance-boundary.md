# Public source CI and release provenance

The public repository is a clean source export with a new Git history. Its
initial commit does not contain the private development repository's history,
qualification records, host selection files, build logs, or SDK archive. The
source manifest records the SDK source identity and base archive digest; a
separate local export record maps those inputs to the public commit and tree.

The public CI workflow runs only synthetic installer regression fixtures on
Ubuntu 24.04 and macOS 15. Its disposable OpenSSH keys are test fixtures. A test
signature does not identify the ami-rust publisher, authenticate a release, or
close R1-A6. CI has no signing key, OIDC permission, release trigger, or upload
step.

The R1 final SDK producer remains a separate protected workflow. Reproduction
there requires the six qualified external prerequisites and their pinned
producers: Rust, custom Cargo, the AROS toolchain, the collector, the AROS C
SDK, and the vendor tree. Those inputs must be independently authenticated and
available to protected CI before that workflow can reproduce the candidate.
This source workflow neither downloads nor vendors those prerequisites and
makes no claim that the R1 final SDK producer is ready.
