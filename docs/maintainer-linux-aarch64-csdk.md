# Linux ARM64 C-SDK candidate qualification

This internal workflow produces the portable C-SDK prerequisite on a standard
Ubuntu 24.04 ARM64 GitHub runner. It does not admit Linux ARM64 to the released
SDK, publish a package, or change the qualified x86-64 AROS ABI-v1 baseline.
SDK host admission remains a separate L1/RC2/RC3 decision.

First require successful normal PR checks, including the Linux composed
supervisor/producer/compiler cleanup fixture. Merge through normal protection.
Then run this command from the exact merged source checkout:

```sh
gh workflow run csdk-linux-aarch64-producer.yml --repo metaneutrons/ami-rust --ref main
```

Retain the returned run ID and bind its source commit, attempt, original artifact
ZIP size and API digest. A terminal failed run remains failed; fix its source or
inputs before starting a separately identified campaign. Do not retry or relabel
the original result. Check a native run at intervals of at least 30 minutes.

The workflow requires protected `main`, verifies the pinned LLVM and collector
distribution, checks source identities and capacity, and applies the existing
5,400-second campaign, 300-second review reserve, 4 GiB aggregate RSS, 12 GiB
workspace, 16 MiB logs and 1,200-second command budgets. The producer has an
earlier work cutoff and ordered cleanup reserves inside that campaign. Failure
and incomplete-cleanup receipts remain part of the evidence.

Before LLVM acquisition, the driver checks all native host prerequisites:
`cc` (including an AArch64 `-dumpmachine` result), `cmake`, `pkg-config`,
`perl`, `git`, and the fixed `/usr/bin/patch`. Relative names use only the
controlled `/usr/local/bin:/usr/bin:/bin` search path. Each selected executable
has a recorded resolved path, byte identity, and version; successful production
also requires unchanged executable identities. Ambient `PATH` entries are not
fallbacks. Retain the runner image identity with those observations; a missing
tool is a prerequisite failure and does not qualify a C-SDK candidate.

After success, independently verify the original artifact and complete producer
receipts, source and license inventories, C-SDK profile and file identities,
resource records and cleanup. Compare the target content under the existing
reproducibility contract. Only then derive a new SDK input identity and run the
full application, relocation, AROS runtime/memory and distribution gates.

The internal supervision still uses Python temporarily. This workflow is not
RC4/RC5 Python-retirement evidence. Original inputs, historic producer receipts,
and old releases remain immutable.
