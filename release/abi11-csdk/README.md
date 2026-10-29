# ABI11 C SDK release input

`abi11-csdk.tar.xz` is the minimal ABI11 C-SDK subset required by the ami-rust
native bridge. It is selected from the official AROS ABI-v11 SDK release and is
stored as a reproducible repository input; it is not generated during a release
job.

Upstream input:

- release: `ABIv11_2026.09`
- asset: `SDK-202609-any-x86_64.zip`
- URL: `https://github.com/deadwood2/AROS/releases/download/ABIv11_2026.09/SDK-202609-any-x86_64.zip`
- bytes: `273594897`
- SHA-256: `8a4e5f09f027844501c1421bd3948c4e55ceb005a16b0bd3575276f40c8977e6`

The committed profile selects 182 SDK headers, `startup.o`, and the 31 static
libraries used by the fixed ABI11 link recipe. The Clang-provided `stdarg.h`
dependency remains part of the pinned LLVM toolchain and is not duplicated.
All 214 archive members and their identities are recorded in `profile.json`.

Archive construction is deterministic: GNU tar `1.35`, ustar format, sorted
members, timestamp `1791936000`, numeric owner/group `0`, normalized
`u=rwX,go=rX` modes, and single-threaded xz output from GNU tar.

AROS source and SDK files retain their upstream licence terms. The exact
upstream source release is the corresponding source for this unmodified byte
selection.
