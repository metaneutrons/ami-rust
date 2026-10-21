# ami-rust-sha256sum

A read-only SHA-256 command-line example for the ami-rust runtime.

The app skips argv[0] and accepts one or more byte paths, including paths
containing spaces, subject to the SDK limit of 127 path bytes. For each readable
file it prints the 64-character lowercase SHA-256 digest, two spaces, the original
path bytes, and a newline. Inputs are opened with ReadExisting, read through one
4096-byte heap buffer, and never modified.

A file open, read, close, or path error sets the final status to 10 while later
paths are still processed. A stdout error also returns status 10. Invoking the
app without file paths reports usage on stderr and returns status 10. File,
stdout and buffer-allocation errors also go to the borrowed DOS error stream;
if the process has no error handle, the SDK uses its output handle. Error lines
include the raw path where applicable, signed native error, class and operation.
Serial runtime diagnostics remain available for qualification. A failed stderr
write is logged serially without recursively writing another stderr error.

Pure formatting tests cover lowercase digest output, paths with spaces, the SDK
path-length bound, signed native error boundaries and raw non-UTF-8 path bytes.
The package is a workspace member. The retained development native stderr probe
checks actual separate stdout/stderr, usage and missing-file behavior on the
pinned ABI-v1 image. The retained R1 application/error/memory evidence predates this ordinary Cargo package-integration candidate and does not qualify its package/archive path.
## Ordinary Cargo integration boundary

This package is a development candidate for ordinary Cargo binary integration. Its additive build script requires the pinned `x86_64-aros` target-library candidate and exact `aros-native-build = 0.2.0-dev` host helper. The helper remains an in-workspace `publish = false` crate and currently admits macOS AArch64 and Linux x86_64 only. Private package/archive checks and macOS Cargo builds are recorded in [the development evidence](../../docs/evidence/rc2-cargo-reference-packages-development-20261022.json). They do not replace the outstanding three-host runtime qualification; Linux AArch64 host admission is still missing.
