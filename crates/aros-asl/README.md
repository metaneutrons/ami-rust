# aros-asl

The `asl.library` file requester for the selected AROS ABI profile. `Asl::open`
owns the library reference, `FileRequestBuilder` describes the requester with a
tag list built on the stack, and `FileRequester::request` shows it and returns
`Outcome::Accepted` with the selected paths as owned `AslPath` values, or
`Outcome::Cancelled`. A parent `aros-intuition` window can be given; it sleeps
while the requester is open.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. The native bridge reads the requester's result and records
every requester, so a forgotten requester is freed when the program ends.
