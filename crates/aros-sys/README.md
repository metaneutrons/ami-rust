# aros-sys

Raw, allocation-free Rust declarations and calls for x86-64 AROS. The existing
native bridge remains the qualified ABI-v1 application boundary. Additional
raw modules expose an initial non-variadic library surface:

- `exec`: libraries, signals, message ports and messages;
- `dos`: files, locks, directory iteration, errors and path handling;
- `utility`: tag-list traversal;
- `intuition`: windows and BOOPSI object attributes.

The generated vector backends support the ABI-v1 base-last contract and the
ABI-v11 `r12` library-base contract. They are checked against both pinned SDKs;
the BOOPSI `DoMethodA`, `DoSuperMethodA`, and `CoerceMethodA` adapters and both
ABI paths have completed the native M3 qualification recorded in
[`docs/m3-qualification.md`](../../docs/m3-qualification.md). The reviewed
allowlist, generator instructions and input hashes live in `bindings/` at the
repository root.

The package-level `LICENSE` and `MODIFICATIONS.md` preserve the AROS Public License 1.1 scope and source history. The separate MIT and Apache license files apply to original ami-rust contributions only to the extent stated in the composite license.
