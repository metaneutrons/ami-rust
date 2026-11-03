# aros-sys

Raw, allocation-free Rust declarations and calls for x86-64 AROS. The native
bridge supports the qualified `x86_64-unknown-aros-abi1` and
`x86_64-unknown-aros-abi11` targets. Ten raw modules expose 100 non-variadic
library calls, one function per vector:

- `exec`: libraries, signals, message ports and messages;
- `dos`: files, locks, directory iteration, errors and path handling;
- `utility`: tag-list traversal;
- `graphics`: bitmaps, rastports and drawing;
- `intuition`: windows, public screens and BOOPSI object attributes;
- `asl`: the file requester;
- `locale`: locales and message catalogs;
- `icon`: disk objects and tool types;
- `workbench`: application windows, icons and menu items;
- `timer`: `timer.device` access.

The crate also declares the native records the safe crates read and the 118
functions of the native C bridge. Every public item is documented.

The generated vector backends support the ABI-v1 base-last contract and the
ABI-v11 `r12` library-base contract. They are checked against both pinned SDKs;
the BOOPSI `DoMethodA`, `DoSuperMethodA`, and `CoerceMethodA` adapters and both
ABI paths have completed the native M3 qualification recorded in
[`docs/m3-qualification.md`](../../docs/m3-qualification.md). The reviewed
allowlist, generator instructions and input hashes live in `bindings/` at the
repository root.

The package-level `LICENSE` and `MODIFICATIONS.md` preserve the AROS Public License 1.1 scope and source history. The separate MIT and Apache license files apply to original ami-rust contributions only to the extent stated in the composite license.
