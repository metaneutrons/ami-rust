# AROS-derived interface modifications

Original Code: the AROS Development Team's native ABI declarations in
compiler/include/exec/nodes.h, exec/lists.h, exec/libraries.h, exec/ports.h,
dos/dos.h and aros/types/spinlock_s.h, at AROS-NX commit
e0d5e367d15cc7da4ebac8f9db17868756c79569. Their full original source/notices
are provided in the accompanying AROS source archive under the AROS Public
License 1.1. All six hashes match the qualified Developer SDK copies.

2026-10-14: Fabian Schmieder's ami-rust implementation translated the selected
structures/types into Rust repr(C) declarations and added a bounded bridge ABI,
layout oracle values and SDK entry points. Revisions preserved unsigned native
string pointer types and the qualified task/lifetime contracts.

2026-10-15: the retained implementation added the qualified borrowed stderr
boundary. Packaging now records the applicable AROS scope explicitly without
changing executable Rust/C implementation bytes. Source licensing notices and
the modification record accompany every SDK source copy.

2026-10-29: the reviewed API allowlist added generated raw Rust vector calls
for selected Exec, DOS, Utility and Intuition functions. Separate x86-64
backends implement the ABI-v1 base-last convention and Deadwood AROS ABI-v11
2026.09 `r12` library-base convention. The committed provenance record hashes
all consulted `clib` and `defines` headers; no generated SDK source is required
by consumers.

Covered Code and its modifications remain subject to AROS Public License 1.1;
the original ami-rust additions also have the owner-selected MIT OR Apache-2.0
grant to the extent that this does not relicense or restrict AROS Covered Code.
