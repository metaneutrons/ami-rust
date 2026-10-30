---
title: M2 MUI API model evidence
---

# M2 MUI API model evidence

This record applies the M2 criteria in `docs/plans/ami-rust-0.1.md` to the
canonical files under `bindings/mui/`. GitHub issue #8 owns the execution state;
the plan remains the acceptance authority.

## Inputs and scope

- ABI1: `metaneutrons/AROS-NX` commit
  `e0d5e367d15cc7da4ebac8f9db17868756c79569`.
- ABI11: `deadwood2/AROS` commit
  `fbc242c1046cffb5e5827a4626ee62bdd45664e9`.
- Entry point: `workbench/libs/muimaster/mui.h` at each commit.
- Selection: the complete transitive quoted-include closure inside the
  muimaster source root. Private and internal headers are refused if that public
  closure reaches them.
- Superclasses: built-in class descriptors from every class implementation at
  the same commit. `MUIC_Scrmodelist` is the sole reviewed exception because it
  has no descriptor and is a special `MUIC_List` class.

The ABI1 closure has 70 public headers; the ABI11 closure has 68. ABI1 alone
includes `classes/panel.h` and `classes/panelgroup.h`, exposing `MUIC_Panel`,
`MUIC_PanelTitle`, `MUIC_PanelGroup`, and `MUIC_DragHandle`. The canonical model
keeps the ABI surfaces separate rather than presenting those symbols as ABI11.

## Inventory result

The deterministic model contains these occurrence counts across both ABIs:

| Category | Count |
| --- | ---: |
| Classes with superclass relation | 140 |
| Attributes | 917 |
| Methods | 400 |
| `MUIV_*` values | 177 |
| Identifier bases | 129 |
| Other macros, including constructor helpers | 1,076 |
| Preprocessor guards | 138 |
| Enum values | 314 |
| `MUIP_*` message structures | 385 |
| Lines carrying a private marker | 474 |

An independent source-to-model comparison found no missing or additional macro
occurrences: ABI1 has 1,515 in both views and ABI11 has 1,462. The same
comparison found 195 message structures in both ABI1 views and 190 in both
ABI11 views. Private-marker line counts also match: 239 for ABI1 and 235 for
ABI11.

## Acceptance probes

- Positive: `generate mui` completed for both pinned Git objects and `check
  mui` reproduced the committed `api.json` and `provenance.json` bytes.
- Stale counter-probe: after changing an isolated generated copy, `check mui`
  exited unsuccessfully and identified the stale file.
- Grammar counter-probe: the parser rejects a conditional expression containing
  `? :` as unsupported instead of silently emitting a guessed value.
- Parser tests cover identifier arithmetic, integer casts, unresolved external
  identifiers, explicit unsupported syntax, and stale-output rejection.

These probes qualify model generation only. They do not claim that M3 Rust
bindings or M4 safe wrappers have been generated.
