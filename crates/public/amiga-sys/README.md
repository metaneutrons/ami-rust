# amiga-sys

Local compatibility facade that re-exports the raw declarations from `aros-sys` for the selected native x86-64 AROS ABI-v1 profile. Calls at this boundary remain unsafe. This package remains unpublished: the 2026-10-21 namespace survey recorded the crates.io name `amiga-sys` as registered to an unrelated project and is excluded from this repository’s release package set. Consumers that need the raw ABI should depend on the intended public crate `aros-sys`. Other Amiga-compatible systems and ABI profiles are outside the qualified scope.
