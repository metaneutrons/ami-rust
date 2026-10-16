# Pinned build prerequisites

**The APL-covered source for the original and portable C-SDK archives is
available under APL 1.1.** Read the conspicuous
[source-availability notice](../portable-csdk/SOURCE-AVAILABILITY.md),
[complete licence](../portable-csdk/APL-1.1.txt) and dated
[modification record](../portable-csdk/CHANGES.md) before redistribution.
The modifications derive from Original Code provided by the AROS Development
Team (Initial Developer). Other components retain their original licence terms.

`csdk.tar.xz` is the unchanged original prerequisite;
`portable-csdk.tar.xz` is the separately identified source-derived candidate.
Their exact hashes, profiles, corresponding source and patch series are pinned
by [the portable C-SDK specification](../portable-csdk/spec.json).
`vendor.tar.xz` is the locked Cargo vendor input pinned by
[ci-sdk-inputs.json](../ci-sdk-inputs.json).

These are repository inputs for building and qualifying ami-rust. An SDK release
requires its own completed release gates and authenticated distribution.
