# Changelog

All notable changes to ami-rust will be documented here.

## [0.2.0](https://github.com/metaneutrons/ami-rust/compare/v0.1.0...v0.2.0) (2026-11-04)


### Features

* **aros:** 64-bit file sizes and positions through dos64.library ([#83](https://github.com/metaneutrons/ami-rust/issues/83)) ([573effc](https://github.com/metaneutrons/ami-rust/commit/573effce38c940c082222ab9a22477e16b799985))
* **aros:** directories, variables, current directory and argument templates ([#79](https://github.com/metaneutrons/ami-rust/issues/79)) ([f55e039](https://github.com/metaneutrons/ami-rust/commit/f55e039ac5773a2bea03124099909589f560cfde))
* **aros:** grow registries on demand and add devices and I/O requests ([#77](https://github.com/metaneutrons/ami-rust/issues/77)) ([8daf0ea](https://github.com/metaneutrons/ami-rust/commit/8daf0eac02d820a75f3012bef151c8b85423afe8))
* **asl:** aros-asl file requester returning owned paths ([#87](https://github.com/metaneutrons/ami-rust/issues/87)) ([bef7cde](https://github.com/metaneutrons/ami-rust/commit/bef7cde2d9378ffac77cc975ee6133d071f84e89))
* **build:** explain refusals and accept the sccache wrapper ([#47](https://github.com/metaneutrons/ami-rust/issues/47)) ([d79cbc8](https://github.com/metaneutrons/ami-rust/commit/d79cbc8423c13c4e4eb72a82e347225d3d8ad5b5))
* **docs:** build each release's documentation from its tag ([#51](https://github.com/metaneutrons/ami-rust/issues/51)) ([afdd270](https://github.com/metaneutrons/ami-rust/commit/afdd2707ff768b0ed087b284aac83aff75311f62))
* **docs:** editor setup, changelog, mobile gate and fully checked examples ([#48](https://github.com/metaneutrons/ami-rust/issues/48)) ([ef425b9](https://github.com/metaneutrons/ami-rust/commit/ef425b980d4756dbc94b0f7e120b0ba6011f7eb7))
* **docs:** render Rust API reference in Astro ([#45](https://github.com/metaneutrons/ami-rust/issues/45)) ([27200ec](https://github.com/metaneutrons/ami-rust/commit/27200ec232dc386e1e0058281dded49a613f08dc))
* **docs:** unify API reference and complete application guides ([#46](https://github.com/metaneutrons/ami-rust/issues/46)) ([09fc503](https://github.com/metaneutrons/ami-rust/commit/09fc503281652f7b7c28d4d99225d8d7ce6eb322))
* **docs:** versioned documentation ([#50](https://github.com/metaneutrons/ami-rust/issues/50)) ([467f471](https://github.com/metaneutrons/ami-rust/commit/467f471d5e8db29fe8f85a5e0aca05252598e686))
* **graphics:** aros-graphics on graphics.library ([#85](https://github.com/metaneutrons/ami-rust/issues/85)) ([a471520](https://github.com/metaneutrons/ami-rust/commit/a4715204e30374176568960ef7003b92d1c9ef08))
* **icon,workbench:** aros-icon and aros-workbench ([#89](https://github.com/metaneutrons/ami-rust/issues/89)) ([ffe3a6d](https://github.com/metaneutrons/ami-rust/commit/ffe3a6d51644249187930a90eb27d003162ba6d7))
* **intuition:** aros-intuition windows and typed events ([#86](https://github.com/metaneutrons/ami-rust/issues/86)) ([699c6fb](https://github.com/metaneutrons/ami-rust/commit/699c6fbeb91f95e5ad957f9c2607b1ce614bf6dd))
* **locale:** aros-locale catalogs with defaults and date formatting ([#88](https://github.com/metaneutrons/ami-rust/issues/88)) ([cf29175](https://github.com/metaneutrons/ami-rust/commit/cf29175e21c054a3b5c731b46b0e46859c29f679))
* **registry:** publish aros-native-build and aros-elf ([#94](https://github.com/metaneutrons/ami-rust/issues/94)) ([fd705ec](https://github.com/metaneutrons/ami-rust/commit/fd705ec9110908dd8deb1cf67811c72c9b4640b9))
* **registry:** publish the aros crates to a static Cargo registry ([#91](https://github.com/metaneutrons/ami-rust/issues/91)) ([d8e3851](https://github.com/metaneutrons/ami-rust/commit/d8e385159e8dd9b3042c4025bac20569461aa009))
* **sys:** generate ABI-v11 calls with up to twelve arguments ([#84](https://github.com/metaneutrons/ami-rust/issues/84)) ([4978a4f](https://github.com/metaneutrons/ami-rust/commit/4978a4fee40441567fe2564510b6fcb1a4a5355f))
* **timer:** aros-timer on timer.device ([#80](https://github.com/metaneutrons/ami-rust/issues/80)) ([4edb90d](https://github.com/metaneutrons/ami-rust/commit/4edb90d17c408eef2d8e5fae9a49bed3c846d028))


### Bug Fixes

* **cargo:** configure canonical AROS targets ([#35](https://github.com/metaneutrons/ami-rust/issues/35)) ([0bbb492](https://github.com/metaneutrons/ami-rust/commit/0bbb492842007a229bb30bf413d610a40438118d))
* **ci:** skip native matrix for documentation ([06f17c7](https://github.com/metaneutrons/ami-rust/commit/06f17c78b8f1905feeace655c2c5d3a5f7f90141))
* **docs:** use canonical site routes ([#41](https://github.com/metaneutrons/ami-rust/issues/41)) ([8fa4170](https://github.com/metaneutrons/ami-rust/commit/8fa41706ffa5efefeffa1f4b910a23b6b40066c3))
* **release:** refresh the pinned digest of the native vendor manifest ([#96](https://github.com/metaneutrons/ami-rust/issues/96)) ([a44250f](https://github.com/metaneutrons/ami-rust/commit/a44250fcbd38ccbc3c9a379be7b841e296e3dd6c))
* **sys:** declare Library and MsgPort as ABI-v11 does ([#97](https://github.com/metaneutrons/ami-rust/issues/97)) ([3f73203](https://github.com/metaneutrons/ami-rust/commit/3f73203fda135966a8030ae79ed9afc7d86f55de))

## 0.1.0 (2026-10-30)


### Features

* **bindings:** generate canonical MUI API model ([7bd2153](https://github.com/metaneutrons/ami-rust/commit/7bd21530b4208a338c6c711af6fb35fb2b41fa5b))
* **crates:** add AROS ABI-v1 libraries and examples ([cdcfa58](https://github.com/metaneutrons/ami-rust/commit/cdcfa58ba7507e41341c7a3f73c6ac5861762858))
* **crates:** establish the public AROS crate set ([#3](https://github.com/metaneutrons/ami-rust/issues/3)) ([c8100ec](https://github.com/metaneutrons/ami-rust/commit/c8100ec10fa4d46506a9dbf759b8964a0b4fe3c7))
* **crates:** generate the initial AROS API bindings ([ff5d0cd](https://github.com/metaneutrons/ami-rust/commit/ff5d0cd5c83e0adf9ac601410d7823834a27a418))
* **mui:** complete raw dual-ABI bindings ([20c8677](https://github.com/metaneutrons/ami-rust/commit/20c8677feffff7802cfb5fd50f071a9001d57239)), closes [#9](https://github.com/metaneutrons/ami-rust/issues/9)
* **mui:** complete safe interaction lifecycle ([#21](https://github.com/metaneutrons/ami-rust/issues/21)) ([72cad52](https://github.com/metaneutrons/ami-rust/commit/72cad52941d1da4290e7483b8b3969ead605104a)), closes [#12](https://github.com/metaneutrons/ami-rust/issues/12)
* **mui:** generate the complete standard class API ([614908c](https://github.com/metaneutrons/ami-rust/commit/614908ca22ba0787e7cb3d6e9da2cba507a49979))
* **mui:** implement safe scoped object model ([b8ab0a6](https://github.com/metaneutrons/ami-rust/commit/b8ab0a6a0b799042d0e038890da513d3fb18ef2e))
* **release:** prepare dual-ABI 0.1 candidate ([#24](https://github.com/metaneutrons/ami-rust/issues/24)) ([804ba2d](https://github.com/metaneutrons/ami-rust/commit/804ba2d8890f37caed1601daf6714f980e880f4a))
* **runtime:** qualify the x86-64 ABI11 baseline ([#16](https://github.com/metaneutrons/ami-rust/issues/16)) ([acdfc6f](https://github.com/metaneutrons/ami-rust/commit/acdfc6fc5936fb6eca7017ef40afb08cee74221e))
* **toolchain:** produce dual-ABI SDK candidates ([#22](https://github.com/metaneutrons/ami-rust/issues/22)) ([fe8cb82](https://github.com/metaneutrons/ami-rust/commit/fe8cb82325a90aff077e7bb4c0707e2ff514c5f5))
* **tooling:** add reproducible SDK production ([0c4cb6f](https://github.com/metaneutrons/ami-rust/commit/0c4cb6f76da56e4f1bdce6a49dfc3a8ad8d1086e))


### Bug Fixes

* **branding:** align pixel accents with monogram ([#2](https://github.com/metaneutrons/ami-rust/issues/2)) ([dc3721e](https://github.com/metaneutrons/ami-rust/commit/dc3721e5ac63b6cec1f0e7f2686578301e36109e))
* **ci:** retain per-host application identities ([#28](https://github.com/metaneutrons/ami-rust/issues/28)) ([9579552](https://github.com/metaneutrons/ami-rust/commit/95795520653aca959bb17b3b73cf025261d049a7))
* **release:** admit initial 0.1 toolchain ([#26](https://github.com/metaneutrons/ami-rust/issues/26)) ([613b65a](https://github.com/metaneutrons/ami-rust/commit/613b65a8e13fb88daa35d26dfd3158ca95bc1a84))
* **release:** refresh native prefix source pin ([#25](https://github.com/metaneutrons/ami-rust/issues/25)) ([80e713c](https://github.com/metaneutrons/ami-rust/commit/80e713c49fb5e9637decdb42a33f54b644f4fcb8))
* **release:** tag the reviewed release source ([#32](https://github.com/metaneutrons/ami-rust/issues/32)) ([51a9b35](https://github.com/metaneutrons/ami-rust/commit/51a9b356c7577dabef4e09a085f027c6101e62f5))
* **toolchain:** admit host-specific candidate inputs ([#27](https://github.com/metaneutrons/ami-rust/issues/27)) ([6ff27b6](https://github.com/metaneutrons/ami-rust/commit/6ff27b68ec3883ec418bd19cb593c46b84f4af07))
* **toolchain:** qualify dual-ABI SDK candidates ([#23](https://github.com/metaneutrons/ami-rust/issues/23)) ([405b97b](https://github.com/metaneutrons/ami-rust/commit/405b97b6f18ea07c961bd0904a05b15ca534cca3))
* **tooling:** repair historical fixture inputs ([df88a66](https://github.com/metaneutrons/ami-rust/commit/df88a66d34e33e5a8f4e6639b62a415168e97248))

## [Unreleased]
