# Changelog

## [0.1.0](https://github.com/metaneutrons/ami-rust/compare/v0.1.0...v0.1.0) (2026-10-17)


### Features

* add experimental AROS x86-64 Rust SDK sources ([5478079](https://github.com/metaneutrons/ami-rust/commit/5478079da0a8c3074940cdc2a6f22f9442747863))
* authenticate complete SDK release candidates in protected CI ([#22](https://github.com/metaneutrons/ami-rust/issues/22)) ([f418a54](https://github.com/metaneutrons/ami-rust/commit/f418a541c1b5d3ac32c86b1acf33dd4a75c210ab))
* authenticate public SDK assets before consumer replay ([#29](https://github.com/metaneutrons/ami-rust/issues/29)) ([1590c2a](https://github.com/metaneutrons/ami-rust/commit/1590c2a67e130d30ded6c3bcc66d31e1449b8fee))
* collect unaccepted native reference proposals ([#17](https://github.com/metaneutrons/ami-rust/issues/17)) ([42459cc](https://github.com/metaneutrons/ami-rust/commit/42459cc60d95ef4d22701dcaf51d7ec69f64f0a8))
* stage exact SDK release assets with draft readback ([#20](https://github.com/metaneutrons/ami-rust/issues/20)) ([75a8e40](https://github.com/metaneutrons/ami-rust/commit/75a8e407d5e03a27368566a5fd7f0abec4e3b68a))
* verify public SDK retrieval and consumer replay ([#14](https://github.com/metaneutrons/ami-rust/issues/14)) ([7136125](https://github.com/metaneutrons/ami-rust/commit/7136125a335f5c4934b874b87d464698911c7602))


### Bug Fixes

* account for native build intermediates ([#18](https://github.com/metaneutrons/ami-rust/issues/18)) ([916b8d8](https://github.com/metaneutrons/ami-rust/commit/916b8d86b459741d989aa711d90a237e443025e0))
* align consumer recipes and compile fixture metadata ([#51](https://github.com/metaneutrons/ami-rust/issues/51)) ([4aabec7](https://github.com/metaneutrons/ami-rust/commit/4aabec776f0829198f08f50f52b23e4f12fbf0cb))
* align SBOM identity with the production SDK version ([#21](https://github.com/metaneutrons/ami-rust/issues/21)) ([1c51bdc](https://github.com/metaneutrons/ami-rust/commit/1c51bdcd2e53015f92649b4e921b81fae9e4e626))
* avoid duplicate SDK workspace inventory scans ([#43](https://github.com/metaneutrons/ami-rust/issues/43)) ([11e58e0](https://github.com/metaneutrons/ami-rust/commit/11e58e0a8677ddef80cdbef2687ba35e0c6d5289))
* bind public releases to their source tags ([#19](https://github.com/metaneutrons/ami-rust/issues/19)) ([aceebfb](https://github.com/metaneutrons/ami-rust/commit/aceebfbe61463817a51ad9bae39db50f29e9615b))
* bind SDK packaging to the qualified R4 native profile ([#39](https://github.com/metaneutrons/ami-rust/issues/39)) ([84ed4a7](https://github.com/metaneutrons/ami-rust/commit/84ed4a7b2a88373229784616c0036c1ba9e2b8c0))
* **ci:** pin the hosted Python runtime independently of runner images ([#6](https://github.com/metaneutrons/ami-rust/issues/6)) ([ea0cf65](https://github.com/metaneutrons/ami-rust/commit/ea0cf65e46d56b6e7b8154e0ce1369a7b33b1d2b))
* correct Cargo notice capsule inventory self-reference ([#28](https://github.com/metaneutrons/ami-rust/issues/28)) ([1094b27](https://github.com/metaneutrons/ami-rust/commit/1094b27b00f2a7d6100aec79bb26a37b2037d381))
* emit schema-compatible SLSA publisher provenance ([#41](https://github.com/metaneutrons/ami-rust/issues/41)) ([b76848b](https://github.com/metaneutrons/ami-rust/commit/b76848b33209711bce0a91cd2c246cff981e435e))
* make production consumer preparation reproducible ([#9](https://github.com/metaneutrons/ami-rust/issues/9)) ([f65e49e](https://github.com/metaneutrons/ami-rust/commit/f65e49ea896ac34411415c151983c122bc55b776))
* pass SDK context to consumer project builds ([#12](https://github.com/metaneutrons/ami-rust/issues/12)) ([3d0c33a](https://github.com/metaneutrons/ami-rust/commit/3d0c33a698d00a5399991fc78f25ef7d997edfdb))
* preserve exact source and notice bytes in Git ([085f89e](https://github.com/metaneutrons/ami-rust/commit/085f89e329eeb00e1b9b1c5a988c364268f31cf1))
* qualify portable hosted Cargo prerequisites ([#34](https://github.com/metaneutrons/ami-rust/issues/34)) ([8e98f23](https://github.com/metaneutrons/ami-rust/commit/8e98f230483af5e4785e233c74a68099b97fe2ca))
* remap host compiler paths in cross SDK builds ([#25](https://github.com/metaneutrons/ami-rust/issues/25)) ([416fc07](https://github.com/metaneutrons/ami-rust/commit/416fc07b8834e84503db688f02ac0df6698f07e3))
* remove feasibility quotas from application memory ([#16](https://github.com/metaneutrons/ami-rust/issues/16)) ([189a7d5](https://github.com/metaneutrons/ami-rust/commit/189a7d5c46bcdc79ab4e078d4e8c63f0c94d6f84))
* remove hosted Cargo debug paths and correct RSS guard ([#33](https://github.com/metaneutrons/ami-rust/issues/33)) ([8fb15e1](https://github.com/metaneutrons/ami-rust/commit/8fb15e1efbf648664fb1e31d685d24849ce4e8a2))
* report the verified host in installation results ([#49](https://github.com/metaneutrons/ami-rust/issues/49)) ([e5ed104](https://github.com/metaneutrons/ami-rust/commit/e5ed10412af1b3e3647b3f889716f0b3f7973257))
* retain exact diagnostics for cold-root build mismatches ([#23](https://github.com/metaneutrons/ami-rust/issues/23)) ([8b84412](https://github.com/metaneutrons/ami-rust/commit/8b844120742797eade002a849f2963b1676b66d6))
* retain independent consumer archive evidence ([#35](https://github.com/metaneutrons/ami-rust/issues/35)) ([fedeee1](https://github.com/metaneutrons/ami-rust/commit/fedeee14f1fb687e2c8376601c9fc32244e63e59))
* retire verified Cargo scratch before SDK derivation ([#36](https://github.com/metaneutrons/ami-rust/issues/36)) ([1d0fe4f](https://github.com/metaneutrons/ami-rust/commit/1d0fe4f10c8f264fd4b8fd50baccadd34869a802))
* separate SDK installer logs from Cargo bootstrap ([#15](https://github.com/metaneutrons/ami-rust/issues/15)) ([b73f002](https://github.com/metaneutrons/ami-rust/commit/b73f00240fbb65b364f10363e0dd4ddb74e333bc))
* use one exact GitHub attestation identity selector ([#47](https://github.com/metaneutrons/ami-rust/issues/47)) ([6736a4e](https://github.com/metaneutrons/ami-rust/commit/6736a4e265e71e1b4d327f93b36b207c9e589db5))
* validate current Cargo producer pins before SDK work ([#13](https://github.com/metaneutrons/ami-rust/issues/13)) ([20e56eb](https://github.com/metaneutrons/ami-rust/commit/20e56ebe052b4dbb2c71c7cd9a7afe020f2448d2))
* validate GitHub provenance before SDK builds ([#45](https://github.com/metaneutrons/ami-rust/issues/45)) ([493db1d](https://github.com/metaneutrons/ami-rust/commit/493db1df86a29bbd4fb0f11da13429a7e5887096))
* verify static release inputs before SDK production ([#10](https://github.com/metaneutrons/ami-rust/issues/10)) ([0dbdc25](https://github.com/metaneutrons/ami-rust/commit/0dbdc2549cf1d3e166f0523e642c0b401b3f4a9f))

## [0.1.0](https://github.com/metaneutrons/ami-rust/compare/v0.1.0...v0.1.0) (2026-10-17)


### Features

* add experimental AROS x86-64 Rust SDK sources ([5478079](https://github.com/metaneutrons/ami-rust/commit/5478079da0a8c3074940cdc2a6f22f9442747863))
* authenticate complete SDK release candidates in protected CI ([#22](https://github.com/metaneutrons/ami-rust/issues/22)) ([f418a54](https://github.com/metaneutrons/ami-rust/commit/f418a541c1b5d3ac32c86b1acf33dd4a75c210ab))
* authenticate public SDK assets before consumer replay ([#29](https://github.com/metaneutrons/ami-rust/issues/29)) ([1590c2a](https://github.com/metaneutrons/ami-rust/commit/1590c2a67e130d30ded6c3bcc66d31e1449b8fee))
* collect unaccepted native reference proposals ([#17](https://github.com/metaneutrons/ami-rust/issues/17)) ([42459cc](https://github.com/metaneutrons/ami-rust/commit/42459cc60d95ef4d22701dcaf51d7ec69f64f0a8))
* stage exact SDK release assets with draft readback ([#20](https://github.com/metaneutrons/ami-rust/issues/20)) ([75a8e40](https://github.com/metaneutrons/ami-rust/commit/75a8e407d5e03a27368566a5fd7f0abec4e3b68a))
* verify public SDK retrieval and consumer replay ([#14](https://github.com/metaneutrons/ami-rust/issues/14)) ([7136125](https://github.com/metaneutrons/ami-rust/commit/7136125a335f5c4934b874b87d464698911c7602))


### Bug Fixes

* account for native build intermediates ([#18](https://github.com/metaneutrons/ami-rust/issues/18)) ([916b8d8](https://github.com/metaneutrons/ami-rust/commit/916b8d86b459741d989aa711d90a237e443025e0))
* align SBOM identity with the production SDK version ([#21](https://github.com/metaneutrons/ami-rust/issues/21)) ([1c51bdc](https://github.com/metaneutrons/ami-rust/commit/1c51bdcd2e53015f92649b4e921b81fae9e4e626))
* avoid duplicate SDK workspace inventory scans ([#43](https://github.com/metaneutrons/ami-rust/issues/43)) ([11e58e0](https://github.com/metaneutrons/ami-rust/commit/11e58e0a8677ddef80cdbef2687ba35e0c6d5289))
* bind public releases to their source tags ([#19](https://github.com/metaneutrons/ami-rust/issues/19)) ([aceebfb](https://github.com/metaneutrons/ami-rust/commit/aceebfbe61463817a51ad9bae39db50f29e9615b))
* bind SDK packaging to the qualified R4 native profile ([#39](https://github.com/metaneutrons/ami-rust/issues/39)) ([84ed4a7](https://github.com/metaneutrons/ami-rust/commit/84ed4a7b2a88373229784616c0036c1ba9e2b8c0))
* **ci:** pin the hosted Python runtime independently of runner images ([#6](https://github.com/metaneutrons/ami-rust/issues/6)) ([ea0cf65](https://github.com/metaneutrons/ami-rust/commit/ea0cf65e46d56b6e7b8154e0ce1369a7b33b1d2b))
* correct Cargo notice capsule inventory self-reference ([#28](https://github.com/metaneutrons/ami-rust/issues/28)) ([1094b27](https://github.com/metaneutrons/ami-rust/commit/1094b27b00f2a7d6100aec79bb26a37b2037d381))
* emit schema-compatible SLSA publisher provenance ([#41](https://github.com/metaneutrons/ami-rust/issues/41)) ([b76848b](https://github.com/metaneutrons/ami-rust/commit/b76848b33209711bce0a91cd2c246cff981e435e))
* make production consumer preparation reproducible ([#9](https://github.com/metaneutrons/ami-rust/issues/9)) ([f65e49e](https://github.com/metaneutrons/ami-rust/commit/f65e49ea896ac34411415c151983c122bc55b776))
* pass SDK context to consumer project builds ([#12](https://github.com/metaneutrons/ami-rust/issues/12)) ([3d0c33a](https://github.com/metaneutrons/ami-rust/commit/3d0c33a698d00a5399991fc78f25ef7d997edfdb))
* preserve exact source and notice bytes in Git ([085f89e](https://github.com/metaneutrons/ami-rust/commit/085f89e329eeb00e1b9b1c5a988c364268f31cf1))
* qualify portable hosted Cargo prerequisites ([#34](https://github.com/metaneutrons/ami-rust/issues/34)) ([8e98f23](https://github.com/metaneutrons/ami-rust/commit/8e98f230483af5e4785e233c74a68099b97fe2ca))
* remap host compiler paths in cross SDK builds ([#25](https://github.com/metaneutrons/ami-rust/issues/25)) ([416fc07](https://github.com/metaneutrons/ami-rust/commit/416fc07b8834e84503db688f02ac0df6698f07e3))
* remove feasibility quotas from application memory ([#16](https://github.com/metaneutrons/ami-rust/issues/16)) ([189a7d5](https://github.com/metaneutrons/ami-rust/commit/189a7d5c46bcdc79ab4e078d4e8c63f0c94d6f84))
* remove hosted Cargo debug paths and correct RSS guard ([#33](https://github.com/metaneutrons/ami-rust/issues/33)) ([8fb15e1](https://github.com/metaneutrons/ami-rust/commit/8fb15e1efbf648664fb1e31d685d24849ce4e8a2))
* report the verified host in installation results ([#49](https://github.com/metaneutrons/ami-rust/issues/49)) ([e5ed104](https://github.com/metaneutrons/ami-rust/commit/e5ed10412af1b3e3647b3f889716f0b3f7973257))
* retain exact diagnostics for cold-root build mismatches ([#23](https://github.com/metaneutrons/ami-rust/issues/23)) ([8b84412](https://github.com/metaneutrons/ami-rust/commit/8b844120742797eade002a849f2963b1676b66d6))
* retain independent consumer archive evidence ([#35](https://github.com/metaneutrons/ami-rust/issues/35)) ([fedeee1](https://github.com/metaneutrons/ami-rust/commit/fedeee14f1fb687e2c8376601c9fc32244e63e59))
* retire verified Cargo scratch before SDK derivation ([#36](https://github.com/metaneutrons/ami-rust/issues/36)) ([1d0fe4f](https://github.com/metaneutrons/ami-rust/commit/1d0fe4f10c8f264fd4b8fd50baccadd34869a802))
* separate SDK installer logs from Cargo bootstrap ([#15](https://github.com/metaneutrons/ami-rust/issues/15)) ([b73f002](https://github.com/metaneutrons/ami-rust/commit/b73f00240fbb65b364f10363e0dd4ddb74e333bc))
* use one exact GitHub attestation identity selector ([#47](https://github.com/metaneutrons/ami-rust/issues/47)) ([6736a4e](https://github.com/metaneutrons/ami-rust/commit/6736a4e265e71e1b4d327f93b36b207c9e589db5))
* validate current Cargo producer pins before SDK work ([#13](https://github.com/metaneutrons/ami-rust/issues/13)) ([20e56eb](https://github.com/metaneutrons/ami-rust/commit/20e56ebe052b4dbb2c71c7cd9a7afe020f2448d2))
* validate GitHub provenance before SDK builds ([#45](https://github.com/metaneutrons/ami-rust/issues/45)) ([493db1d](https://github.com/metaneutrons/ami-rust/commit/493db1df86a29bbd4fb0f11da13429a7e5887096))
* verify static release inputs before SDK production ([#10](https://github.com/metaneutrons/ami-rust/issues/10)) ([0dbdc25](https://github.com/metaneutrons/ami-rust/commit/0dbdc2549cf1d3e166f0523e642c0b401b3f4a9f))

## 0.1.0 (2026-10-17)


### Features

* add experimental AROS x86-64 Rust SDK sources ([5478079](https://github.com/metaneutrons/ami-rust/commit/5478079da0a8c3074940cdc2a6f22f9442747863))
* authenticate complete SDK release candidates in protected CI ([#22](https://github.com/metaneutrons/ami-rust/issues/22)) ([f418a54](https://github.com/metaneutrons/ami-rust/commit/f418a541c1b5d3ac32c86b1acf33dd4a75c210ab))
* authenticate public SDK assets before consumer replay ([#29](https://github.com/metaneutrons/ami-rust/issues/29)) ([1590c2a](https://github.com/metaneutrons/ami-rust/commit/1590c2a67e130d30ded6c3bcc66d31e1449b8fee))
* collect unaccepted native reference proposals ([#17](https://github.com/metaneutrons/ami-rust/issues/17)) ([42459cc](https://github.com/metaneutrons/ami-rust/commit/42459cc60d95ef4d22701dcaf51d7ec69f64f0a8))
* stage exact SDK release assets with draft readback ([#20](https://github.com/metaneutrons/ami-rust/issues/20)) ([75a8e40](https://github.com/metaneutrons/ami-rust/commit/75a8e407d5e03a27368566a5fd7f0abec4e3b68a))
* verify public SDK retrieval and consumer replay ([#14](https://github.com/metaneutrons/ami-rust/issues/14)) ([7136125](https://github.com/metaneutrons/ami-rust/commit/7136125a335f5c4934b874b87d464698911c7602))


### Bug Fixes

* account for native build intermediates ([#18](https://github.com/metaneutrons/ami-rust/issues/18)) ([916b8d8](https://github.com/metaneutrons/ami-rust/commit/916b8d86b459741d989aa711d90a237e443025e0))
* align SBOM identity with the production SDK version ([#21](https://github.com/metaneutrons/ami-rust/issues/21)) ([1c51bdc](https://github.com/metaneutrons/ami-rust/commit/1c51bdcd2e53015f92649b4e921b81fae9e4e626))
* avoid duplicate SDK workspace inventory scans ([#43](https://github.com/metaneutrons/ami-rust/issues/43)) ([11e58e0](https://github.com/metaneutrons/ami-rust/commit/11e58e0a8677ddef80cdbef2687ba35e0c6d5289))
* bind public releases to their source tags ([#19](https://github.com/metaneutrons/ami-rust/issues/19)) ([aceebfb](https://github.com/metaneutrons/ami-rust/commit/aceebfbe61463817a51ad9bae39db50f29e9615b))
* bind SDK packaging to the qualified R4 native profile ([#39](https://github.com/metaneutrons/ami-rust/issues/39)) ([84ed4a7](https://github.com/metaneutrons/ami-rust/commit/84ed4a7b2a88373229784616c0036c1ba9e2b8c0))
* **ci:** pin the hosted Python runtime independently of runner images ([#6](https://github.com/metaneutrons/ami-rust/issues/6)) ([ea0cf65](https://github.com/metaneutrons/ami-rust/commit/ea0cf65e46d56b6e7b8154e0ce1369a7b33b1d2b))
* correct Cargo notice capsule inventory self-reference ([#28](https://github.com/metaneutrons/ami-rust/issues/28)) ([1094b27](https://github.com/metaneutrons/ami-rust/commit/1094b27b00f2a7d6100aec79bb26a37b2037d381))
* emit schema-compatible SLSA publisher provenance ([#41](https://github.com/metaneutrons/ami-rust/issues/41)) ([b76848b](https://github.com/metaneutrons/ami-rust/commit/b76848b33209711bce0a91cd2c246cff981e435e))
* make production consumer preparation reproducible ([#9](https://github.com/metaneutrons/ami-rust/issues/9)) ([f65e49e](https://github.com/metaneutrons/ami-rust/commit/f65e49ea896ac34411415c151983c122bc55b776))
* pass SDK context to consumer project builds ([#12](https://github.com/metaneutrons/ami-rust/issues/12)) ([3d0c33a](https://github.com/metaneutrons/ami-rust/commit/3d0c33a698d00a5399991fc78f25ef7d997edfdb))
* preserve exact source and notice bytes in Git ([085f89e](https://github.com/metaneutrons/ami-rust/commit/085f89e329eeb00e1b9b1c5a988c364268f31cf1))
* qualify portable hosted Cargo prerequisites ([#34](https://github.com/metaneutrons/ami-rust/issues/34)) ([8e98f23](https://github.com/metaneutrons/ami-rust/commit/8e98f230483af5e4785e233c74a68099b97fe2ca))
* remap host compiler paths in cross SDK builds ([#25](https://github.com/metaneutrons/ami-rust/issues/25)) ([416fc07](https://github.com/metaneutrons/ami-rust/commit/416fc07b8834e84503db688f02ac0df6698f07e3))
* remove feasibility quotas from application memory ([#16](https://github.com/metaneutrons/ami-rust/issues/16)) ([189a7d5](https://github.com/metaneutrons/ami-rust/commit/189a7d5c46bcdc79ab4e078d4e8c63f0c94d6f84))
* remove hosted Cargo debug paths and correct RSS guard ([#33](https://github.com/metaneutrons/ami-rust/issues/33)) ([8fb15e1](https://github.com/metaneutrons/ami-rust/commit/8fb15e1efbf648664fb1e31d685d24849ce4e8a2))
* retain exact diagnostics for cold-root build mismatches ([#23](https://github.com/metaneutrons/ami-rust/issues/23)) ([8b84412](https://github.com/metaneutrons/ami-rust/commit/8b844120742797eade002a849f2963b1676b66d6))
* retain independent consumer archive evidence ([#35](https://github.com/metaneutrons/ami-rust/issues/35)) ([fedeee1](https://github.com/metaneutrons/ami-rust/commit/fedeee14f1fb687e2c8376601c9fc32244e63e59))
* retire verified Cargo scratch before SDK derivation ([#36](https://github.com/metaneutrons/ami-rust/issues/36)) ([1d0fe4f](https://github.com/metaneutrons/ami-rust/commit/1d0fe4f10c8f264fd4b8fd50baccadd34869a802))
* separate SDK installer logs from Cargo bootstrap ([#15](https://github.com/metaneutrons/ami-rust/issues/15)) ([b73f002](https://github.com/metaneutrons/ami-rust/commit/b73f00240fbb65b364f10363e0dd4ddb74e333bc))
* use one exact GitHub attestation identity selector ([#47](https://github.com/metaneutrons/ami-rust/issues/47)) ([6736a4e](https://github.com/metaneutrons/ami-rust/commit/6736a4e265e71e1b4d327f93b36b207c9e589db5))
* validate current Cargo producer pins before SDK work ([#13](https://github.com/metaneutrons/ami-rust/issues/13)) ([20e56eb](https://github.com/metaneutrons/ami-rust/commit/20e56ebe052b4dbb2c71c7cd9a7afe020f2448d2))
* validate GitHub provenance before SDK builds ([#45](https://github.com/metaneutrons/ami-rust/issues/45)) ([493db1d](https://github.com/metaneutrons/ami-rust/commit/493db1df86a29bbd4fb0f11da13429a7e5887096))
* verify static release inputs before SDK production ([#10](https://github.com/metaneutrons/ami-rust/issues/10)) ([0dbdc25](https://github.com/metaneutrons/ami-rust/commit/0dbdc2549cf1d3e166f0523e642c0b401b3f4a9f))
