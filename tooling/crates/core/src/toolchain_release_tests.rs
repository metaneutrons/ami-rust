use super::{ReleaseHost, parse_toolchain_release};
use serde_json::{Value, json};

fn file(name: String) -> Value {
    json!({"name": name, "bytes": 42, "sha256": "a".repeat(64)})
}

fn candidate() -> Value {
    let version = "0.1.0";
    let hosts: Vec<_> = ReleaseHost::ALL.into_iter().map(|host| {
        let base = format!("ami-rust-toolchain-{version}-{}", host.key());
        json!({
            "host": host,
            "rustup": {
                "rustc": file(format!("ami-rust-rustc-{version}-{}.tar.xz", host.key())),
                "cargo": file(format!("ami-rust-cargo-{version}-{}.tar.xz", host.key())),
                "rust_std": file(format!("ami-rust-rust-std-{version}-{}.tar.xz", host.key())),
            },
            "archive": file(format!("{base}.tar.xz")),
            "inventory": file(format!("{base}.manifest.json")),
            "debian": host.debian_architecture().map(|arch| file(format!("ami-rust_{version}-1_{arch}.deb"))),
        })
    }).collect();
    let crates: Vec<_> = super::CRATES
        .into_iter()
        .map(|name| {
            json!({
                "name": name, "version": version,
                "archive": file(format!("{name}-{version}.crate")),
                "dependencies": match name {
                    "aros-native-build" => vec!["aros-elf"],
                    "aros" => vec!["aros-sys"],
                    "aros-mui-sys" => vec!["aros-sys"],
                    "aros-mui" => vec!["aros", "aros-sys", "aros-mui-sys"],
                    _ => Vec::new(),
                },
            })
        })
        .collect();
    let mut value = json!({
        "schema": "ami-rust-toolchain-release-v2", "version": version,
        "package_revision": 1, "target": "x86_64-aros",
        "source": {"commit": "1".repeat(40), "tree": "2".repeat(40), "epoch": 1792870000},
        "hosts": hosts, "crates": crates,
        "rustup_distribution": {
            "channel": version, "catalog_commit": "3".repeat(40),
            "rust_version": "1.100.0-nightly (330d31712 2026-09-17)",
            "cargo_version": "1.99.0 (3efb1f477 2026-07-17)", "release_tag": "v0.1.0",
            "manifest": file(format!("channel-rust-{version}.toml")),
            "checksum": file(format!("channel-rust-{version}.toml.sha256")),
        },
        "sources": file(format!("ami-rust-{version}-sources.tar.xz")),
        "vendor": file(format!("ami-rust-{version}-vendor.tar.xz")),
        "homebrew_formula": file("ami-rust.rb".to_owned()),
    });
    let release: super::ToolchainRelease = serde_json::from_value(value.clone()).unwrap();
    let rendered = release.rustup_manifest_files().unwrap();
    for (key, name, content) in [
        ("manifest", rendered.manifest_name, rendered.manifest),
        ("checksum", rendered.checksum_name, rendered.checksum),
    ] {
        value["rustup_distribution"][key] = json!({"name":name,"bytes":content.len(),"sha256":crate::digest::sha256_bytes(content.as_bytes())});
    }
    value
}

fn accepts(value: &Value) -> bool {
    parse_toolchain_release(&serde_json::to_vec(value).unwrap()).is_ok()
}

#[test]
fn complete_three_host_inventory_derives_one_asset_set_and_crate_order() {
    let release = parse_toolchain_release(&serde_json::to_vec(&candidate()).unwrap()).unwrap();
    assert_eq!(release.toolchain_name(), "aros-0.1.0");
    assert_eq!(release.package_prefix(), "libexec/ami-rust/0.1.0");
    let assets = release.expected_assets();
    // Twenty-two payloads each have an SBOM/signature, seven metadata files
    // each have one signature, plus the self-excluding final checksum file.
    assert_eq!(assets.len(), 81);
    assert_eq!(release.unsigned_payloads().len(), 28);
    assert_eq!(
        release.rustup_dist_server(),
        format!(
            "https://raw.githubusercontent.com/metaneutrons/ami-rust/{}/distribution/rustup/0.1.0",
            "3".repeat(40),
        )
    );
    assert!(assets.contains(&"channel-rust-0.1.0.toml.sha256.sigstore.json".to_owned()));
    assert!(assets.contains(&"ami-rust-rust-std-0.1.0-linux-aarch64.tar.xz.spdx.json".to_owned()));
    assert!(assets.contains(&"ami-rust_0.1.0-1_arm64.deb".to_owned()));
    assert!(assets.contains(&"ami-rust-toolchain-0.1.0-macos-aarch64.tar.xz.spdx.json".to_owned()));
    assert!(
        !assets
            .iter()
            .any(|name| name.ends_with(".spdx.json.sigstore.json"))
    );
    let order = release.publication_order().unwrap();
    for row in &release.crates {
        for dependency in &row.dependencies {
            assert!(
                order.iter().position(|name| name == dependency).unwrap()
                    < order.iter().position(|name| name == &row.name).unwrap()
            );
        }
    }
}

#[test]
fn v3_native_reference_application_is_a_payload_and_v2_rejects_it() {
    let mut v3 = candidate();
    v3["schema"] = json!("ami-rust-toolchain-release-v3");
    v3["reference_application"] = json!({
        "target": "x86_64-aros",
        "abi": "v1",
        "archive": file("ami-rust-sha256sum-0.1.0-x86_64-aros.tar.xz".to_owned()),
    });
    let release = parse_toolchain_release(&serde_json::to_vec(&v3).unwrap()).unwrap();
    let assets = release.expected_assets();
    assert_eq!(release.unsigned_payloads().len(), 29);
    assert_eq!(assets.len(), 84);
    assert!(assets.contains(&"ami-rust-sha256sum-0.1.0-x86_64-aros.tar.xz".to_owned()));
    assert!(assets.contains(&"ami-rust-sha256sum-0.1.0-x86_64-aros.tar.xz.spdx.json".to_owned()));
    assert!(
        assets.contains(&"ami-rust-sha256sum-0.1.0-x86_64-aros.tar.xz.sigstore.json".to_owned())
    );

    let mut missing = v3.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("reference_application");
    assert!(!accepts(&missing));
    let mut wrong_abi = v3.clone();
    wrong_abi["reference_application"]["abi"] = json!("v2");
    assert!(!accepts(&wrong_abi));
    let mut wrong_target = v3.clone();
    wrong_target["reference_application"]["target"] = json!("aarch64-aros");
    assert!(!accepts(&wrong_target));

    let mut v2_with_application = v3;
    v2_with_application["schema"] = json!("ami-rust-toolchain-release-v2");
    assert!(!accepts(&v2_with_application));
}

#[test]
fn missing_duplicated_or_crossed_host_and_debian_identities_refuse() {
    let valid = candidate();
    let mut missing = valid.clone();
    missing["hosts"].as_array_mut().unwrap().pop();
    assert!(!accepts(&missing));
    let mut duplicate = valid.clone();
    duplicate["hosts"][2] = duplicate["hosts"][1].clone();
    assert!(!accepts(&duplicate));
    let mut crossed = valid.clone();
    crossed["hosts"][2]["debian"]["name"] = json!("ami-rust_0.1.0-1_amd64.deb");
    assert!(!accepts(&crossed));
    let mut mac_deb = valid.clone();
    mac_deb["hosts"][0]["debian"] = valid["hosts"][1]["debian"].clone();
    assert!(!accepts(&mac_deb));
}

#[test]
fn historical_cli_and_incomplete_or_forged_crate_inventory_refuse() {
    let valid = candidate();
    let mut old = valid.clone();
    old["schema"] = json!("ami-rust-release-v2");
    assert!(!accepts(&old));
    let mut launcher = valid.clone();
    launcher["host_launchers"] = json!({});
    assert!(!accepts(&launcher));
    let mut occupied = valid.clone();
    occupied["crates"][0]["name"] = json!("amiga-os");
    assert!(!accepts(&occupied));
    let mut mismatched_archive = valid.clone();
    mismatched_archive["crates"][0]["version"] = json!("0.2.0");
    assert!(!accepts(&mismatched_archive));
    let mut traversal = valid.clone();
    traversal["sources"]["name"] = json!("../sources.tar.xz");
    assert!(!accepts(&traversal));
    let mut bad_digest = valid.clone();
    bad_digest["vendor"]["sha256"] = json!("not-a-digest");
    assert!(!accepts(&bad_digest));
    let mut empty = valid.clone();
    empty["vendor"]["bytes"] = json!(0);
    assert!(!accepts(&empty));
}

#[test]
fn dependency_cycles_unknown_edges_and_duplicate_json_keys_refuse() {
    let valid = candidate();
    let mut cycle = valid.clone();
    cycle["crates"][0]["dependencies"] = json!(["aros-alloc"]);
    assert!(!accepts(&cycle));
    let mut missing = valid.clone();
    missing["crates"][0]["dependencies"] = json!(["unpublished-other"]);
    assert!(!accepts(&missing));
    let mut duplicate = valid.clone();
    duplicate["crates"][0]["dependencies"] = json!(["aros-elf", "aros-elf"]);
    assert!(!accepts(&duplicate));
    let bytes = serde_json::to_string(&valid).unwrap();
    let bytes = format!(
        "{{\"schema\":\"ami-rust-toolchain-release-v2\",{}",
        &bytes[1..]
    );
    assert!(parse_toolchain_release(bytes.as_bytes()).is_err());
}

#[test]
fn fresh_stable_version_is_required_and_input_order_is_irrelevant() {
    let valid = candidate();
    for version in [
        "0.0.9",
        "00.1.0",
        "0.1.0-dev",
        "0.1.0+packaging.1",
        "0.1",
        "0.1.0/path",
    ] {
        let mut invalid = valid.clone();
        invalid["version"] = json!(version);
        assert!(!accepts(&invalid), "accepted invalid version {version}");
    }
    let mut shuffled = valid.clone();
    shuffled["hosts"].as_array_mut().unwrap().reverse();
    shuffled["crates"].as_array_mut().unwrap().reverse();
    let a = parse_toolchain_release(&serde_json::to_vec(&valid).unwrap()).unwrap();
    let b = parse_toolchain_release(&serde_json::to_vec(&shuffled).unwrap()).unwrap();
    assert_eq!(
        a.publication_order().unwrap(),
        b.publication_order().unwrap()
    );
    assert_eq!(a.expected_assets(), b.expected_assets());
    let mut separate_crate_version = valid.clone();
    separate_crate_version["crates"][0]["version"] = json!("0.2.0");
    let first_name = separate_crate_version["crates"][0]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    separate_crate_version["crates"][0]["archive"]["name"] =
        json!(format!("{first_name}-0.2.0.crate"));
    assert!(accepts(&separate_crate_version));
}

#[test]
fn missing_crossed_or_legacy_rustup_distribution_refuses() {
    let valid = candidate();
    let mut old = valid.clone();
    old["schema"] = json!("ami-rust-toolchain-release-v1");
    assert!(!accepts(&old));
    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("rustup_distribution");
    assert!(!accepts(&missing));
    let mut missing_cargo = valid.clone();
    missing_cargo["hosts"][0]["rustup"]
        .as_object_mut()
        .unwrap()
        .remove("cargo");
    assert!(!accepts(&missing_cargo));
    for field in ["channel", "catalog_commit"] {
        let mut bad = valid.clone();
        bad["rustup_distribution"][field] = json!("invalid");
        assert!(!accepts(&bad));
    }
    let mut cycle = valid.clone();
    cycle["rustup_distribution"]["catalog_commit"] = cycle["source"]["commit"].clone();
    assert!(!accepts(&cycle));
    let mut crossed = valid.clone();
    crossed["hosts"][0]["rustup"]["rustc"] = crossed["hosts"][1]["rustup"]["rustc"].clone();
    assert!(!accepts(&crossed));
    let mut named_like_payload = valid.clone();
    named_like_payload["rustup_distribution"]["manifest"]["name"] =
        valid["sources"]["name"].clone();
    assert!(!accepts(&named_like_payload));
}

#[test]
fn changed_component_or_manifest_checksum_cannot_keep_old_metadata_identity() {
    let valid = candidate();
    for (key, field) in [("manifest", "sha256"), ("checksum", "sha256")] {
        let mut bad = valid.clone();
        bad["rustup_distribution"][key][field] = json!("0".repeat(64));
        assert!(!accepts(&bad));
    }
    let mut changed_component = valid.clone();
    changed_component["hosts"][1]["rustup"]["cargo"]["sha256"] = json!("b".repeat(64));
    assert!(!accepts(&changed_component));
    for (field, value) in [
        ("release_tag", "v0.1.0-qualification.0"),
        ("release_tag", "v0.1.0/other"),
        ("rust_version", "forged\nversion"),
    ] {
        let mut bad = valid.clone();
        bad["rustup_distribution"][field] = json!(value);
        assert!(!accepts(&bad));
    }
}
