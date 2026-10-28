//! Closed release inventory for the Cargo/rustup product, independent of the
//! historical CLI release contracts. Parsing checks claims, not signatures,
//! registry ownership, filesystem bytes or release acceptance.

use crate::{
    Refusal, Result,
    json::{JsonProfile, parse_json_value},
    records::Sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[path = "toolchain_release_files.rs"]
mod files;
#[path = "toolchain_release_rustup.rs"]
mod rustup;
pub use files::{UnsignedPayloadReadback, verify_unsigned_payloads};
pub use rustup::{
    RustupManifestFiles, RustupManifestHost, RustupManifestRequest, render_rustup_manifest,
};

const SCHEMA_V2: &str = "ami-rust-toolchain-release-v2";
const SCHEMA_V3: &str = "ami-rust-toolchain-release-v3";
const TARGET: &str = "x86_64-aros";
const CRATES: [&str; 8] = [
    "aros-sys",
    "aros-alloc",
    "aros-runtime",
    "aros-sdk",
    "amiga-alloc",
    "amiga-os",
    "aros-elf",
    "aros-native-build",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ReleaseHost {
    #[serde(rename = "macos-aarch64")]
    MacosAarch64,
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "linux-aarch64")]
    LinuxAarch64,
}

impl ReleaseHost {
    pub const ALL: [Self; 3] = [Self::MacosAarch64, Self::LinuxX86_64, Self::LinuxAarch64];

    pub fn key(self) -> &'static str {
        match self {
            Self::MacosAarch64 => "macos-aarch64",
            Self::LinuxX86_64 => "linux-x86_64",
            Self::LinuxAarch64 => "linux-aarch64",
        }
    }

    pub fn rust_triple(self) -> &'static str {
        match self {
            Self::MacosAarch64 => "aarch64-apple-darwin",
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::LinuxAarch64 => "aarch64-unknown-linux-gnu",
        }
    }

    pub fn debian_architecture(self) -> Option<&'static str> {
        match self {
            Self::MacosAarch64 => None,
            Self::LinuxX86_64 => Some("amd64"),
            Self::LinuxAarch64 => Some("arm64"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub bytes: u64,
    pub sha256: Sha256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub commit: String,
    pub tree: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPayload {
    pub host: ReleaseHost,
    pub archive: Artifact,
    pub inventory: Artifact,
    pub debian: Option<Artifact>,
    pub rustup: RustupComponents,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustupComponents {
    pub rustc: Artifact,
    pub cargo: Artifact,
    pub rust_std: Artifact,
}

impl RustupComponents {
    pub fn artifacts(&self) -> [&Artifact; 3] {
        [&self.rustc, &self.cargo, &self.rust_std]
    }
}

/// Static catalog identity is separate from the SDK source commit: its
/// manifest references already-built component hashes, without a self hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustupDistribution {
    pub channel: String,
    pub catalog_commit: String,
    pub rust_version: String,
    pub cargo_version: String,
    pub release_tag: String,
    pub manifest: Artifact,
    pub checksum: Artifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CratePayload {
    pub name: String,
    pub version: String,
    pub archive: Artifact,
    /// Workspace dependencies only; checked against actual packaged manifests
    /// by the producer before this inventory is signed.
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReferenceApplication {
    pub target: String,
    pub abi: String,
    pub archive: Artifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainRelease {
    pub schema: String,
    pub version: String,
    pub package_revision: u32,
    pub target: String,
    pub source: SourceIdentity,
    pub hosts: Vec<HostPayload>,
    pub crates: Vec<CratePayload>,
    pub sources: Artifact,
    pub vendor: Artifact,
    pub homebrew_formula: Artifact,
    pub rustup_distribution: RustupDistribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_application: Option<NativeReferenceApplication>,
}

/// Reject duplicate JSON keys and historical launcher/interpreter schemas.
/// A successful parse never authorizes installation or publication.
pub fn parse_toolchain_release(raw: &[u8]) -> Result<ToolchainRelease> {
    let value = parse_json_value(raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let release: ToolchainRelease = serde_json::from_value(value)
        .map_err(|error| Refusal::new(format!("invalid toolchain release inventory: {error}")))?;
    release.validate()?;
    Ok(release)
}

impl ToolchainRelease {
    /// Raw payload and metadata subjects, before signature/SBOM generation.
    /// The release inventory itself is written separately to avoid a self hash.
    pub fn unsigned_payloads(&self) -> Vec<&Artifact> {
        let mut result = Vec::new();
        for row in &self.hosts {
            result.extend([&row.archive, &row.inventory]);
            result.extend(row.rustup.artifacts());
            if let Some(deb) = &row.debian {
                result.push(deb);
            }
        }
        result.extend(self.crates.iter().map(|row| &row.archive));
        result.extend([
            &self.sources,
            &self.vendor,
            &self.homebrew_formula,
            &self.rustup_distribution.manifest,
            &self.rustup_distribution.checksum,
        ]);
        if let Some(application) = &self.reference_application {
            result.push(&application.archive);
        }
        result
    }

    pub fn toolchain_name(&self) -> String {
        format!("aros-{}", self.version)
    }

    pub fn package_prefix(&self) -> String {
        format!("libexec/ami-rust/{}", self.version)
    }

    /// Format the declared catalog URL. The caller must authenticate the
    /// reviewed commit and its content; this method does not fetch or trust it.
    /// A flat Release asset directory cannot provide rustup's dist/ hierarchy.
    pub fn rustup_dist_server(&self) -> String {
        format!(
            "https://raw.githubusercontent.com/metaneutrons/ami-rust/{}/distribution/rustup/{}",
            self.rustup_distribution.catalog_commit, self.version,
        )
    }

    pub fn rustup_manifest_files(&self) -> Result<RustupManifestFiles> {
        render_rustup_manifest(&RustupManifestRequest {
            version: self.version.clone(),
            epoch: self.source.epoch,
            rust_version: self.rustup_distribution.rust_version.clone(),
            cargo_version: self.rustup_distribution.cargo_version.clone(),
            release_tag: self.rustup_distribution.release_tag.clone(),
            hosts: self
                .hosts
                .iter()
                .map(|row| RustupManifestHost {
                    host: row.host,
                    components: row.rustup.clone(),
                })
                .collect(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        let reference_application = match (self.schema.as_str(), &self.reference_application) {
            (SCHEMA_V2, None) => None,
            (SCHEMA_V3, Some(application)) => Some(application),
            _ => {
                return Err(Refusal::new(
                    "toolchain release schema and reference application do not match",
                ));
            }
        };
        if self.target != TARGET {
            return Err(Refusal::new(
                "unsupported toolchain release schema or target",
            ));
        }
        let version = stable_version(&self.version)?;
        if let Some(application) = reference_application {
            if application.target != self.target || application.abi != "v1" {
                return Err(Refusal::new(
                    "native reference application target or ABI is unsupported",
                ));
            }
            artifact(
                &application.archive,
                &format!(
                    "ami-rust-sha256sum-{}-{}.tar.xz",
                    self.version, application.target
                ),
            )?;
        }
        if version <= [0, 1, 0] || self.package_revision == 0 {
            return Err(Refusal::new(
                "toolchain release requires a new version and positive package revision",
            ));
        }
        if !commit_id(&self.source.commit)
            || !commit_id(&self.source.tree)
            || self.source.epoch == 0
        {
            return Err(Refusal::new(
                "toolchain source commit/tree/epoch is invalid",
            ));
        }
        if self.rustup_distribution.channel != self.version
            || !commit_id(&self.rustup_distribution.catalog_commit)
            || self.rustup_distribution.catalog_commit == self.source.commit
        {
            return Err(Refusal::new(
                "rustup channel must match the SDK version and use a distinct catalog commit",
            ));
        }
        artifact(
            &self.rustup_distribution.manifest,
            &format!("channel-rust-{}.toml", self.version),
        )?;
        artifact(
            &self.rustup_distribution.checksum,
            &format!("channel-rust-{}.toml.sha256", self.version),
        )?;
        let hosts: BTreeSet<_> = self.hosts.iter().map(|row| row.host).collect();
        if self.hosts.len() != 3 || hosts != ReleaseHost::ALL.into_iter().collect() {
            return Err(Refusal::new(
                "toolchain release requires each of the three hosts exactly once",
            ));
        }
        for row in &self.hosts {
            let base = format!("ami-rust-toolchain-{}-{}", self.version, row.host.key());
            artifact(&row.archive, &format!("{base}.tar.xz"))?;
            artifact(&row.inventory, &format!("{base}.manifest.json"))?;
            for (component, payload) in ["rustc", "cargo", "rust-std"]
                .into_iter()
                .zip(row.rustup.artifacts())
            {
                artifact(
                    payload,
                    &format!(
                        "ami-rust-{component}-{}-{}.tar.xz",
                        self.version,
                        row.host.key(),
                    ),
                )?;
            }
            match (row.host.debian_architecture(), &row.debian) {
                (Some(arch), Some(deb)) => artifact(
                    deb,
                    &format!(
                        "ami-rust_{}-{}_{arch}.deb",
                        self.version, self.package_revision
                    ),
                )?,
                (None, None) => {}
                _ => {
                    return Err(Refusal::new(
                        "Debian payload must match the Linux host architecture",
                    ));
                }
            }
        }
        let rendered = self.rustup_manifest_files()?;
        rustup::require_rendered_identity(
            &self.rustup_distribution.manifest,
            &rendered.manifest_name,
            rendered.manifest.as_bytes(),
        )?;
        rustup::require_rendered_identity(
            &self.rustup_distribution.checksum,
            &rendered.checksum_name,
            rendered.checksum.as_bytes(),
        )?;
        artifact(
            &self.sources,
            &format!("ami-rust-{}-sources.tar.xz", self.version),
        )?;
        artifact(
            &self.vendor,
            &format!("ami-rust-{}-vendor.tar.xz", self.version),
        )?;
        artifact(&self.homebrew_formula, "ami-rust.rb")?;
        let names: BTreeSet<_> = self.crates.iter().map(|row| row.name.as_str()).collect();
        if self.crates.len() != CRATES.len() || names != CRATES.into_iter().collect() {
            return Err(Refusal::new(
                "toolchain release requires the eight public crates; amiga-sys is unpublished compatibility source",
            ));
        }
        for row in &self.crates {
            // Crate and SDK versions are separate identities. Publication
            // checks the version in each actual packaged Cargo manifest.
            stable_version(&row.version)?;
            artifact(&row.archive, &format!("{}-{}.crate", row.name, row.version))?;
            let deps: BTreeSet<_> = row.dependencies.iter().map(String::as_str).collect();
            if deps.len() != row.dependencies.len()
                || !deps.is_subset(&names)
                || deps.contains(row.name.as_str())
            {
                return Err(Refusal::new(
                    "invalid public crate workspace dependency set",
                ));
            }
        }
        self.publication_order()?;
        let assets = self.expected_assets();
        if assets.len() != assets.iter().collect::<BTreeSet<_>>().len() {
            return Err(Refusal::new("toolchain release asset names collide"));
        }
        Ok(())
    }

    /// Stable topological ordering. The producer must first bind these edges
    /// to the actual archives; declaration order is never publication order.
    pub fn publication_order(&self) -> Result<Vec<String>> {
        let mut pending: BTreeMap<_, _> = self
            .crates
            .iter()
            .map(|row| (row.name.clone(), row.dependencies.clone()))
            .collect();
        let mut published = BTreeSet::new();
        let mut result = Vec::new();
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .iter()
                .filter(|(_, deps)| deps.iter().all(|dep| published.contains(dep)))
                .map(|(name, _)| name.clone())
                .collect();
            if ready.is_empty() {
                return Err(Refusal::new(
                    "public crate dependency graph has a cycle or missing dependency",
                ));
            }
            for name in ready {
                pending.remove(&name);
                published.insert(name.clone());
                result.push(name);
            }
        }
        Ok(result)
    }

    /// One list drives signing, checksums, staging and public readback. SBOMs
    /// accompany payloads; metadata has signatures but no synthetic payload SBOM.
    /// SHA256SUMS excludes itself and is covered by GitHub provenance.
    pub fn expected_assets(&self) -> Vec<String> {
        let mut result = Vec::new();
        let mut payload = |name: &str| {
            result.extend([
                name.to_owned(),
                format!("{name}.spdx.json"),
                format!("{name}.sigstore.json"),
            ]);
        };
        for row in &self.hosts {
            payload(&row.archive.name);
            for component in row.rustup.artifacts() {
                payload(&component.name);
            }
            if let Some(deb) = &row.debian {
                payload(&deb.name);
            }
        }
        for row in &self.crates {
            payload(&row.archive.name);
        }
        payload(&self.sources.name);
        payload(&self.vendor.name);
        if let Some(application) = &self.reference_application {
            payload(&application.archive.name);
        }
        for name in self
            .hosts
            .iter()
            .map(|row| row.inventory.name.as_str())
            .chain([
                self.homebrew_formula.name.as_str(),
                self.rustup_distribution.manifest.name.as_str(),
                self.rustup_distribution.checksum.name.as_str(),
                "toolchain-release.json",
            ])
        {
            result.extend([name.to_owned(), format!("{name}.sigstore.json")]);
        }
        result.push("SHA256SUMS".to_owned());
        result.sort();
        result
    }
}

fn stable_version(value: &str) -> Result<[u64; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(Refusal::new(
            "toolchain version must be canonical stable SemVer",
        ));
    }
    let mut result = [0; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Refusal::new(
                "toolchain version must be canonical stable SemVer",
            ));
        }
        result[index] = part
            .parse()
            .map_err(|_| Refusal::new("toolchain version component overflow"))?;
    }
    Ok(result)
}

fn commit_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn artifact(value: &Artifact, expected: &str) -> Result<()> {
    if value.name != expected || value.bytes == 0 {
        return Err(Refusal::new(format!(
            "release artifact identity mismatch: expected {expected}"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "toolchain_release_tests.rs"]
mod tests;
