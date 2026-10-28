//! Canonical standard-rustup metadata, bound to the release's nine components.
//! Rendering validates declarations only, not archives or publisher identity.
use super::{Artifact, ReleaseHost, RustupComponents, artifact, stable_version};
use crate::{Refusal, Result, digest::sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustupManifestHost {
    pub host: ReleaseHost,
    pub components: RustupComponents,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustupManifestRequest {
    pub version: String,
    pub epoch: u64,
    pub rust_version: String,
    pub cargo_version: String,
    pub release_tag: String,
    pub hosts: Vec<RustupManifestHost>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustupManifestFiles {
    pub manifest_name: String,
    pub manifest: String,
    pub checksum_name: String,
    pub checksum: String,
}

pub fn render_rustup_manifest(spec: &RustupManifestRequest) -> Result<RustupManifestFiles> {
    if stable_version(&spec.version)? <= [0, 1, 0] {
        return Err(Refusal::new("rustup requires a new stable SDK version"));
    }
    let date = date(spec.epoch)?;
    for version in [&spec.rust_version, &spec.cargo_version] {
        if version.trim().is_empty()
            || version.len() > 512
            || !version.bytes().all(|b| (b' '..=b'~').contains(&b))
        {
            return Err(Refusal::new(
                "rustup tool versions must be bounded printable ASCII",
            ));
        }
    }
    let tag_base = format!("v{}", spec.version);
    if spec.release_tag != tag_base {
        let prefix = format!("{tag_base}-qualification.");
        let suffix = spec
            .release_tag
            .strip_prefix(&prefix)
            .ok_or_else(|| Refusal::new("rustup release tag does not match the SDK"))?;
        if suffix.starts_with('0')
            || suffix.is_empty()
            || !suffix.bytes().all(|b| b.is_ascii_digit())
            || suffix.parse::<u64>().is_err()
        {
            return Err(Refusal::new("invalid rustup qualification release tag"));
        }
    }
    if spec.hosts.len() != 3
        || spec.hosts.iter().map(|h| h.host).collect::<BTreeSet<_>>()
            != ReleaseHost::ALL.into_iter().collect()
    {
        return Err(Refusal::new(
            "rustup requires each supported host exactly once",
        ));
    }
    for row in &spec.hosts {
        for (component, payload) in ["rustc", "cargo", "rust-std"]
            .into_iter()
            .zip(row.components.artifacts())
        {
            artifact(
                payload,
                &format!(
                    "ami-rust-{component}-{}-{}.tar.xz",
                    spec.version,
                    row.host.key()
                ),
            )?;
        }
    }
    let mut rows = vec![
        "manifest-version = \"2\"".to_owned(),
        format!("date = {}", quote(&date)),
        String::new(),
        "[profiles]".to_owned(),
        "minimal = [\"rustc\", \"cargo\", \"rust-std\"]".to_owned(),
        "default = [\"rustc\", \"cargo\", \"rust-std\"]".to_owned(),
        "complete = [\"rustc\", \"cargo\", \"rust-std\"]".to_owned(),
        String::new(),
        "[pkg.rust]".to_owned(),
        format!("version = {}", quote(&spec.rust_version)),
    ];
    for host in ReleaseHost::ALL {
        let triple = host.rust_triple();
        rows.extend([
            String::new(),
            format!("[pkg.rust.target.{triple}]"),
            "available = true".to_owned(),
            "components = [".to_owned(),
        ]);
        for component in ["rustc", "cargo", "rust-std"] {
            rows.push(format!(
                "  {{ pkg = \"{component}\", target = \"{triple}\" }},"
            ));
        }
        rows.push("]".to_owned());
    }
    for (index, component) in ["rustc", "cargo", "rust-std"].into_iter().enumerate() {
        let version = if component == "cargo" {
            &spec.cargo_version
        } else {
            &spec.rust_version
        };
        rows.extend([
            String::new(),
            format!("[pkg.{component}]"),
            format!("version = {}", quote(version)),
        ]);
        for host in ReleaseHost::ALL {
            let row = spec
                .hosts
                .iter()
                .find(|row| row.host == host)
                .ok_or_else(|| Refusal::new("missing rustup host"))?;
            let payload = row.components.artifacts()[index];
            let url = format!(
                "https://github.com/metaneutrons/ami-rust/releases/download/{}/{}",
                spec.release_tag, payload.name
            );
            rows.extend([
                String::new(),
                format!("[pkg.{component}.target.{}]", host.rust_triple()),
                "available = true".to_owned(),
                format!("xz_url = {}", quote(&url)),
                format!("xz_hash = {}", quote(payload.sha256.as_str())),
            ]);
        }
    }
    let manifest_name = format!("channel-rust-{}.toml", spec.version);
    let manifest = rows.join("\n") + "\n";
    let checksum = format!("{}  {manifest_name}\n", sha256_bytes(manifest.as_bytes()));
    Ok(RustupManifestFiles {
        checksum_name: format!("{manifest_name}.sha256"),
        manifest_name,
        manifest,
        checksum,
    })
}

pub(super) fn require_rendered_identity(row: &Artifact, name: &str, bytes: &[u8]) -> Result<()> {
    artifact(row, name)?;
    if row.bytes != bytes.len() as u64 || row.sha256.as_str() != sha256_bytes(bytes) {
        return Err(Refusal::new(
            "rustup metadata identity differs from canonical component-bound rendering",
        ));
    }
    Ok(())
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn date(epoch: u64) -> Result<String> {
    // Bounded Gregorian calendar conversion; no platform time_t assumptions.
    if epoch == 0 || epoch > 253_402_300_799 {
        return Err(Refusal::new(
            "rustup source epoch is outside years 1970..9999",
        ));
    }
    let mut days = epoch / 86_400;
    let mut year = 1970_u64;
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for length in months {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    Ok(format!("{year:04}-{month:02}-{:02}", days + 1))
}

#[cfg(test)]
mod tests {
    use super::date;
    #[test]
    fn utc_calendar_handles_leap_centuries_and_range() {
        for (epoch, expected) in [
            (1, "1970-01-01"),
            (951_782_400, "2000-02-29"),
            (4_107_542_400, "2100-03-01"),
            (253_402_300_799, "9999-12-31"),
        ] {
            assert_eq!(date(epoch).unwrap(), expected);
        }
        assert!(date(0).is_err());
        assert!(date(253_402_300_800).is_err());
    }
}
