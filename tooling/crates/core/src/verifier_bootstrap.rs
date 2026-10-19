//! Acquire the fixed publisher-verifier TCB without an interpreter bootstrap.
//! The operating system supplies curl/TLS; compiled archive and executable
//! digests select GH/Cosign. Downloaded tools never authenticate themselves.
use crate::{
    Refusal, Result,
    acquisition::{
        AcquisitionObservationConfig, CurlExecutablePin, DownloadLimits, DownloadPin, HttpsOrigin,
        acquire_pinned_download,
    },
    baseline::InitialBaseline,
    consumer_session::ConsumerSession,
    digest::sha256_bytes,
    directory::Directory,
    ownership,
    package_records::NativePackagePins,
    publisher_files::{read_bundle_file, read_open_regular},
    publisher_policy::parse_publisher_policy,
    resource_capture::{ResourceLimits, SampleLimits},
    signals::SigtermGuard,
    workspace_accounting::ScanLimits,
};
use serde_json::Value;
use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct PublisherBootstrap {
    pub policy_path: PathBuf,
    pub inputs: Vec<u8>,
}

pub fn bootstrap_verifiers(
    session: &mut ConsumerSession<'_>,
    source: &Path,
    pins: &NativePackagePins,
    baseline: &InitialBaseline,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<PublisherBootstrap> {
    pins.host.ensure_current()?;
    session.recheck_root()?;
    let source_root = Directory::open(source)?;
    let auth = &baseline.runtime_acquisition()["authentication"];
    let manifest_pin = &auth["tool_pin_manifest"];
    let manifest = read_bundle_file(&source_root, text(manifest_pin, "path")?, 1024 * 1024)?;
    check_identity(&manifest, manifest_pin, "bytes", "sha256")?;
    let tools = &auth["tools_by_host"][host_name(pins.host)];
    let state = ownership::existing_private_state(session.path())?;
    let work = state.mkdir_new(OsStr::new("publisher-bootstrap"), 0o700)?;
    let tools_root = work.mkdir_new(OsStr::new("tools"), 0o700)?;
    let trust_root = work.mkdir_new(OsStr::new("trust"), 0o700)?;
    let work_path = session.path().join("publisher-bootstrap");
    // Policy path strings must be representable before the first acquisition.
    let tools_path = work_path.join("tools");
    let trust_path = work_path.join("trust");
    if tools_path.to_str().is_none() || trust_path.to_str().is_none() {
        return Err(Refusal::new("publisher policy paths must be valid UTF-8"));
    }
    let observation = AcquisitionObservationConfig {
        resource_limits: ResourceLimits {
            max_visible_rss_bytes: 4 * 1024 * 1024 * 1024,
            max_workspace_bytes: 12 * 1024 * 1024 * 1024,
            max_log_bytes: 16 * 1024 * 1024,
        },
        sample_limits: SampleLimits {
            max_ps_bytes: 2 * 1024 * 1024,
            max_ps_rows: 32768,
            max_history_entries: 131072,
            max_roots: 1,
            scan: ScanLimits {
                max_entries: 100000,
                max_work_units: 200001,
            },
        },
        required_roots: vec![session.path().to_path_buf()],
    };
    for tool in ["gh", "cosign"] {
        signals.check()?;
        let pin = &tools[tool];
        let archive_name = format!("{tool}.download");
        let destination = ownership::fresh_output(&work_path.join(&archive_name))?;
        let download = DownloadPin::new(
            text(pin, "url")?,
            count(pin, "download_bytes")?,
            text(pin, "download_sha256")?,
            HttpsOrigin::Github,
            [HttpsOrigin::GithubReleaseAssets, HttpsOrigin::GithubObjects],
        )?;
        let receipt = acquire_pinned_download(
            &download,
            curl,
            &destination,
            DownloadLimits {
                max_bytes: count(pin, "download_bytes")?,
                total_timeout: Duration::from_secs(1200),
                per_hop_timeout: Duration::from_secs(300),
                termination_grace: Duration::from_secs(2),
                max_redirects: 5,
                max_header_bytes: 64 * 1024,
                max_stderr_bytes: 64 * 1024,
            },
            &observation,
            || signals.requested(),
        )?;
        write_new(
            &work,
            &format!("{tool}-acquisition.json"),
            &serde_json::to_vec_pretty(&receipt.resource_reports)
                .map_err(|e| Refusal::new(e.to_string()))?,
            0o600,
        )?;
        let raw = read_open_regular(
            work.regular(OsStr::new(&archive_name))?,
            count(pin, "download_bytes")? as usize,
        )?;
        check_identity(&raw, pin, "download_bytes", "download_sha256")?;
        let binary = if tool == "cosign" {
            raw
        } else {
            let member = text(pin, "archive_member")?;
            match pins.host {
                crate::records::Host::MacosAarch64 => {
                    selected_zip_member(&raw, member, count(pin, "binary_bytes")?, || {
                        signals.check()
                    })?
                }
                crate::records::Host::LinuxX86_64 => {
                    selected_gzip_tar_member(&raw, member, count(pin, "binary_bytes")?, || {
                        signals.check()
                    })?
                }
            }
        };
        check_identity(&binary, pin, "binary_bytes", "binary_sha256")?;
        write_new(&tools_root, tool, &binary, 0o755)?;
        work.unlink_entry(OsStr::new(&archive_name))?;
    }
    for root in ["gh", "cosign"] {
        signals.check()?;
        let pin = &auth["trust_roots"][root];
        let bytes = read_bundle_file(&source_root, text(pin, "path")?, 16 * 1024 * 1024)?;
        check_identity(&bytes, pin, "bytes", "sha256")?;
        write_new(&trust_root, root, &bytes, 0o600)?;
    }
    let inputs = crate::publisher_materials::publisher_input_manifest(source, || signals.check())?;
    write_new(&trust_root, "inputs.json", &inputs, 0o600)?;
    let policy = serde_json::json!({
        "schema":"ami-rust-publisher-trust-v2", "repository":pins.repository,
        "workflow":".github/workflows/sdk-qualify.yml", "workflow_sha":pins.source_commit,
        "source_sha":pins.source_commit, "source_ref":"refs/heads/main",
        "oidc_issuer":"https://token.actions.githubusercontent.com",
        "cert_identity":"https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
        "inputs_manifest_sha256":sha256_bytes(&inputs), "allowed_host_profiles":["macos-aarch64","linux-x86_64"],
        "gh":{"path":tools_path.join("gh").to_str().unwrap(), "sha256":tools["gh"]["binary_sha256"]},
        "cosign":{"path":tools_path.join("cosign").to_str().unwrap(), "sha256":tools["cosign"]["binary_sha256"]},
        "gh_trusted_roots":{"path":trust_path.join("gh").to_str().unwrap(),"sha256":auth["trust_roots"]["gh"]["sha256"]},
        "cosign_trusted_root":{"path":trust_path.join("cosign").to_str().unwrap(),"sha256":auth["trust_roots"]["cosign"]["sha256"]},
    });
    let mut raw = serde_json::to_vec_pretty(&policy).map_err(|e| Refusal::new(e.to_string()))?;
    raw.push(b'\n');
    parse_publisher_policy(&raw)?;
    write_new(&trust_root, "publisher-policy.json", &raw, 0o600)?;
    session.recheck_root()?;
    Ok(PublisherBootstrap {
        policy_path: trust_path.join("publisher-policy.json"),
        inputs,
    })
}

fn host_name(host: crate::records::Host) -> &'static str {
    match host {
        crate::records::Host::LinuxX86_64 => "linux-x86_64",
        crate::records::Host::MacosAarch64 => "macos-aarch64",
    }
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| Refusal::new(format!("verifier pin misses {name}")))
}
fn count(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .ok_or_else(|| Refusal::new(format!("verifier pin misses {name}")))
}
fn check_identity(raw: &[u8], pin: &Value, bytes: &str, digest: &str) -> Result<()> {
    if raw.len() as u64 != count(pin, bytes)? || sha256_bytes(raw) != text(pin, digest)? {
        return Err(Refusal::new(
            "verifier input differs from its compiled baseline pin",
        ));
    }
    Ok(())
}
fn write_new(root: &Directory, name: &str, raw: &[u8], mode: u32) -> Result<()> {
    let mut file = root.create_new_file(OsStr::new(name), mode)?;
    file.write_all(raw)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn selected_gzip_tar_member(
    raw: &[u8],
    selected: &str,
    bytes: u64,
    mut cancelled: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    crate::compression::copy_gzip(
        raw,
        &mut decoded,
        crate::compression::DecodeLimits {
            max_compressed_bytes: 32 * 1024 * 1024,
            max_decoded_bytes: 256 * 1024 * 1024,
            max_xz_memory_kib: 1,
        },
    )?;
    cancelled()?;
    let mut archive = tar::Archive::new(decoded.as_slice());
    let mut selected_bytes = None;
    for (index, entry) in archive
        .entries()
        .map_err(|e| Refusal::new(e.to_string()))?
        .enumerate()
    {
        cancelled()?;
        if index >= 10000 {
            return Err(Refusal::new("verifier archive exceeds member bound"));
        }
        let mut entry = entry.map_err(|e| Refusal::new(e.to_string()))?;
        if entry.path_bytes().as_ref() == selected.as_bytes() {
            if selected_bytes.is_some()
                || !entry.header().entry_type().is_file()
                || entry.size() != bytes
            {
                return Err(Refusal::new(
                    "verifier archive does not have one exact regular executable",
                ));
            }
            selected_bytes = Some(read_exact_member(&mut entry, bytes, &mut cancelled)?);
        }
    }
    selected_bytes
        .ok_or_else(|| Refusal::new("verifier executable is absent from its authenticated archive"))
}

/// Read the one selected member from an authenticated ordinary ZIP. Nothing
/// is extracted by path; unsupported/encrypted/ZIP64/multidisk inputs refuse.
fn selected_zip_member(
    raw: &[u8],
    selected: &str,
    bytes: u64,
    mut cancelled: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let minimum = raw.len().saturating_sub(65557);
    let end = (minimum..raw.len().saturating_sub(21))
        .rev()
        .find(|&p| raw.get(p..p + 4) == Some(b"PK\x05\x06"))
        .ok_or_else(|| Refusal::new("verifier ZIP end record is missing"))?;
    if read16(raw, end + 4)? != 0
        || read16(raw, end + 6)? != 0
        || read16(raw, end + 8)? != read16(raw, end + 10)?
        || read16(raw, end + 10)? == u16::MAX
        || read16(raw, end + 10)? > 10000
        || end.checked_add(22 + read16(raw, end + 20)? as usize) != Some(raw.len())
    {
        return Err(Refusal::new("unsupported verifier ZIP layout"));
    }
    let central = read32(raw, end + 16)? as usize;
    let size = read32(raw, end + 12)? as usize;
    if central.checked_add(size) != Some(end) {
        return Err(Refusal::new("verifier ZIP central directory range differs"));
    }
    let mut cursor = central;
    let mut result = None;
    for _ in 0..read16(raw, end + 10)? {
        cancelled()?;
        if raw.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            return Err(Refusal::new("invalid verifier ZIP directory header"));
        }
        let flags = read16(raw, cursor + 8)?;
        let method = read16(raw, cursor + 10)?;
        let compressed = read32(raw, cursor + 20)? as usize;
        let expanded = read32(raw, cursor + 24)? as u64;
        let name_len = read16(raw, cursor + 28)? as usize;
        let extra_len = read16(raw, cursor + 30)? as usize;
        let comment_len = read16(raw, cursor + 32)? as usize;
        let name = raw
            .get(cursor + 46..cursor + 46 + name_len)
            .ok_or_else(|| Refusal::new("truncated verifier ZIP name"))?;
        if name == selected.as_bytes() {
            let mode = read32(raw, cursor + 38)? >> 16;
            if result.is_some()
                || flags & 1 != 0
                || ![0, 8].contains(&method)
                || expanded != bytes
                || mode & 0o170000 == 0o120000
                || read16(raw, cursor + 34)? != 0
                || compressed == u32::MAX as usize
            {
                return Err(Refusal::new("unsupported verifier ZIP executable member"));
            }
            let local = read32(raw, cursor + 42)? as usize;
            if raw.get(local..local + 4) != Some(b"PK\x03\x04")
                || read16(raw, local + 6)? != flags
                || read16(raw, local + 8)? != method
            {
                return Err(Refusal::new("verifier ZIP local header disagrees"));
            }
            let local_name_len = read16(raw, local + 26)? as usize;
            let start = local
                .checked_add(30 + local_name_len + read16(raw, local + 28)? as usize)
                .ok_or_else(|| Refusal::new("verifier ZIP data offset overflow"))?;
            if raw.get(local + 30..local + 30 + local_name_len) != Some(name)
                || start
                    .checked_add(compressed)
                    .is_none_or(|limit| limit > central)
            {
                return Err(Refusal::new("verifier ZIP member range differs"));
            }
            let compressed = &raw[start..start + compressed];
            let output = if method == 0 {
                read_exact_member(&mut std::io::Cursor::new(compressed), bytes, &mut cancelled)?
            } else {
                read_exact_member(
                    &mut flate2::read::DeflateDecoder::new(compressed),
                    bytes,
                    &mut cancelled,
                )?
            };
            if crc32(&output) != read32(raw, cursor + 16)? {
                return Err(Refusal::new("verifier ZIP executable CRC mismatch"));
            }
            result = Some(output);
        }
        cursor = cursor
            .checked_add(46 + name_len + extra_len + comment_len)
            .filter(|offset| *offset <= end)
            .ok_or_else(|| Refusal::new("verifier ZIP directory overflow"))?;
    }
    if cursor != end {
        return Err(Refusal::new("verifier ZIP directory has trailing bytes"));
    }
    result.ok_or_else(|| Refusal::new("verifier executable is absent from its authenticated ZIP"))
}
fn read_exact_member(
    input: &mut impl Read,
    bytes: u64,
    cancelled: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    if bytes > 256 * 1024 * 1024 {
        return Err(Refusal::new(
            "verifier binary exceeds the bootstrap profile",
        ));
    }
    let mut output = Vec::new();
    let mut block = [0; 64 * 1024];
    loop {
        cancelled()?;
        let amount = input.read(&mut block)?;
        if amount == 0 {
            break;
        }
        if (output.len() as u64)
            .checked_add(amount as u64)
            .is_none_or(|n| n > bytes)
        {
            return Err(Refusal::new("verifier binary is longer than its pin"));
        }
        output.extend_from_slice(&block[..amount]);
    }
    if output.len() as u64 != bytes {
        return Err(Refusal::new("verifier binary length differs from its pin"));
    }
    Ok(output)
}
fn read16(raw: &[u8], offset: usize) -> Result<u16> {
    raw.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| Refusal::new("truncated verifier ZIP integer"))
}
fn read32(raw: &[u8], offset: usize) -> Result<u32> {
    raw.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| Refusal::new("truncated verifier ZIP integer"))
}
fn crc32(raw: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in raw {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zip(method: u16) -> (Vec<u8>, usize) {
        let name = b"release/bin/gh";
        let payload = b"pinned verifier fixture";
        let mut body = payload.to_vec();
        if method == 8 {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(payload).unwrap();
            body = encoder.finish().unwrap();
        }
        let mut local = vec![0_u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&20_u16.to_le_bytes());
        local[8..10].copy_from_slice(&method.to_le_bytes());
        local[14..18].copy_from_slice(&crc32(payload).to_le_bytes());
        local[18..22].copy_from_slice(&(body.len() as u32).to_le_bytes());
        local[22..26].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&body);
        let central_offset = local.len();
        let mut central = vec![0_u8; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[4..6].copy_from_slice(&0x0314_u16.to_le_bytes());
        central[6..8].copy_from_slice(&20_u16.to_le_bytes());
        central[10..12].copy_from_slice(&method.to_le_bytes());
        central[16..20].copy_from_slice(&crc32(payload).to_le_bytes());
        central[20..24].copy_from_slice(&(body.len() as u32).to_le_bytes());
        central[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        central[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        central[38..42].copy_from_slice(&(0o100755_u32 << 16).to_le_bytes());
        central.extend_from_slice(name);
        let mut end = vec![0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&1_u16.to_le_bytes());
        end[10..12].copy_from_slice(&1_u16.to_le_bytes());
        end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
        end[16..20].copy_from_slice(&(central_offset as u32).to_le_bytes());
        local.extend_from_slice(&central);
        local.extend_from_slice(&end);
        (local, central_offset)
    }

    #[test]
    fn selected_zip_checks_deflate_stored_crc_bounds_headers_and_cancellation() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        for method in [0, 8] {
            let (raw, central) = zip(method);
            let read =
                |raw: &[u8], bytes| selected_zip_member(raw, "release/bin/gh", bytes, || Ok(()));
            assert_eq!(read(&raw, 23).unwrap(), b"pinned verifier fixture");
            assert!(read(&raw, 22).is_err());
            assert!(read(&raw[..raw.len() - 1], 23).is_err());
            assert!(selected_zip_member(&raw, "other/bin/gh", 23, || Ok(())).is_err());
            assert!(
                selected_zip_member(&raw, "release/bin/gh", 23, || Err(Refusal::new(
                    "cancelled"
                )))
                .is_err()
            );
            let mut bad = raw.clone();
            bad[central + 16] ^= 1;
            assert!(read(&bad, 23).unwrap_err().to_string().contains("CRC"));
            let mut bad = raw.clone();
            bad[central + 8] |= 1;
            assert!(read(&bad, 23).is_err());
            let mut bad = raw.clone();
            bad[8..10].copy_from_slice(&99_u16.to_le_bytes());
            assert!(read(&bad, 23).is_err());
        }
    }

    #[test]
    fn selected_gzip_member_requires_complete_gzip_and_exact_unique_file() {
        let payload = b"pinned verifier fixture";
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "release/bin/gh", payload.as_slice())
            .unwrap();
        let plain = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).unwrap();
        let raw = encoder.finish().unwrap();
        assert_eq!(
            selected_gzip_tar_member(&raw, "release/bin/gh", 23, || Ok(())).unwrap(),
            payload
        );
        assert!(selected_gzip_tar_member(&raw, "release/bin/gh", 22, || Ok(())).is_err());
        assert!(
            selected_gzip_tar_member(&raw[..raw.len() - 1], "release/bin/gh", 23, || Ok(()))
                .is_err()
        );
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(selected_gzip_tar_member(&trailing, "release/bin/gh", 23, || Ok(())).is_err());
    }
}
