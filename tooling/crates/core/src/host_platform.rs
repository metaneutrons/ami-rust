//! Host selection from kernel identity and the platform's installed OS record.
//!
//! Environment variables and command lookup do not participate. Linux reads
//! the canonical target of `/etc/os-release` as a protected bounded regular
//! file; the conventional `/etc/os-release` symlink is therefore permitted.

use crate::{Refusal, Result, records::Host};

#[cfg(target_os = "linux")]
const MAX_OS_RELEASE_BYTES: usize = 2 * 1024 * 1024;

/// Identify one of the two supported native host profiles.
pub fn supported_host() -> Result<Host> {
    let (kernel, machine) = kernel_identity()?;

    #[cfg(target_os = "macos")]
    {
        let product_version = macos_product_version()?;
        macos_profile(&kernel, &machine, std::env::consts::ARCH, &product_version)
    }

    #[cfg(target_os = "linux")]
    {
        let release = linux_os_release()?;
        linux_profile(&kernel, &machine, std::env::consts::ARCH, &release)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (kernel, machine);
        Err(Refusal::new("unsupported native host profile"))
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_profile(
    kernel_name: &str,
    kernel_machine: &str,
    compiled_arch: &str,
    product_version: &str,
) -> Result<Host> {
    if kernel_name != "Darwin" {
        return Err(Refusal::new("running kernel is not macOS"));
    }
    if kernel_machine != "arm64" || compiled_arch != "aarch64" {
        return Err(Refusal::new(
            "supported macOS host requires arm64 kernel and aarch64 executable",
        ));
    }
    let major = product_version.split('.').next().unwrap_or_default();
    if major != "26" {
        return Err(Refusal::new(
            "supported macOS host requires product major version 26",
        ));
    }
    Ok(Host::MacosAarch64)
}

#[cfg(any(target_os = "linux", test))]
fn linux_profile(
    kernel_name: &str,
    kernel_machine: &str,
    compiled_arch: &str,
    os_release: &[u8],
) -> Result<Host> {
    if kernel_name != "Linux" {
        return Err(Refusal::new("running kernel is not Linux"));
    }
    if kernel_machine != "x86_64" || compiled_arch != "x86_64" {
        return Err(Refusal::new(
            "supported Linux host requires x86_64 kernel and executable",
        ));
    }
    let (id, version_id) = parse_os_release(os_release)?;
    if id != "ubuntu" || version_id != "24.04" {
        return Err(Refusal::new("supported Linux host requires Ubuntu 24.04"));
    }
    Ok(Host::LinuxX86_64)
}

#[cfg(any(target_os = "linux", test))]
fn parse_os_release(raw: &[u8]) -> Result<(&str, &str)> {
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) || raw.contains(&0) {
        return Err(Refusal::new("OS release record has a BOM or NUL byte"));
    }
    if raw
        .iter()
        .any(|byte| (*byte < 0x20 && !matches!(*byte, b'\n' | b'\r' | b'\t')) || *byte == 0x7f)
    {
        return Err(Refusal::new("OS release record contains control bytes"));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| Refusal::new("OS release record is not valid UTF-8"))?;
    let mut id = None;
    let mut version_id = None;

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let slot = match key {
            "ID" => &mut id,
            "VERSION_ID" => &mut version_id,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Refusal::new(format!("OS release record repeats {key}")));
        }
        *slot = Some(parse_selector_value(value)?);
    }

    let id = id.ok_or_else(|| Refusal::new("OS release record is missing ID"))?;
    let version_id =
        version_id.ok_or_else(|| Refusal::new("OS release record is missing VERSION_ID"))?;
    Ok((id, version_id))
}

#[cfg(any(target_os = "linux", test))]
fn parse_selector_value(raw: &str) -> Result<&str> {
    let value = if raw.starts_with('"') {
        if raw.len() < 2 || !raw.ends_with('"') {
            return Err(Refusal::new("OS release selector has malformed quotes"));
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.contains('"') || inner.contains('\\') {
            return Err(Refusal::new(
                "OS release selector uses unsupported quoting or escapes",
            ));
        }
        inner
    } else if raw.contains('"') || raw.contains('\\') || raw.contains('\'') {
        return Err(Refusal::new("OS release selector has malformed quoting"));
    } else {
        raw
    };
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Refusal::new(
            "OS release selector is empty or contains whitespace/control characters",
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn linux_os_release() -> Result<Vec<u8>> {
    use std::{fs, path::Path};

    let link = Path::new("/etc/os-release");
    let canonical = fs::canonicalize(link)
        .map_err(|error| Refusal::new(format!("could not resolve /etc/os-release: {error}")))?;
    let file = crate::ownership::protected_regular_file(&canonical, false)?;
    crate::publisher_files::read_open_regular(file, MAX_OS_RELEASE_BYTES)
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "The kernel product-version selector is read through the fixed sysctl name and a bounded buffer."
)]
fn macos_product_version() -> Result<String> {
    use std::ptr;

    let name = c"kern.osproductversion";
    let mut buffer = [0_u8; 64];
    let mut length = buffer.len();
    // SAFETY: name is a valid static C string; buffer and length are writable
    // for the supplied capacity, and no new value is passed to sysctl.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 || length == 0 || length > buffer.len() {
        return Err(Refusal::new("could not read bounded macOS product version"));
    }
    let end = buffer[..length]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Refusal::new("macOS product version is not NUL terminated"))?;
    let value = std::str::from_utf8(&buffer[..end])
        .map_err(|_| Refusal::new("macOS product version is not valid UTF-8"))?;
    if value.is_empty()
        || !value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(Refusal::new("macOS product version is malformed"));
    }
    Ok(value.to_owned())
}

#[allow(
    unsafe_code,
    reason = "uname reads kernel-provided identity into a fully initialized fixed-size struct."
)]
fn kernel_identity() -> Result<(String, String)> {
    use std::{ffi::CStr, mem::MaybeUninit};

    let mut identity = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: uname initializes the fixed-size utsname structure on success.
    if unsafe { libc::uname(identity.as_mut_ptr()) } != 0 {
        return Err(Refusal::new("could not read kernel identity"));
    }
    // SAFETY: successful uname initialized the complete structure and each
    // identity field is NUL terminated by the platform ABI.
    let identity = unsafe { identity.assume_init() };
    // SAFETY: uname supplies NUL-terminated sysname and machine arrays.
    let kernel = unsafe { CStr::from_ptr(identity.sysname.as_ptr()) };
    // SAFETY: uname supplies NUL-terminated sysname and machine arrays.
    let machine = unsafe { CStr::from_ptr(identity.machine.as_ptr()) };
    let kernel = std::str::from_utf8(kernel.to_bytes())
        .map_err(|_| Refusal::new("kernel name is not valid UTF-8"))?
        .to_owned();
    let machine = std::str::from_utf8(machine.to_bytes())
        .map_err(|_| Refusal::new("kernel architecture is not valid UTF-8"))?
        .to_owned();
    Ok((kernel, machine))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_os_release_selector_forms_without_evaluation() {
        assert_eq!(
            parse_os_release(b"ID=ubuntu\nVERSION_ID=24.04\nNAME=Ubuntu\n").unwrap(),
            ("ubuntu", "24.04")
        );
        assert_eq!(
            parse_os_release(b"ID=\"ubuntu\"\nVERSION_ID=\"24.04\"\n").unwrap(),
            ("ubuntu", "24.04")
        );
        assert_eq!(
            parse_os_release(b"ID=$(id)\nVERSION_ID=24.04\n").unwrap(),
            ("$(id)", "24.04")
        );
        assert!(
            linux_profile("Linux", "x86_64", "x86_64", b"ID=$(id)\nVERSION_ID=24.04\n").is_err()
        );
    }

    #[test]
    fn refuses_missing_duplicate_malformed_or_non_utf8_os_release_selectors() {
        let malformed: &[&[u8]] = &[
            b"VERSION_ID=24.04\n",
            b"ID=ubuntu\n",
            b"ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n",
            b"ID=ubuntu\nVERSION_ID=24.04\nVERSION_ID=24.04\n",
            b"ID=\"ubuntu\nVERSION_ID=24.04\n",
            b"ID='ubuntu'\nVERSION_ID=24.04\n",
            &[
                0xef, 0xbb, 0xbf, b'I', b'D', b'=', b'u', b'b', b'u', b'n', b't', b'u', b'\n',
            ],
            &[b'I', b'D', b'=', 0xff, b'\n'],
            &[
                b'I', b'D', b'=', b'u', b'b', b'u', b'n', b't', b'u', 0x7f, b'\n',
            ],
        ];
        for raw in malformed {
            assert!(parse_os_release(raw).is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn linux_profile_requires_kernel_binary_and_os_release_to_agree() {
        let release = b"ID=ubuntu\nVERSION_ID=24.04\n";
        assert_eq!(
            linux_profile("Linux", "x86_64", "x86_64", release).unwrap(),
            Host::LinuxX86_64
        );
        assert!(linux_profile("FreeBSD", "x86_64", "x86_64", release).is_err());
        assert!(linux_profile("Linux", "aarch64", "x86_64", release).is_err());
        assert!(linux_profile("Linux", "x86_64", "aarch64", release).is_err());
        assert!(
            linux_profile(
                "Linux",
                "x86_64",
                "x86_64",
                b"ID=debian\nVERSION_ID=24.04\n"
            )
            .is_err()
        );
        assert!(
            linux_profile(
                "Linux",
                "x86_64",
                "x86_64",
                b"ID=ubuntu\nVERSION_ID=22.04\n"
            )
            .is_err()
        );
    }

    #[test]
    fn macos_profile_requires_kernel_binary_and_product_major_to_agree() {
        assert_eq!(
            macos_profile("Darwin", "arm64", "aarch64", "26.0.0").unwrap(),
            Host::MacosAarch64
        );
        assert!(macos_profile("FreeBSD", "arm64", "aarch64", "26.0.0").is_err());
        assert!(macos_profile("Darwin", "x86_64", "aarch64", "26.0.0").is_err());
        assert!(macos_profile("Darwin", "arm64", "x86_64", "26.0.0").is_err());
        assert!(macos_profile("Darwin", "arm64", "aarch64", "15.0.0").is_err());
    }

    #[test]
    fn native_detection_matches_compiled_host_on_supported_ci() {
        assert_eq!(supported_host().unwrap(), Host::current().unwrap());
    }
}
