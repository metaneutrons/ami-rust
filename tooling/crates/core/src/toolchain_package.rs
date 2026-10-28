//! Deterministic rust-installer v3 archives from a verified portable SDK tree.
//!
//! The caller supplies the typed receipt returned by `native_prefix`. This
//! module verifies that complete regular-file view before and after packaging,
//! partitions it into rustc, Cargo and host rust-std components, and writes
//! fresh TAR.XZ archives. It performs no acquisition, signing or publication.

use crate::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_file},
    files::validate_relative_inventory_path,
    inventory::{FileIdentity, InventoryLimits, verify_complete},
};
use lzma_rust2::{XzOptions, XzWriter};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use tar::{Builder, EntryType, Header};

const MAX_ENTRIES: usize = 20_000;
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub struct RustupPackageRequest<'a> {
    pub prefix: &'a Path,
    pub output: &'a Path,
    pub host_key: &'a str,
    pub rust_host_triple: &'a str,
    pub version: &'a str,
    pub epoch: u64,
    pub files: &'a [FileIdentity],
}

pub struct NativePackageRequest<'a> {
    pub prefix: &'a Path,
    pub output: &'a Path,
    pub host_key: &'a str,
    pub version: &'a str,
    pub epoch: u64,
    pub files: &'a [FileIdentity],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackagedArtifact {
    pub role: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RustupPackageReceipt {
    pub artifacts: Vec<PackagedArtifact>,
    pub ownership: BTreeMap<String, Vec<FileIdentity>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NativePackageReceipt {
    pub artifacts: Vec<PackagedArtifact>,
}

struct Component {
    name: String,
    label: &'static str,
    files: Vec<FileIdentity>,
}

pub fn package_rustup_components(
    request: RustupPackageRequest<'_>,
    mut check: impl FnMut() -> Result<()>,
) -> Result<RustupPackageReceipt> {
    validate_version(request.version)?;
    if request.epoch == 0 || request.files.is_empty() || request.files.len() > MAX_ENTRIES {
        return Err(Refusal::new(
            "rustup package request is empty or outside its bounds",
        ));
    }
    if request.output.exists() {
        return Err(Refusal::new("rustup package output must be absent"));
    }
    let prefix = fs::canonicalize(request.prefix)?;
    let parent = fs::canonicalize(
        request
            .output
            .parent()
            .ok_or_else(|| Refusal::new("rustup package output has no parent"))?,
    )?;
    if request.output.starts_with(&prefix) || prefix.starts_with(request.output) {
        return Err(Refusal::new(
            "rustup package output overlaps its SDK prefix",
        ));
    }
    verify_complete(
        &prefix,
        request.files,
        &[],
        InventoryLimits {
            max_tree_entries: MAX_ENTRIES,
            max_link_resolution_steps: 256,
        },
    )?;
    check()?;
    let components = plan_components(request.files, request.rust_host_triple)?;
    let stage = parent.join(format!(
        ".{}.rustup-stage-{}",
        request
            .output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Refusal::new("rustup output leaf must be UTF-8"))?,
        std::process::id()
    ));
    if stage.exists() {
        return Err(Refusal::new("rustup package staging path is occupied"));
    }
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<RustupPackageReceipt> {
        let notices = request
            .files
            .iter()
            .filter(|row| row.path.starts_with("share/doc/"))
            .cloned()
            .collect::<Vec<_>>();
        let mut artifacts = Vec::new();
        let mut ownership = BTreeMap::new();
        for component in components {
            check()?;
            let file_name = format!(
                "ami-rust-{}-{}-{}.tar.xz",
                component.label, request.version, request.host_key
            );
            let archive_root = file_name
                .strip_suffix(".tar.xz")
                .expect("fixed archive suffix");
            let path = stage.join(&file_name);
            let component_notices = if component.label == "cargo" || component.label == "rust-std" {
                notices.as_slice()
            } else {
                &[]
            };
            write_component_archive(
                &prefix,
                &path,
                archive_root,
                &component.name,
                &component.files,
                component_notices,
                request.epoch,
                &mut check,
            )?;
            let bytes = fs::symlink_metadata(&path)?.len();
            if bytes == 0 || bytes > MAX_ARCHIVE_BYTES {
                return Err(Refusal::new(
                    "rustup component archive is empty or over its bound",
                ));
            }
            artifacts.push(PackagedArtifact {
                role: format!("rustup-{}-component", component.label),
                path: file_name,
                bytes,
                sha256: sha256_file(&path)?,
            });
            ownership.insert(component.name, component.files);
        }
        verify_complete(
            &prefix,
            request.files,
            &[],
            InventoryLimits {
                max_tree_entries: MAX_ENTRIES,
                max_link_resolution_steps: 256,
            },
        )?;
        check()?;
        fs::rename(&stage, request.output)?;
        Ok(RustupPackageReceipt {
            artifacts,
            ownership,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

/// Materialize the Direct archive, the host's Debian package when applicable,
/// and the common notice archive from the same verified SDK inventory.
///
/// This is a byte producer only. Signing, repository publication and package
/// manager metadata remain the caller's responsibility.
pub fn package_native_formats(
    request: NativePackageRequest<'_>,
    mut check: impl FnMut() -> Result<()>,
) -> Result<NativePackageReceipt> {
    validate_version(request.version)?;
    let debian_arch = match request.host_key {
        "macos-aarch64" => None,
        "linux-x86_64" => Some("amd64"),
        "linux-aarch64" => Some("arm64"),
        _ => return Err(Refusal::new("unsupported native package host")),
    };
    if request.epoch == 0 || request.files.is_empty() || request.files.len() > MAX_ENTRIES {
        return Err(Refusal::new(
            "native package request is empty or outside its bounds",
        ));
    }
    if request.output.exists() {
        return Err(Refusal::new("native package output must be absent"));
    }
    let prefix = fs::canonicalize(request.prefix)?;
    let parent = fs::canonicalize(
        request
            .output
            .parent()
            .ok_or_else(|| Refusal::new("native package output has no parent"))?,
    )?;
    if request.output.starts_with(&prefix) || prefix.starts_with(request.output) {
        return Err(Refusal::new(
            "native package output overlaps its SDK prefix",
        ));
    }
    verify_complete(
        &prefix,
        request.files,
        &[],
        InventoryLimits {
            max_tree_entries: MAX_ENTRIES,
            max_link_resolution_steps: 256,
        },
    )?;
    let stage = parent.join(format!(
        ".{}.native-stage-{}",
        request
            .output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Refusal::new("native output leaf must be UTF-8"))?,
        std::process::id()
    ));
    if stage.exists() {
        return Err(Refusal::new("native package staging path is occupied"));
    }
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<NativePackageReceipt> {
        let mut artifacts = Vec::new();
        let direct_name = format!("ami-rust-{}-{}.tar.xz", request.version, request.host_key);
        let direct_path = stage.join(&direct_name);
        write_inventory_archive(
            &prefix,
            &direct_path,
            &format!("libexec/ami-rust/{}", request.version),
            request.files,
            request.epoch,
            None,
            &mut check,
        )?;
        artifacts.push(package_identity(
            "direct-archive",
            &direct_path,
            direct_name,
        )?);

        let notices = request
            .files
            .iter()
            .filter(|row| row.path.starts_with("share/doc/"))
            .cloned()
            .collect::<Vec<_>>();
        if notices.is_empty() {
            return Err(Refusal::new("SDK has no release notice files"));
        }
        let notices_name = format!("ami-rust-{}-notices.tar.xz", request.version);
        let notices_path = stage.join(&notices_name);
        write_inventory_archive(
            &prefix,
            &notices_path,
            &format!("ami-rust-{}-notices", request.version),
            &notices,
            request.epoch,
            None,
            &mut check,
        )?;
        artifacts.push(package_identity(
            "release-notices",
            &notices_path,
            notices_name,
        )?);

        if let Some(architecture) = debian_arch {
            let work = stage.join(".deb-work");
            fs::create_dir(&work)?;
            let data = work.join("data.tar.xz");
            let control = work.join("control.tar.xz");
            let marker = work.join("debian-binary");
            write_inventory_archive(
                &prefix,
                &data,
                &format!("usr/libexec/ami-rust/{}", request.version),
                request.files,
                request.epoch,
                Some(("usr/libexec/ami-rust/current", request.version)),
                &mut check,
            )?;
            write_debian_control(
                &control,
                request.version,
                architecture,
                request.epoch,
                request.files,
            )?;
            fs::write(&marker, b"2.0\n")?;
            let deb_name = format!("ami-rust_{}_{}.deb", request.version, architecture);
            let deb_path = stage.join(&deb_name);
            write_ar(
                &deb_path,
                request.epoch,
                [marker.as_path(), control.as_path(), data.as_path()],
            )?;
            fs::remove_dir_all(work)?;
            artifacts.push(package_identity("debian-package", &deb_path, deb_name)?);
        }

        verify_complete(
            &prefix,
            request.files,
            &[],
            InventoryLimits {
                max_tree_entries: MAX_ENTRIES,
                max_link_resolution_steps: 256,
            },
        )?;
        check()?;
        fs::rename(&stage, request.output)?;
        Ok(NativePackageReceipt { artifacts })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn package_identity(role: &str, path: &Path, name: String) -> Result<PackagedArtifact> {
    let bytes = fs::symlink_metadata(path)?.len();
    if bytes == 0 || bytes > MAX_ARCHIVE_BYTES {
        return Err(Refusal::new("native package is empty or over its bound"));
    }
    Ok(PackagedArtifact {
        role: role.to_owned(),
        path: name,
        bytes,
        sha256: sha256_file(path)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_inventory_archive(
    prefix: &Path,
    destination: &Path,
    archive_root: &str,
    files: &[FileIdentity],
    epoch: u64,
    symlink: Option<(&str, &str)>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let xz = XzWriter::new(output, XzOptions::with_preset(6))
        .map_err(|error| Refusal::new(format!("could not create package XZ stream: {error}")))?;
    let mut builder = Builder::new(xz);
    let mut directories = BTreeSet::new();
    directories.insert(archive_root.to_owned());
    add_parents(archive_root, &mut directories);
    for row in files {
        add_parents(&format!("{archive_root}/{}", row.path), &mut directories);
    }
    if let Some((path, _)) = symlink {
        add_parents(path, &mut directories);
    }
    for directory in directories {
        append_directory(&mut builder, &directory, epoch)?;
    }
    for row in files {
        check()?;
        append_file(
            &mut builder,
            prefix,
            row,
            &format!("{archive_root}/{}", row.path),
            epoch,
        )?;
    }
    if let Some((path, target)) = symlink {
        let mut link = header(0, 0o777, epoch, EntryType::Symlink)?;
        link.set_link_name(target)?;
        link.set_cksum();
        builder.append_data(&mut link, path, &[][..])?;
    }
    finish_archive(builder, "package")
}

fn write_debian_control(
    destination: &Path,
    version: &str,
    architecture: &str,
    epoch: u64,
    files: &[FileIdentity],
) -> Result<()> {
    let installed_kib = files
        .iter()
        .try_fold(0_u64, |total, row| {
            total
                .checked_add(row.bytes)
                .ok_or_else(|| Refusal::new("installed byte total overflow"))
        })?
        .div_ceil(1024);
    let control = format!(
        "Package: ami-rust\nVersion: {version}-1\nArchitecture: {architecture}\nMaintainer: Fabian Schmieder <436979+metaneutrons@users.noreply.github.com>\nDepends: libc6, libgcc-s1, libstdc++6, zlib1g\nInstalled-Size: {installed_kib}\nSection: devel\nPriority: optional\nDescription: Rust cross-development toolchain for x86-64 AROS\n"
    );
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let xz = XzWriter::new(output, XzOptions::with_preset(6)).map_err(|error| {
        Refusal::new(format!(
            "could not create Debian control XZ stream: {error}"
        ))
    })?;
    let mut builder = Builder::new(xz);
    append_bytes(&mut builder, "control", control.as_bytes(), 0o644, epoch)?;
    finish_archive(builder, "Debian control")
}

fn finish_archive(mut builder: Builder<XzWriter<File>>, label: &str) -> Result<()> {
    builder.finish()?;
    let xz = builder.into_inner()?;
    let mut output = xz
        .finish()
        .map_err(|error| Refusal::new(format!("could not finish {label} XZ stream: {error}")))?;
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn write_ar<'a>(
    destination: &Path,
    epoch: u64,
    members: impl IntoIterator<Item = &'a Path>,
) -> Result<()> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    output.write_all(b"!<arch>\n")?;
    for path in members {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| Refusal::new("Debian AR member name must be UTF-8"))?;
        if name.len() > 15 {
            return Err(Refusal::new("Debian AR member name is too long"));
        }
        let bytes = fs::symlink_metadata(path)?.len();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
            format!("{name}/"),
            epoch,
            0,
            0,
            0o100644,
            bytes
        );
        if header.len() != 60 {
            return Err(Refusal::new("Debian AR header is not canonical"));
        }
        output.write_all(header.as_bytes())?;
        std::io::copy(&mut File::open(path)?, &mut output)?;
        if bytes % 2 != 0 {
            output.write_all(b"\n")?;
        }
    }
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn plan_components(files: &[FileIdentity], triple: &str) -> Result<Vec<Component>> {
    let std_prefix = format!("lib/rustlib/{triple}/lib/");
    let std_name = format!("rust-std-{triple}");
    let mut rustc = Vec::new();
    let mut cargo = Vec::new();
    let mut rust_std = Vec::new();
    let mut paths = BTreeSet::new();
    for row in files {
        validate_relative_inventory_path(&row.path)?;
        if !paths.insert(&row.path) || !is_sha256_digest(&row.sha256) {
            return Err(Refusal::new(
                "rustup input inventory has a duplicate or invalid row",
            ));
        }
        let mode = row
            .mode
            .ok_or_else(|| Refusal::new("portable SDK inventory must record every file mode"))?;
        let user = mode & 0o700;
        let group = (user & 0o500) >> 3;
        if mode != user | group | (group >> 3) {
            return Err(Refusal::new(format!(
                "rust-installer would normalize SDK mode for {}",
                row.path
            )));
        }
        if row.path == "bin/cargo" {
            cargo.push(row.clone());
        } else if row.path.starts_with(&std_prefix) {
            rust_std.push(row.clone());
        } else {
            rustc.push(row.clone());
        }
    }
    if cargo.len() != 1
        || cargo[0].mode.is_none_or(|mode| mode & 0o111 == 0)
        || rustc
            .iter()
            .all(|row| row.path != "bin/rustc" || row.mode.is_none_or(|mode| mode & 0o111 == 0))
        || rust_std.is_empty()
    {
        return Err(Refusal::new(
            "rustup component partition lacks rustc, Cargo or host rust-std",
        ));
    }
    for rows in [&mut rustc, &mut cargo, &mut rust_std] {
        rows.sort_by(|left, right| left.path.cmp(&right.path));
    }
    Ok(vec![
        Component {
            name: "rustc".to_owned(),
            label: "rustc",
            files: rustc,
        },
        Component {
            name: "cargo".to_owned(),
            label: "cargo",
            files: cargo,
        },
        Component {
            name: std_name,
            label: "rust-std",
            files: rust_std,
        },
    ])
}

#[allow(clippy::too_many_arguments)]
fn write_component_archive(
    prefix: &Path,
    destination: &Path,
    archive_root: &str,
    component: &str,
    files: &[FileIdentity],
    notices: &[FileIdentity],
    epoch: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let xz = XzWriter::new(output, XzOptions::with_preset(6))
        .map_err(|error| Refusal::new(format!("could not create rustup XZ stream: {error}")))?;
    let mut builder = Builder::new(xz);
    let payload_root = format!("{archive_root}/{component}");
    let manifest = files
        .iter()
        .map(|row| format!("file:{}\n", row.path))
        .collect::<String>();
    let metadata = [
        (
            format!("{archive_root}/rust-installer-version"),
            b"3\n".to_vec(),
        ),
        (
            format!("{archive_root}/components"),
            format!("{component}\n").into_bytes(),
        ),
        (format!("{payload_root}/manifest.in"), manifest.into_bytes()),
    ];
    let mut directories = BTreeSet::new();
    add_parents(&payload_root, &mut directories);
    directories.insert(archive_root.to_owned());
    directories.insert(payload_root.clone());
    for row in files {
        add_parents(&format!("{payload_root}/{}", row.path), &mut directories);
    }
    for row in notices {
        add_parents(
            &format!("{archive_root}/NOTICES/{}", row.path),
            &mut directories,
        );
    }
    for (path, _) in &metadata {
        add_parents(path, &mut directories);
    }
    for directory in directories {
        append_directory(&mut builder, &directory, epoch)?;
    }
    for (path, bytes) in metadata {
        append_bytes(&mut builder, &path, &bytes, 0o644, epoch)?;
    }
    for row in files {
        check()?;
        append_file(
            &mut builder,
            prefix,
            row,
            &format!("{payload_root}/{}", row.path),
            epoch,
        )?;
    }
    for row in notices {
        check()?;
        append_file(
            &mut builder,
            prefix,
            row,
            &format!("{archive_root}/NOTICES/{}", row.path),
            epoch,
        )?;
    }
    builder.finish()?;
    let xz = builder.into_inner()?;
    let mut output = xz
        .finish()
        .map_err(|error| Refusal::new(format!("could not finish rustup XZ stream: {error}")))?;
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn append_directory<W: Write>(builder: &mut Builder<W>, path: &str, epoch: u64) -> Result<()> {
    let mut header = header(0, 0o755, epoch, EntryType::Directory)?;
    builder.append_data(
        &mut header,
        format!("{}/", path.trim_end_matches('/')),
        &[][..],
    )?;
    Ok(())
}

fn append_bytes<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    bytes: &[u8],
    mode: u32,
    epoch: u64,
) -> Result<()> {
    let mut header = header(bytes.len() as u64, mode, epoch, EntryType::Regular)?;
    builder.append_data(&mut header, path, bytes)?;
    Ok(())
}

fn append_file<W: Write>(
    builder: &mut Builder<W>,
    prefix: &Path,
    row: &FileIdentity,
    archive_path: &str,
    epoch: u64,
) -> Result<()> {
    let source = prefix.join(&row.path);
    let metadata = fs::symlink_metadata(&source)?;
    let mode = row
        .mode
        .ok_or_else(|| Refusal::new("archive file mode is absent"))?;
    if !metadata.file_type().is_file()
        || metadata.len() != row.bytes
        || metadata.permissions().mode() & 0o777 != mode
        || sha256_file(&source)? != row.sha256
    {
        return Err(Refusal::new(format!(
            "SDK file changed before packaging: {}",
            row.path
        )));
    }
    let mut header = header(row.bytes, mode, epoch, EntryType::Regular)?;
    let mut file = File::open(&source)?;
    builder.append_data(&mut header, archive_path, &mut file)?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(Refusal::new("SDK file grew while it was being packaged"));
    }
    Ok(())
}

fn header(size: u64, mode: u32, epoch: u64, kind: EntryType) -> Result<Header> {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(epoch);
    header.set_username("")?;
    header.set_groupname("")?;
    header.set_entry_type(kind);
    header.set_cksum();
    Ok(header)
}

fn add_parents(path: &str, directories: &mut BTreeSet<String>) {
    let mut current = String::new();
    let parts = path.split('/').collect::<Vec<_>>();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(part);
        directories.insert(current.clone());
    }
}

fn validate_version(version: &str) -> Result<()> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(Refusal::new("toolchain version must be numeric x.y.z"));
    }
    Ok(())
}
