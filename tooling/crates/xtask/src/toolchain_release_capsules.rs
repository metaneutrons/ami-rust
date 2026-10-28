//! Internal deterministic source/vendor capsule preparation.
//!
//! This packages the caller's declared inputs and a clean Git checkout. It
//! does not establish source or vendor completeness, provenance, authenticity,
//! signing, publication, or RC3 acceptance.

use ami_rust_core::{
    Refusal, Result,
    digest::is_sha256_digest,
    directory::Directory,
    files::open_regular_nofollow,
    json::{JsonProfile, parse_json_value},
    process_capture::{self, CaptureLimits, CommandSpec},
    signals::SigtermGuard,
};
use lzma_rust2::{XzOptions, XzWriter};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tar::{Builder, EntryType, Header};

const REQUEST_SCHEMA: &str = "ami-rust-toolchain-capsule-request-v1";
const RESULT_SCHEMA: &str = "ami-rust-toolchain-capsule-result-v1";
const SOURCE_INVENTORY_SCHEMA: &str = "ami-rust-toolchain-source-capsule-inventory-v1";
const VENDOR_INVENTORY_SCHEMA: &str = "ami-rust-toolchain-vendor-capsule-inventory-v1";
const CAPSULE_CLAIM: &str = "Local unsigned source/vendor capsule bytes only. This does not establish completeness, source or vendor authenticity, provenance, signing, publication, or RC3 acceptance.";
const READ_BUFFER_BYTES: usize = 64 * 1024;
const COMMAND_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const COMMAND_STDERR_BYTES: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(1_200);

struct Deadline {
    started: Instant,
    signals: SigtermGuard,
}

impl Deadline {
    fn acquire() -> Result<Self> {
        Ok(Self {
            started: Instant::now(),
            signals: SigtermGuard::acquire()?,
        })
    }

    fn check(&self) -> Result<()> {
        self.signals.check()?;
        if self.started.elapsed() >= DEADLINE {
            return Err(Refusal::new(
                "toolchain release capsule production exceeded its 1200-second deadline",
            ));
        }
        Ok(())
    }

    fn remaining(&self) -> Duration {
        DEADLINE.saturating_sub(self.started.elapsed())
    }
}

#[derive(Clone, Debug)]
struct Material {
    role: String,
    filename: String,
    path: PathBuf,
    bytes: u64,
    sha256: String,
    mode: u32,
    archive_path: String,
}

#[derive(Clone, Debug)]
struct SourceFile {
    path: String,
    object_id: String,
    content_path: PathBuf,
    mode: u32,
    bytes: u64,
    sha256: String,
    archive_path: String,
}

#[derive(Clone, Debug)]
struct Request {
    version: String,
    commit: String,
    tree: String,
    epoch: u64,
    source_root: PathBuf,
    source_inputs: Vec<Material>,
    vendor_inputs: Vec<Material>,
    output: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    schema: String,
    version: String,
    source: SourceIdentityDocument,
    source_root: String,
    source_inputs: Vec<MaterialDocument>,
    vendor_inputs: Vec<MaterialDocument>,
    output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentityDocument {
    commit: String,
    tree: String,
    epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialDocument {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Artifact {
    name: String,
    bytes: u64,
    sha256: String,
}

enum ArchiveEntry {
    File {
        archive_path: String,
        source_path: PathBuf,
        bytes: u64,
        sha256: String,
        mode: u32,
    },
    Bytes {
        archive_path: String,
        bytes: Vec<u8>,
        mode: u32,
    },
}

impl ArchiveEntry {
    fn path(&self) -> &str {
        match self {
            Self::File { archive_path, .. } | Self::Bytes { archive_path, .. } => archive_path,
        }
    }

    fn metadata(&self) -> (u64, u32) {
        match self {
            Self::File { bytes, mode, .. } => (*bytes, *mode),
            Self::Bytes { bytes, mode, .. } => (bytes.len() as u64, *mode),
        }
    }
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let Some(option) = arguments.next() else {
        return Err(usage());
    };
    if option != OsStr::new("--request") {
        return Err(usage());
    }
    let request = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().is_some() {
        return Err(usage());
    }

    let deadline = Deadline::acquire()?;
    let result = produce_request(&request, &deadline)?;
    deadline.check()?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|error| Refusal::new(format!(
            "could not serialize capsule result: {error}"
        )))?
    );
    Ok(())
}

fn produce_request(request_path: &Path, deadline: &Deadline) -> Result<Value> {
    deadline.check()?;
    let raw = read_request(request_path, deadline)?;
    let value = parse_json_value(&raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let mut request = parse_request(&value)?;
    request.source_root = canonical_directory(&request.source_root, "source_root")?;
    request.output = fresh_output_path(&request.output)?;
    validate_disjoint_paths(&request)?;
    let parent = request
        .output
        .parent()
        .expect("validated output has a parent");
    let parent_directory = Directory::open(parent)?;
    let (stage, failure_stage) = create_stage(&request.output)?;
    let production = (|| {
        let git = resolve_git()?;
        verify_source_identity(&git, &request, deadline)?;
        let source_files = read_source_tree(
            &git,
            &request,
            &stage.join(".work").join("source-blobs"),
            deadline,
        )?;
        let source_inputs = inspect_materials(&request.source_inputs, deadline)?;
        let vendor_inputs = inspect_materials(&request.vendor_inputs, deadline)?;
        deadline.check()?;
        produce_staged(
            &request,
            &source_files,
            &source_inputs,
            &vendor_inputs,
            &stage,
            &git,
            deadline,
        )
    })();
    match production {
        Ok(result) => {
            if let Err(error) = deadline.check() {
                retain_failure(&stage, &failure_stage, &request, &error)?;
                return Err(Refusal::new(format!(
                    "{error}; capsule failure work retained at {}",
                    failure_stage.display()
                )));
            }
            if request.output.exists() || fs::symlink_metadata(&request.output).is_ok() {
                let refusal = Refusal::new("capsule output path appeared during production");
                retain_failure(&stage, &failure_stage, &request, &refusal)?;
                return Err(Refusal::new(format!(
                    "{refusal}; capsule failure work retained at {}",
                    failure_stage.display()
                )));
            }
            let stage_name = stage.file_name().expect("staging directory has a basename");
            let output_name = request
                .output
                .file_name()
                .expect("validated output has a basename");
            if let Err(error) =
                parent_directory.rename_no_replace(stage_name, &parent_directory, output_name)
            {
                let refusal = Refusal::new(format!(
                    "could not atomically publish completed local capsules: {error}"
                ));
                retain_failure(&stage, &failure_stage, &request, &refusal)?;
                return Err(Refusal::new(format!(
                    "{refusal}; capsule failure work retained at {}",
                    failure_stage.display()
                )));
            }
            Ok(result)
        }
        Err(error) => {
            retain_failure(&stage, &failure_stage, &request, &error)?;
            Err(Refusal::new(format!(
                "{error}; capsule failure work retained at {}",
                failure_stage.display()
            )))
        }
    }
}

fn read_request(path: &Path, deadline: &Deadline) -> Result<Vec<u8>> {
    let limit = JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes();
    let mut file = open_regular_nofollow(path)?;
    let length = file.metadata()?.len();
    if length > limit as u64 {
        return Err(Refusal::new(
            "toolchain capsule request exceeds the JSON profile limit",
        ));
    }
    let mut raw = Vec::with_capacity(usize::try_from(length).unwrap_or(limit));
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        deadline.check()?;
        let remaining = limit.saturating_sub(raw.len());
        let read_limit = buffer.len().min(remaining.saturating_add(1));
        let read = file.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        if raw.len().saturating_add(read) > limit {
            return Err(Refusal::new(
                "toolchain capsule request grew beyond the JSON profile limit",
            ));
        }
        raw.extend_from_slice(&buffer[..read]);
    }
    Ok(raw)
}

fn parse_request(value: &Value) -> Result<Request> {
    let document: RequestDocument = serde_json::from_value(value.clone())
        .map_err(|error| Refusal::new(format!("capsule request has an invalid shape: {error}")))?;
    if document.schema != REQUEST_SCHEMA {
        return Err(Refusal::new("unsupported toolchain capsule request schema"));
    }
    let version = document.version;
    validate_version(&version)?;
    let commit = document.source.commit;
    let tree = document.source.tree;
    validate_git_object_id(&commit, "source commit")?;
    validate_git_object_id(&tree, "source tree")?;
    let epoch = document.source.epoch;
    let source_root = absolute_path(&document.source_root, "source_root")?;
    let output = absolute_path(&document.output, "output")?;
    let source_inputs =
        parse_materials(document.source_inputs, "source_inputs", &version, "sources")?;
    let vendor_inputs =
        parse_materials(document.vendor_inputs, "vendor_inputs", &version, "vendor")?;
    if vendor_inputs.is_empty() {
        return Err(Refusal::new(
            "vendor_inputs must contain at least one declared material",
        ));
    }
    Ok(Request {
        version,
        commit,
        tree,
        epoch,
        source_root,
        source_inputs,
        vendor_inputs,
        output,
    })
}

fn parse_materials(
    rows: Vec<MaterialDocument>,
    name: &str,
    version: &str,
    capsule: &str,
) -> Result<Vec<Material>> {
    let mut materials = Vec::with_capacity(rows.len());
    let mut archive_names = BTreeSet::new();
    let mut folded_names = BTreeSet::new();
    for row in rows {
        let role = row.role;
        validate_component(&role, "material role")?;
        let path = absolute_path(&row.path, "material path")?;
        let filename = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Refusal::new("material basename must be UTF-8"))?
            .to_owned();
        validate_component(&filename, "material filename")?;
        let bytes = row.bytes;
        let sha256 = row.sha256;
        if !is_sha256_digest(&sha256) {
            return Err(Refusal::new(
                "material sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        let relative = format!("materials/{role}/{filename}");
        if !archive_names.insert(relative.clone())
            || !folded_names.insert(relative.to_ascii_lowercase())
        {
            return Err(Refusal::new(format!(
                "{name} contains duplicate or case-colliding archive names"
            )));
        }
        materials.push(Material {
            role,
            filename,
            path,
            bytes,
            sha256,
            mode: 0o644,
            archive_path: format!("ami-rust-{version}/{capsule}/{relative}"),
        });
    }
    materials.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(materials)
}

fn inspect_materials(materials: &[Material], deadline: &Deadline) -> Result<Vec<Material>> {
    let mut inspected = Vec::with_capacity(materials.len());
    for material in materials {
        deadline.check()?;
        let material = material.clone();
        let mut file = open_regular_nofollow(&material.path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(Refusal::new(
                "declared capsule material is not a regular file",
            ));
        }
        if metadata.len() != material.bytes {
            return Err(Refusal::new(
                "declared capsule material byte count does not match the file",
            ));
        }
        let (bytes, sha256) = hash_reader(&mut file, Some(material.bytes), deadline)?;
        if bytes != material.bytes || sha256 != material.sha256 {
            return Err(Refusal::new(
                "declared capsule material SHA-256 or byte count does not match",
            ));
        }
        inspected.push(material);
    }
    Ok(inspected)
}

fn verify_source_identity(git: &Path, request: &Request, deadline: &Deadline) -> Result<()> {
    let root = git_output(
        git,
        &request.source_root,
        &["rev-parse", "--show-toplevel"],
        deadline,
    )?;
    let root = output_text(&root, "Git repository root")?;
    let root = PathBuf::from(root.trim());
    if root != request.source_root {
        return Err(Refusal::new(
            "source_root is not the exact canonical Git repository root",
        ));
    }
    let commit = git_output(
        git,
        &request.source_root,
        &["rev-parse", "--verify", "HEAD"],
        deadline,
    )?;
    let commit = output_text(&commit, "Git HEAD")?.trim();
    let tree = git_output(
        git,
        &request.source_root,
        &["rev-parse", "--verify", "HEAD^{tree}"],
        deadline,
    )?;
    let tree = output_text(&tree, "Git HEAD tree")?.trim();
    if commit != request.commit || tree != request.tree {
        return Err(Refusal::new(
            "source checkout commit or tree differs from the declared identity",
        ));
    }
    let status = git_output(
        git,
        &request.source_root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        deadline,
    )?;
    if !status.is_empty() {
        return Err(Refusal::new(
            "source checkout is not clean, including untracked non-ignored files",
        ));
    }
    Ok(())
}

fn read_source_tree(
    git: &Path,
    request: &Request,
    blob_cache: &Path,
    deadline: &Deadline,
) -> Result<Vec<SourceFile>> {
    let work_root = blob_cache
        .parent()
        .ok_or_else(|| Refusal::new("source blob cache has no work directory"))?;
    fs::DirBuilder::new().mode(0o700).create(work_root)?;
    fs::set_permissions(work_root, fs::Permissions::from_mode(0o700))?;
    fs::DirBuilder::new().mode(0o700).create(blob_cache)?;
    fs::set_permissions(blob_cache, fs::Permissions::from_mode(0o700))?;
    let records = git_tree_records(git, &request.source_root, &request.commit, deadline)?;
    let mut files = Vec::with_capacity(records.len());
    let mut names = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let repository_root = format!("ami-rust-{}/sources/repository", request.version);
    for (index, (mode, kind, object_id, path)) in records.into_iter().enumerate() {
        deadline.check()?;
        if kind != "blob" || (mode != 0o100644 && mode != 0o100755) {
            return Err(Refusal::new(
                "source Git tree contains a symlink, gitlink, or non-regular entry",
            ));
        }
        validate_archive_relative_path(&path)?;
        validate_git_object_id(&object_id, "source Git blob object")?;
        let archive_path = format!("{repository_root}/{path}");
        let folded_path = archive_path.to_ascii_lowercase();
        if !names.insert(archive_path.clone()) || !folded.insert(folded_path) {
            return Err(Refusal::new(
                "source Git tree contains duplicate or case-colliding paths",
            ));
        }
        let content_path = blob_cache.join(format!("{index:08}.blob"));
        let (bytes, sha256) = cache_git_blob(
            git,
            &request.source_root,
            &object_id,
            &content_path,
            deadline,
        )?;
        files.push(SourceFile {
            path,
            object_id,
            content_path,
            mode: if mode == 0o100755 { 0o755 } else { 0o644 },
            bytes,
            sha256,
            archive_path,
        });
    }
    files.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(files)
}

fn produce_staged(
    request: &Request,
    source_files: &[SourceFile],
    source_inputs: &[Material],
    vendor_inputs: &[Material],
    stage: &Path,
    git: &Path,
    deadline: &Deadline,
) -> Result<Value> {
    let source_inventory = source_inventory(request, source_files, source_inputs)?;
    let vendor_inventory = vendor_inventory(request, vendor_inputs)?;
    let mut source_entries = source_archive_entries(
        &request.version,
        source_files,
        source_inputs,
        source_inventory,
    )?;
    let mut vendor_entries = material_archive_entries(vendor_inputs);
    vendor_entries.push(ArchiveEntry::Bytes {
        archive_path: format!("ami-rust-{}/vendor/inventory.json", request.version),
        bytes: vendor_inventory,
        mode: 0o644,
    });
    source_entries.sort_by(|left, right| left.path().cmp(right.path()));
    vendor_entries.sort_by(|left, right| left.path().cmp(right.path()));

    let source_name = format!("ami-rust-{}-sources.tar.xz", request.version);
    let vendor_name = format!("ami-rust-{}-vendor.tar.xz", request.version);
    let source_part = stage.join(format!("{source_name}.part"));
    let vendor_part = stage.join(format!("{vendor_name}.part"));
    write_archive(&source_part, &source_entries, request.epoch, deadline)?;
    write_archive(&vendor_part, &vendor_entries, request.epoch, deadline)?;
    verify_source_identity(git, request, deadline)?;
    let source_artifact = hash_artifact(&source_part, &source_name, deadline)?;
    let vendor_artifact = hash_artifact(&vendor_part, &vendor_name, deadline)?;
    fs::rename(&source_part, stage.join(&source_name))?;
    fs::rename(&vendor_part, stage.join(&vendor_name))?;
    fs::remove_dir_all(stage.join(".work"))?;
    let result = json!({
        "schema": RESULT_SCHEMA,
        "status": "COMPLETED_LOCAL_UNSIGNED_CANDIDATE_ONLY",
        "version": request.version,
        "source": {"commit": request.commit, "tree": request.tree, "epoch": request.epoch},
        "artifacts": [
            {"name": source_artifact.name, "bytes": source_artifact.bytes, "sha256": source_artifact.sha256},
            {"name": vendor_artifact.name, "bytes": vendor_artifact.bytes, "sha256": vendor_artifact.sha256},
        ],
        "claim": CAPSULE_CLAIM,
    });
    write_json_new(&stage.join("result.json"), &result)?;
    sync_directory(stage)?;
    Ok(result)
}

fn source_inventory(
    request: &Request,
    files: &[SourceFile],
    materials: &[Material],
) -> Result<Vec<u8>> {
    let repository_files: Vec<Value> = files
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "git_object": file.object_id,
                "bytes": file.bytes,
                "sha256": file.sha256,
                "mode": format!("{:04o}", file.mode),
            })
        })
        .collect();
    let material_rows: Vec<Value> = materials
        .iter()
        .map(|material| {
            json!({
                "role": material.role,
                "filename": material.filename,
                "path": format!("materials/{}/{}", material.role, material.filename),
                "bytes": material.bytes,
                "sha256": material.sha256,
                "mode": format!("{:04o}", material.mode),
            })
        })
        .collect();
    canonical_json(&json!({
        "schema": SOURCE_INVENTORY_SCHEMA,
        "version": request.version,
        "source": {"commit": request.commit, "tree": request.tree, "epoch": request.epoch},
        "repository_files": repository_files,
        "source_materials": material_rows,
        "claim": CAPSULE_CLAIM,
    }))
}

fn vendor_inventory(request: &Request, materials: &[Material]) -> Result<Vec<u8>> {
    let material_rows: Vec<Value> = materials
        .iter()
        .map(|material| {
            json!({
                "role": material.role,
                "filename": material.filename,
                "path": format!("materials/{}/{}", material.role, material.filename),
                "bytes": material.bytes,
                "sha256": material.sha256,
                "mode": format!("{:04o}", material.mode),
            })
        })
        .collect();
    canonical_json(&json!({
        "schema": VENDOR_INVENTORY_SCHEMA,
        "version": request.version,
        "source": {"commit": request.commit, "tree": request.tree, "epoch": request.epoch},
        "vendor_materials": material_rows,
        "claim": CAPSULE_CLAIM,
    }))
}

fn source_archive_entries(
    version: &str,
    files: &[SourceFile],
    materials: &[Material],
    inventory: Vec<u8>,
) -> Result<Vec<ArchiveEntry>> {
    let mut entries = Vec::with_capacity(files.len() + materials.len() + 1);
    for file in files {
        entries.push(ArchiveEntry::File {
            archive_path: file.archive_path.clone(),
            source_path: file.content_path.clone(),
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            mode: file.mode,
        });
    }
    entries.extend(material_archive_entries(materials));
    entries.push(ArchiveEntry::Bytes {
        archive_path: format!("ami-rust-{version}/sources/inventory.json"),
        bytes: inventory,
        mode: 0o644,
    });
    Ok(entries)
}

fn material_archive_entries(materials: &[Material]) -> Vec<ArchiveEntry> {
    materials
        .iter()
        .map(|material| ArchiveEntry::File {
            archive_path: material.archive_path.clone(),
            source_path: material.path.clone(),
            bytes: material.bytes,
            sha256: material.sha256.clone(),
            mode: material.mode,
        })
        .collect()
}

fn write_archive(
    path: &Path,
    entries: &[ArchiveEntry],
    epoch: u64,
    deadline: &Deadline,
) -> Result<()> {
    deadline.check()?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    output.set_permissions(fs::Permissions::from_mode(0o600))?;
    let xz = XzWriter::new(
        DeadlineWriter::new(output, deadline),
        XzOptions::with_preset(1),
    )
    .map_err(|error| {
        Refusal::new(format!(
            "could not initialize deterministic XZ writer: {error}"
        ))
    })?;
    let mut archive = Builder::new(xz);
    for entry in entries {
        deadline.check()?;
        let (bytes, mode) = entry.metadata();
        let mut header = Header::new_gnu();
        header.set_size(bytes);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(epoch);
        header.set_username("")?;
        header.set_groupname("")?;
        header.set_entry_type(EntryType::Regular);
        match entry {
            ArchiveEntry::Bytes {
                archive_path,
                bytes,
                ..
            } => {
                header.set_cksum();
                let reader = DeadlineReader::new(Cursor::new(bytes), deadline);
                archive.append_data(&mut header, archive_path, reader)?;
            }
            ArchiveEntry::File {
                archive_path,
                source_path,
                bytes,
                sha256,
                ..
            } => {
                let file = open_regular_nofollow(source_path)?;
                if file.metadata()?.len() != *bytes {
                    return Err(Refusal::new(
                        "capsule input changed length during archive production",
                    ));
                }
                let mut reader = HashingReader::new(file, *bytes, deadline);
                archive.append_data(&mut header, archive_path, &mut reader)?;
                reader.verify_end()?;
                let (observed_bytes, observed_sha256) = reader.finish();
                if observed_bytes != *bytes || observed_sha256 != *sha256 {
                    return Err(Refusal::new(
                        "capsule input changed bytes during archive production",
                    ));
                }
            }
        }
    }
    archive.finish()?;
    let xz = archive.into_inner()?;
    let output = xz.finish().map_err(|error| {
        Refusal::new(format!(
            "could not finish deterministic XZ archive: {error}"
        ))
    })?;
    let output = output.into_inner();
    output.sync_all()?;
    Ok(())
}

struct DeadlineReader<'a, R> {
    reader: R,
    deadline: &'a Deadline,
}

impl<'a, R> DeadlineReader<'a, R> {
    fn new(reader: R, deadline: &'a Deadline) -> Self {
        Self { reader, deadline }
    }
}

impl<R: Read> Read for DeadlineReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.deadline
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error.to_string()))?;
        self.reader.read(buffer)
    }
}

struct DeadlineWriter<'a, W> {
    writer: W,
    deadline: &'a Deadline,
}

impl<'a, W> DeadlineWriter<'a, W> {
    fn new(writer: W, deadline: &'a Deadline) -> Self {
        Self { writer, deadline }
    }

    fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for DeadlineWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.deadline
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error.to_string()))?;
        self.writer.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deadline
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error.to_string()))?;
        self.writer.flush()
    }
}

struct HashingReader<'a> {
    file: File,
    expected: u64,
    bytes: u64,
    digest: Sha256,
    deadline: &'a Deadline,
}

impl<'a> HashingReader<'a> {
    fn new(file: File, expected: u64, deadline: &'a Deadline) -> Self {
        Self {
            file,
            expected,
            bytes: 0,
            digest: Sha256::new(),
            deadline,
        }
    }

    fn verify_end(&mut self) -> Result<()> {
        self.deadline.check()?;
        let mut extra = [0_u8; 1];
        if self.file.read(&mut extra)? != 0 {
            return Err(Refusal::new("capsule input grew during archive production"));
        }
        if self.bytes != self.expected {
            return Err(Refusal::new(
                "capsule input was truncated during archive production",
            ));
        }
        Ok(())
    }

    fn finish(self) -> (u64, String) {
        let digest: [u8; 32] = self.digest.finalize().into();
        (self.bytes, encode_digest(&digest))
    }
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.deadline
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error.to_string()))?;
        let remaining = self.expected.saturating_sub(self.bytes);
        let take = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if take == 0 {
            return Ok(0);
        }
        let read = self.file.read(&mut buffer[..take])?;
        self.bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("capsule input byte count overflow"))?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

fn hash_reader(
    reader: &mut impl Read,
    expected: Option<u64>,
    deadline: &Deadline,
) -> Result<(u64, String)> {
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        deadline.check()?;
        let limit = match expected {
            Some(expected) => {
                let remaining = expected.saturating_sub(bytes);
                let limit = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1);
                buffer.len().min(limit)
            }
            None => buffer.len(),
        };
        let read = reader.read(&mut buffer[..limit])?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| Refusal::new("capsule input byte count overflow"))?;
        if expected.is_some_and(|expected| bytes > expected) {
            return Err(Refusal::new("capsule input grew while being inspected"));
        }
        digest.update(&buffer[..read]);
    }
    if expected.is_some_and(|expected| bytes != expected) {
        return Err(Refusal::new(
            "capsule input length changed while being inspected",
        ));
    }
    let digest: [u8; 32] = digest.finalize().into();
    Ok((bytes, encode_digest(&digest)))
}

fn encode_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hash_artifact(path: &Path, name: &str, deadline: &Deadline) -> Result<Artifact> {
    let mut file = open_regular_nofollow(path)?;
    let bytes = file.metadata()?.len();
    let (read_bytes, sha256) = hash_reader(&mut file, Some(bytes), deadline)?;
    if bytes != read_bytes {
        return Err(Refusal::new(
            "completed capsule archive changed during readback",
        ));
    }
    Ok(Artifact {
        name: name.to_owned(),
        bytes,
        sha256,
    })
}

fn git_output(git: &Path, root: &Path, arguments: &[&str], deadline: &Deadline) -> Result<Vec<u8>> {
    deadline.check()?;
    let mut args = vec![OsString::from("-c"), OsString::from("core.fsmonitor=false")];
    args.extend([
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
    ]);
    args.extend([OsString::from("-C"), root.as_os_str().to_owned()]);
    args.extend(arguments.iter().map(OsString::from));
    let command = CommandSpec::new(git.as_os_str(), args, root, git_environment());
    let captured = process_capture::capture(
        &command,
        CaptureLimits {
            timeout: deadline.remaining(),
            stdout_bytes: COMMAND_STDOUT_BYTES,
            stderr_bytes: COMMAND_STDERR_BYTES,
            termination_grace: Duration::from_secs(2),
        },
        || deadline.check().is_err(),
    )
    .map_err(|error| {
        Refusal::new(format!(
            "bounded Git identity/status command failed: {error}"
        ))
    })?;
    deadline.check()?;
    if captured.exit_code() != Some(0) {
        return Err(Refusal::new(
            "Git identity/status command returned a nonzero status",
        ));
    }
    Ok(captured.stdout)
}

fn cache_git_blob(
    git: &Path,
    root: &Path,
    object_id: &str,
    destination: &Path,
    deadline: &Deadline,
) -> Result<(u64, String)> {
    deadline.check()?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut command = Command::new(git);
    command
        .env_clear()
        .envs(git_environment())
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "blob", object_id])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| Refusal::new(format!("could not start Git blob reader: {error}")))?;
    let status = loop {
        if let Err(error) = deadline.check() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        match child.try_wait()? {
            Some(status) => break status,
            None => thread::sleep(Duration::from_millis(25)),
        }
    };
    if !status.success() {
        return Err(Refusal::new("Git could not read a committed source blob"));
    }
    let mut file = open_regular_nofollow(destination)?;
    file.sync_all()?;
    let length = file.metadata()?.len();
    hash_reader(&mut file, Some(length), deadline)
}

fn git_tree_records(
    git: &Path,
    root: &Path,
    commit: &str,
    deadline: &Deadline,
) -> Result<Vec<(u32, String, String, String)>> {
    let mut command = Command::new(git);
    command
        .env_clear()
        .envs(git_environment())
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-C")
        .arg(root)
        .args(["ls-tree", "-r", "-z", "--full-tree", commit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| Refusal::new(format!("could not start local Git tree reader: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Refusal::new("Git tree reader has no output pipe"))?;
    let (sender, receiver) = mpsc::sync_channel::<std::result::Result<Option<Vec<u8>>, String>>(8);
    let reader = thread::spawn(move || {
        let mut reader = io::BufReader::new(stdout);
        loop {
            let mut record = Vec::new();
            match reader.read_until(0, &mut record) {
                Ok(0) => {
                    let _ = sender.send(Ok(None));
                    break;
                }
                Ok(_) if record.last() == Some(&0) => {
                    record.pop();
                    if sender.send(Ok(Some(record))).is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    let _ = sender.send(Err("Git tree output ended within a record".to_owned()));
                    break;
                }
                Err(error) => {
                    let _ = sender.send(Err(format!("could not read Git tree output: {error}")));
                    break;
                }
            }
        }
    });
    let mut records = Vec::new();
    let mut read_error = None;
    loop {
        if let Err(error) = deadline.check() {
            let _ = child.kill();
            drop(receiver);
            let _ = child.wait();
            let _ = reader.join();
            return Err(error);
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(Some(record))) => match parse_git_tree_record(&record) {
                Ok(row) => records.push(row),
                Err(error) => {
                    read_error = Some(error);
                    break;
                }
            },
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                read_error = Some(Refusal::new(error));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                read_error = Some(Refusal::new("Git tree reader stopped before end of output"));
                break;
            }
        }
    }
    if let Some(error) = read_error {
        let _ = child.kill();
        drop(receiver);
        let _ = child.wait();
        if reader.join().is_err() {
            return Err(Refusal::new("Git tree reader thread panicked"));
        }
        return Err(error);
    }
    let status = child.wait()?;
    let join_result = reader.join();
    if join_result.is_err() {
        return Err(Refusal::new("Git tree reader thread panicked"));
    }
    if !status.success() {
        return Err(Refusal::new(
            "Git could not enumerate the declared source tree",
        ));
    }
    deadline.check()?;
    Ok(records)
}

fn parse_git_tree_record(record: &[u8]) -> Result<(u32, String, String, String)> {
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| Refusal::new("Git tree record is malformed"))?;
    let metadata = std::str::from_utf8(&record[..tab])
        .map_err(|_| Refusal::new("Git tree metadata is not UTF-8"))?;
    let path = std::str::from_utf8(&record[tab + 1..])
        .map_err(|_| Refusal::new("tracked source path is not UTF-8"))?;
    let mut fields = metadata.split(' ');
    let mode = fields
        .next()
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .ok_or_else(|| Refusal::new("Git tree mode is invalid"))?;
    let kind = fields
        .next()
        .ok_or_else(|| Refusal::new("Git tree type is missing"))?
        .to_owned();
    let object_id = fields
        .next()
        .ok_or_else(|| Refusal::new("Git tree object identifier is missing"))?
        .to_owned();
    if fields.next().is_some() || path.is_empty() {
        return Err(Refusal::new(
            "Git tree record has extra fields or an empty path",
        ));
    }
    Ok((mode, kind, object_id, path.to_owned()))
}

fn resolve_git() -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| Refusal::new("PATH is unavailable for local Git"))?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("git");
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            continue;
        }
        if let Ok(canonical) = fs::canonicalize(candidate) {
            return Ok(canonical);
        }
    }
    Err(Refusal::new(
        "could not resolve a local Git executable from PATH",
    ))
}

fn git_environment() -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    if let Some(path) = std::env::var_os("PATH") {
        environment.insert(OsString::from("PATH"), path);
    }
    for (key, value) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("LC_ALL", "C"),
    ] {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    environment
}

fn fresh_output_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new("capsule output must be an absolute path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Refusal::new("capsule output must have a parent directory"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Refusal::new(format!("capsule output parent is unavailable: {error}")))?;
    let name = path
        .file_name()
        .filter(|name| {
            *name != OsStr::new("") && *name != OsStr::new(".") && *name != OsStr::new("..")
        })
        .ok_or_else(|| Refusal::new("capsule output must name a fresh directory"))?;
    let canonical = parent.join(name);
    if canonical != path {
        return Err(Refusal::new(
            "capsule output path must use its canonical parent",
        ));
    }
    match fs::symlink_metadata(&canonical) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(canonical),
        Ok(_) => Err(Refusal::new("capsule output must not already exist")),
        Err(error) => Err(Refusal::new(format!(
            "could not inspect capsule output path: {error}"
        ))),
    }
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be an absolute path")));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("{label} is unavailable: {error}")))?;
    if canonical != path || !canonical.is_dir() {
        return Err(Refusal::new(format!(
            "{label} must be a canonical directory path"
        )));
    }
    Ok(canonical)
}

fn validate_disjoint_paths(request: &Request) -> Result<()> {
    if overlaps(&request.output, &request.source_root) {
        return Err(Refusal::new(
            "capsule output must be disjoint from the source checkout",
        ));
    }
    for material in request.source_inputs.iter().chain(&request.vendor_inputs) {
        let parent = material
            .path
            .parent()
            .ok_or_else(|| Refusal::new("material path has no parent directory"))?;
        let parent = fs::canonicalize(parent)
            .map_err(|error| Refusal::new(format!("material parent is unavailable: {error}")))?;
        let identity = parent.join(
            material
                .path
                .file_name()
                .ok_or_else(|| Refusal::new("material path has no basename"))?,
        );
        if overlaps(&request.output, &identity) {
            return Err(Refusal::new(
                "capsule output must be disjoint from declared material files",
            ));
        }
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn create_stage(output: &Path) -> Result<(PathBuf, PathBuf)> {
    let parent = output.parent().expect("validated output has a parent");
    for sequence in 0..1000_u32 {
        let candidate = parent.join(format!(
            ".ami-rust-capsules-{}-{sequence}.work",
            std::process::id()
        ));
        let failure = parent.join(format!(
            ".ami-rust-capsules-{}-{sequence}.failed",
            std::process::id()
        ));
        if candidate == output || failure == output {
            continue;
        }
        if fs::symlink_metadata(&failure).is_ok() {
            continue;
        }
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => {
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
                return Ok((candidate, failure));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not create private capsule staging: {error}"
                )));
            }
        }
    }
    Err(Refusal::new(
        "could not allocate a fresh private capsule staging directory",
    ))
}

fn retain_failure(
    stage: &Path,
    failed_path: &Path,
    request: &Request,
    error: &Refusal,
) -> Result<()> {
    for name in [
        format!("ami-rust-{}-sources.tar.xz", request.version),
        format!("ami-rust-{}-vendor.tar.xz", request.version),
    ] {
        match fs::remove_file(stage.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not remove a non-published capsule from failure staging: {error}"
                )));
            }
        }
    }
    let record = json!({
        "schema": RESULT_SCHEMA,
        "status": "FAILED",
        "version": request.version,
        "source": {"commit": request.commit, "tree": request.tree, "epoch": request.epoch},
        "artifacts": [],
        "error": error.to_string(),
        "claim": CAPSULE_CLAIM,
    });
    let result_path = stage.join("result.json");
    if result_path.exists() {
        fs::remove_file(&result_path)?;
    }
    write_json_new(&result_path, &record)?;
    sync_directory(stage)?;
    fs::rename(stage, failed_path).map_err(|rename_error| {
        Refusal::new(format!(
            "could not retain capsule failure record at {}: {rename_error}",
            stage.display()
        ))
    })?;
    sync_directory(failed_path.parent().expect("failure path has a parent"))?;
    Ok(())
}

fn write_json_new(path: &Path, value: &Value) -> Result<()> {
    let bytes = canonical_json(value)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Refusal::new(format!("could not serialize capsule inventory: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn output_text<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| Refusal::new(format!("{label} is not UTF-8")))
}

fn validate_version(version: &str) -> Result<()> {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(Refusal::new(
            "version must be a canonical stable three-part release version",
        ));
    }
    let parsed: Vec<u64> = parts
        .iter()
        .map(|part| part.parse::<u64>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Refusal::new("version component is too large"))?;
    if (parsed[0], parsed[1], parsed[2]) <= (0, 1, 0) {
        return Err(Refusal::new("version must be later than stable 0.1.0"));
    }
    Ok(())
}

fn validate_git_object_id(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::new(format!(
            "{label} must be a lowercase Git object identifier"
        )));
    }
    Ok(())
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        })
    {
        return Err(Refusal::new(format!(
            "{label} is not one safe portable POSIX component"
        )));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err(Refusal::new(format!(
            "{label} uses a reserved portable filename"
        )));
    }
    Ok(())
}

fn validate_archive_relative_path(value: &str) -> Result<()> {
    if !value.is_ascii() {
        return Err(Refusal::new(
            "tracked source path contains non-ASCII characters; only ASCII paths are supported",
        ));
    }
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f)
        || value.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with('.')
                || part.ends_with(' ')
        })
    {
        return Err(Refusal::new(
            "tracked source path is not a safe portable relative path",
        ));
    }
    Ok(())
}

fn absolute_path(value: &str, label: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be an absolute path")));
    }
    Ok(path)
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask toolchain-release-capsules --request FILE")
}

#[cfg(test)]
mod tests {
    use super::{Deadline, produce_request, resolve_git};
    use lzma_rust2::XzReader;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fs,
        io::Read,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let base =
                fs::canonicalize(std::env::temp_dir()).expect("canonical system temp directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "ami-rust-toolchain-capsule-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(fs::canonicalize(path).expect("canonical test root")),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create capsule test root: {error}"),
                }
            }
            panic!("could not allocate a capsule test root");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove capsule test root");
        }
    }

    struct Fixture {
        temp: TempTree,
        repo: PathBuf,
        source_material: PathBuf,
        vendor_material: PathBuf,
        commit: String,
        tree: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempTree::new();
            let repo = temp.path().join("sdk-source");
            fs::create_dir(&repo).expect("create tiny source checkout");
            let git = resolve_git().expect("resolve Git");
            git_command(&git, &repo, &["init", "-q"]);

            fs::write(repo.join(".gitignore"), "ignored.txt\n").expect("write ignore rule");
            fs::write(repo.join(".gitattributes"), "src/crlf.txt text eol=crlf\n")
                .expect("write deterministic EOL attribute");
            fs::create_dir(repo.join("src")).expect("create source tree");
            fs::write(
                repo.join("src/main.rs"),
                b"fn main() { println!(\"fixture\"); }\n",
            )
            .expect("write source file");
            fs::write(repo.join("src/crlf.txt"), b"checkout line\n")
                .expect("write canonical LF source file");
            fs::create_dir(repo.join("tools")).expect("create executable source directory");
            let executable = repo.join("tools/inspect");
            fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("write executable source");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
                .expect("mark source executable");
            git_command(&git, &repo, &["add", "--all"]);
            git_command(
                &git,
                &repo,
                &[
                    "-c",
                    "user.name=Capsule Fixture",
                    "-c",
                    "user.email=capsule@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "tiny fixture",
                ],
            );
            fs::remove_file(repo.join("src/crlf.txt")).expect("remove source before checkout");
            git_command(&git, &repo, &["checkout-index", "-f", "--", "src/crlf.txt"]);
            assert_eq!(
                fs::read(repo.join("src/crlf.txt")).expect("read EOL-converted checkout"),
                b"checkout line\r\n"
            );
            git_command(&git, &repo, &["add", "--", "src/crlf.txt"]);
            assert!(git_text(&git, &repo, &["status", "--porcelain=v1"]).is_empty());
            fs::write(repo.join("ignored.txt"), b"ignored working-tree file\n")
                .expect("write ignored untracked file");

            let source_material = temp.path().join("source-notes.diff");
            let vendor_material = temp.path().join("vendor-crate.toml");
            fs::write(&source_material, b"diff --git a/x b/x\n").expect("write source material");
            fs::write(
                &vendor_material,
                b"[package]\nname='fixture'\nversion='1.0.0'\n",
            )
            .expect("write vendor material");
            let commit = git_text(&git, &repo, &["rev-parse", "HEAD"]);
            let tree = git_text(&git, &repo, &["rev-parse", "HEAD^{tree}"]);
            Self {
                temp,
                repo: fs::canonicalize(repo).expect("canonical source checkout"),
                source_material,
                vendor_material,
                commit,
                tree,
            }
        }

        fn request(&self, output_name: &str) -> Value {
            let output = self.temp.path().join(output_name);
            json!({
                "schema": "ami-rust-toolchain-capsule-request-v1",
                "version": "0.2.0",
                "source": {
                    "commit": self.commit,
                    "tree": self.tree,
                    "epoch": 1_791_936_000_u64,
                },
                "source_root": self.repo,
                "source_inputs": [{
                    "role": "change-notes",
                    "path": self.source_material,
                    "bytes": fs::metadata(&self.source_material).expect("source material metadata").len(),
                    "sha256": ami_rust_core::digest::sha256_file(&self.source_material).expect("hash source material"),
                }],
                "vendor_inputs": [{
                    "role": "crate-index",
                    "path": self.vendor_material,
                    "bytes": fs::metadata(&self.vendor_material).expect("vendor material metadata").len(),
                    "sha256": ami_rust_core::digest::sha256_file(&self.vendor_material).expect("hash vendor material"),
                }],
                "output": output,
            })
        }

        fn run(&self, value: &Value) -> ami_rust_core::Result<Value> {
            let path = self.temp.path().join("request.json");
            fs::write(&path, serde_json::to_vec(value).expect("serialize request"))
                .expect("write request");
            let deadline = Deadline::acquire()?;
            produce_request(&path, &deadline)
        }
    }

    struct Member {
        bytes: Vec<u8>,
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    }

    fn git_command(git: &Path, root: &Path, arguments: &[&str]) {
        let mut command = Command::new(git);
        command
            .env_clear()
            .envs(super::git_environment())
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-C")
            .arg(root);
        for argument in arguments {
            command.arg(argument);
        }
        let output = command.output().expect("run local fixture Git command");
        assert!(
            output.status.success(),
            "fixture Git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_text(git: &Path, root: &Path, arguments: &[&str]) -> String {
        let mut command = Command::new(git);
        command
            .env_clear()
            .envs(super::git_environment())
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-C")
            .arg(root);
        for argument in arguments {
            command.arg(argument);
        }
        let output = command.output().expect("run local fixture Git query");
        assert!(output.status.success(), "fixture Git query failed");
        String::from_utf8(output.stdout)
            .expect("Git fixture output is UTF-8")
            .trim()
            .to_owned()
    }

    fn archive_members(path: &Path) -> BTreeMap<String, Member> {
        let file = fs::File::open(path).expect("open generated archive");
        let xz = XzReader::new_mem_limit(file, false, 64 * 1024);
        let mut archive = tar::Archive::new(xz);
        let mut members = BTreeMap::new();
        for entry in archive.entries().expect("read tar member list") {
            let mut entry = entry.expect("read tar member");
            let path = entry
                .path()
                .expect("member path")
                .to_str()
                .expect("UTF-8 member path")
                .to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).expect("read member bytes");
            let header = entry.header();
            assert_eq!(header.entry_type(), tar::EntryType::Regular);
            assert_eq!(header.uid().expect("uid"), 0);
            assert_eq!(header.gid().expect("gid"), 0);
            let member = Member {
                bytes,
                mode: header.mode().expect("mode"),
                uid: header.uid().expect("uid"),
                gid: header.gid().expect("gid"),
                mtime: header.mtime().expect("mtime"),
            };
            assert!(members.insert(path, member).is_none(), "duplicate tar path");
        }
        members
    }

    #[test]
    fn deterministic_capsules_contain_only_clean_tree_and_declared_materials() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.source_material, fs::Permissions::from_mode(0o600))
            .expect("set private source material mode");
        fs::set_permissions(&fixture.vendor_material, fs::Permissions::from_mode(0o600))
            .expect("set private vendor material mode");
        let first_request = fixture.request("first-output");
        let first = fixture
            .run(&first_request)
            .expect("produce first capsule set");
        fs::set_permissions(&fixture.source_material, fs::Permissions::from_mode(0o755))
            .expect("set executable source material mode");
        fs::set_permissions(&fixture.vendor_material, fs::Permissions::from_mode(0o755))
            .expect("set executable vendor material mode");
        let second_request = fixture.request("second-output");
        let second = fixture
            .run(&second_request)
            .expect("produce second capsule set");

        assert_eq!(first["status"], "COMPLETED_LOCAL_UNSIGNED_CANDIDATE_ONLY");
        assert_eq!(first["source"]["commit"], fixture.commit);
        assert_eq!(first["source"]["tree"], fixture.tree);
        assert_eq!(first["artifacts"].as_array().unwrap().len(), 2);
        assert!(
            first["claim"]
                .as_str()
                .unwrap()
                .contains("does not establish completeness")
        );

        for (output_name, artifact_name) in [
            ("first-output", "ami-rust-0.2.0-sources.tar.xz"),
            ("second-output", "ami-rust-0.2.0-sources.tar.xz"),
        ] {
            let output = fixture.temp.path().join(output_name);
            assert!(output.join("result.json").is_file());
            assert!(output.join(artifact_name).is_file());
            let mut names: Vec<_> = fs::read_dir(&output)
                .expect("read output payload directory")
                .map(|entry| {
                    entry
                        .expect("output entry")
                        .file_name()
                        .into_string()
                        .unwrap()
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    "ami-rust-0.2.0-sources.tar.xz",
                    "ami-rust-0.2.0-vendor.tar.xz",
                    "result.json",
                ]
            );
        }
        for name in [
            "ami-rust-0.2.0-sources.tar.xz",
            "ami-rust-0.2.0-vendor.tar.xz",
        ] {
            let first_bytes = fs::read(fixture.temp.path().join("first-output").join(name))
                .expect("read first deterministic archive");
            let second_bytes = fs::read(fixture.temp.path().join("second-output").join(name))
                .expect("read second deterministic archive");
            assert_eq!(
                first_bytes, second_bytes,
                "archive changed across fresh output roots"
            );
        }

        let source = archive_members(
            &fixture
                .temp
                .path()
                .join("first-output/ami-rust-0.2.0-sources.tar.xz"),
        );
        let prefix = "ami-rust-0.2.0/sources/";
        assert_eq!(source.len(), 7);
        let main = source
            .get(&format!("{prefix}repository/src/main.rs"))
            .unwrap();
        assert_eq!(main.bytes, b"fn main() { println!(\"fixture\"); }\n");
        assert_eq!(main.mode, 0o644);
        assert_eq!(main.mtime, 1_791_936_000);
        let eol_file = source
            .get(&format!("{prefix}repository/src/crlf.txt"))
            .unwrap();
        assert_eq!(eol_file.bytes, b"checkout line\n");
        assert_eq!(eol_file.mode, 0o644);
        let executable = source
            .get(&format!("{prefix}repository/tools/inspect"))
            .unwrap();
        assert_eq!(executable.mode, 0o755);
        assert_eq!(executable.uid, 0);
        assert_eq!(executable.gid, 0);
        assert!(source.contains_key(&format!("{prefix}repository/.gitignore")));
        assert!(source.contains_key(&format!("{prefix}materials/change-notes/source-notes.diff")));
        assert!(!source.contains_key(&format!("{prefix}repository/ignored.txt")));
        assert!(!source.keys().any(|path| path.contains("/.git/")));
        assert_eq!(
            source[&format!("{prefix}repository/.gitignore")].mode,
            0o644
        );
        assert_eq!(
            source[&format!("{prefix}materials/change-notes/source-notes.diff")].mode,
            0o644
        );
        assert_eq!(source[&format!("{prefix}inventory.json")].mode, 0o644);
        for member in source.values() {
            assert_eq!(member.uid, 0);
            assert_eq!(member.gid, 0);
            assert_eq!(member.mtime, 1_791_936_000);
        }
        let source_inventory = &source[&format!("{prefix}inventory.json")].bytes;
        let inventory: Value =
            serde_json::from_slice(source_inventory).expect("source inventory JSON");
        assert_eq!(
            inventory["schema"],
            "ami-rust-toolchain-source-capsule-inventory-v1"
        );
        assert_eq!(inventory["source"]["commit"], fixture.commit);
        assert_eq!(inventory["repository_files"].as_array().unwrap().len(), 5);
        assert!(
            !source_inventory
                .windows(fixture.temp.path().as_os_str().len())
                .any(|window| { window == fixture.temp.path().as_os_str().as_encoded_bytes() })
        );

        let vendor = archive_members(
            &fixture
                .temp
                .path()
                .join("first-output/ami-rust-0.2.0-vendor.tar.xz"),
        );
        assert_eq!(vendor.len(), 2);
        for member in vendor.values() {
            assert_eq!(member.mode, 0o644);
            assert_eq!(member.uid, 0);
            assert_eq!(member.gid, 0);
            assert_eq!(member.mtime, 1_791_936_000);
        }
        assert_eq!(
            vendor["ami-rust-0.2.0/vendor/materials/crate-index/vendor-crate.toml"].bytes,
            b"[package]\nname='fixture'\nversion='1.0.0'\n"
        );
        assert!(vendor.contains_key("ami-rust-0.2.0/vendor/inventory.json"));
        let vendor_inventory: Value =
            serde_json::from_slice(&vendor["ami-rust-0.2.0/vendor/inventory.json"].bytes)
                .expect("vendor inventory JSON");
        assert_eq!(
            vendor_inventory["schema"],
            "ami-rust-toolchain-vendor-capsule-inventory-v1"
        );
        assert_eq!(
            vendor_inventory["vendor_materials"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            second["artifacts"][0]["sha256"],
            first["artifacts"][0]["sha256"]
        );
        for (index, name) in [
            "ami-rust-0.2.0-sources.tar.xz",
            "ami-rust-0.2.0-vendor.tar.xz",
        ]
        .iter()
        .enumerate()
        {
            let path = fixture.temp.path().join("first-output").join(name);
            assert_eq!(first["artifacts"][index]["name"], *name);
            assert_eq!(
                first["artifacts"][index]["bytes"],
                fs::metadata(&path).unwrap().len()
            );
            assert_eq!(
                first["artifacts"][index]["sha256"],
                ami_rust_core::digest::sha256_file(&path).unwrap()
            );
        }
        let stored_result: Value = serde_json::from_slice(
            &fs::read(fixture.temp.path().join("first-output/result.json")).unwrap(),
        )
        .expect("stored result JSON");
        assert_eq!(stored_result, first);
    }

    #[test]
    fn source_blob_reads_ignore_git_replace_refs() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let fixture = Fixture::new();
        let git = resolve_git().expect("resolve Git");
        let original_blob = git_text(&git, &fixture.repo, &["rev-parse", "HEAD:src/main.rs"]);
        let replacement = fixture.temp.path().join("replacement.rs");
        let replacement_bytes = b"fn replacement() { panic!(\"replace ref\"); }\n";
        fs::write(&replacement, replacement_bytes).expect("write replacement blob source");
        let replacement_blob = git_text(
            &git,
            &fixture.repo,
            &["hash-object", "-w", replacement.to_str().unwrap()],
        );
        git_command(
            &git,
            &fixture.repo,
            &["replace", &original_blob, &replacement_blob],
        );

        let mut ordinary_git = Command::new(&git);
        ordinary_git
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-C")
            .arg(&fixture.repo)
            .args(["show", "HEAD:src/main.rs"]);
        let replaced = ordinary_git.output().expect("verify replacement ref");
        assert!(replaced.status.success());
        assert_eq!(replaced.stdout, replacement_bytes);

        let result = fixture
            .run(&fixture.request("replace-output"))
            .expect("produce capsule despite replace ref");
        let archive = archive_members(
            &fixture
                .temp
                .path()
                .join("replace-output/ami-rust-0.2.0-sources.tar.xz"),
        );
        assert_eq!(result["status"], "COMPLETED_LOCAL_UNSIGNED_CANDIDATE_ONLY");
        assert_eq!(
            archive["ami-rust-0.2.0/sources/repository/src/main.rs"].bytes,
            b"fn main() { println!(\"fixture\"); }\n"
        );
    }

    #[test]
    fn refuses_identity_tampering_and_dirty_checkout_without_output() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let fixture = Fixture::new();
        let mut changed_identity = fixture.request("identity-output");
        changed_identity["source"]["tree"] = json!("0".repeat(40));
        assert!(fixture.run(&changed_identity).is_err());
        assert!(!fixture.temp.path().join("identity-output").exists());

        let mut nested_output = fixture.request("source-overlap-output");
        nested_output["output"] = json!(fixture.repo.join("capsules"));
        assert!(fixture.run(&nested_output).is_err());
        assert!(!fixture.repo.join("capsules").exists());

        let dirty = fixture.request("dirty-output");
        fs::write(
            fixture.repo.join("src/main.rs"),
            b"modified after source commit\n",
        )
        .expect("mutate tracked file");
        assert!(fixture.run(&dirty).is_err());
        assert!(!fixture.temp.path().join("dirty-output").exists());

        fs::write(
            fixture.repo.join("src/main.rs"),
            b"fn main() { println!(\"fixture\"); }\n",
        )
        .expect("restore tracked source bytes");
        fs::write(
            fixture.repo.join("untracked.txt"),
            b"not part of the source tree\n",
        )
        .expect("create non-ignored untracked file");
        let untracked = fixture.request("untracked-output");
        assert!(fixture.run(&untracked).is_err());
        assert!(!fixture.temp.path().join("untracked-output").exists());
    }

    #[test]
    fn refuses_bad_material_hash_unsafe_names_and_unknown_request_fields() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut fixture = Fixture::new();
        for path in ["src/caf\u{00e9}.txt", "src/cafe\u{0301}.txt"] {
            let error = super::validate_archive_relative_path(path)
                .expect_err("reject non-ASCII normalized and decomposed paths");
            assert!(error.to_string().contains("non-ASCII"));
        }

        let mut bad_hash = fixture.request("bad-hash-output");
        bad_hash["vendor_inputs"][0]["sha256"] = json!("f".repeat(64));
        assert!(fixture.run(&bad_hash).is_err());
        assert!(!fixture.temp.path().join("bad-hash-output").exists());
        let failed_stage = fs::read_dir(fixture.temp.path())
            .expect("read retained failure stage")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "failed")
            })
            .expect("failure stage retained");
        let failure: Value = serde_json::from_slice(
            &fs::read(failed_stage.join("result.json")).expect("read failure result"),
        )
        .expect("parse failure result");
        assert_eq!(failure["status"], "FAILED");
        assert_eq!(failure["artifacts"].as_array().unwrap().len(), 0);
        assert!(
            !failure
                .to_string()
                .contains(&fixture.temp.path().display().to_string())
        );

        let mut unsafe_role = fixture.request("unsafe-role-output");
        unsafe_role["source_inputs"][0]["role"] = json!("../outside");
        assert!(fixture.run(&unsafe_role).is_err());
        assert!(!fixture.temp.path().join("unsafe-role-output").exists());

        let source_link = fixture.temp.path().join("source-material-link.diff");
        std::os::unix::fs::symlink(&fixture.source_material, &source_link)
            .expect("create material symlink");
        let mut linked_material = fixture.request("symlink-material-output");
        linked_material["source_inputs"][0]["path"] = json!(source_link);
        assert!(fixture.run(&linked_material).is_err());
        assert!(!fixture.temp.path().join("symlink-material-output").exists());

        let mut unknown = fixture.request("unknown-field-output");
        unknown["network"] = json!("forbidden");
        assert!(fixture.run(&unknown).is_err());
        assert!(!fixture.temp.path().join("unknown-field-output").exists());

        let normalized_path = fixture.repo.join("src/cafe\u{0301}.txt");
        fs::write(&normalized_path, b"non-ASCII filename\n").expect("write Unicode source path");
        let git = resolve_git().expect("resolve Git");
        git_command(&git, &fixture.repo, &["add", "--all"]);
        git_command(
            &git,
            &fixture.repo,
            &[
                "-c",
                "user.name=Capsule Fixture",
                "-c",
                "user.email=capsule@example.invalid",
                "commit",
                "-q",
                "-m",
                "non-ASCII path fixture",
            ],
        );
        fixture.commit = git_text(&git, &fixture.repo, &["rev-parse", "HEAD"]);
        fixture.tree = git_text(&git, &fixture.repo, &["rev-parse", "HEAD^{tree}"]);
        let error = fixture
            .run(&fixture.request("non-ascii-path-output"))
            .expect_err("refuse non-ASCII tracked source path");
        assert!(error.to_string().contains("non-ASCII"));
        assert!(!fixture.temp.path().join("non-ascii-path-output").exists());
    }

    #[test]
    fn refuses_output_reuse_and_symlink_output_without_touching_target() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let fixture = Fixture::new();
        for output_name in [
            format!(".ami-rust-capsules-{}-0.work", std::process::id()),
            format!(".ami-rust-capsules-{}-0.failed", std::process::id()),
        ] {
            let requested_output = fixture.temp.path().join(output_name);
            let (stage, _) = super::create_stage(&requested_output).expect("create staging");
            assert_ne!(stage, requested_output);
            fs::remove_dir_all(stage).expect("remove direct stage fixture");
        }
        let request = fixture.request("reused-output");
        fixture.run(&request).expect("initial fresh output");
        assert!(fixture.run(&request).is_err());

        let target = fixture.temp.path().join("untouched-target");
        fs::create_dir(&target).expect("create symlink target");
        let output_link = fixture.temp.path().join("symlink-output");
        std::os::unix::fs::symlink(&target, &output_link).expect("create output symlink");
        let mut symlink_request = fixture.request("symlink-output");
        symlink_request["output"] = json!(output_link);
        assert!(fixture.run(&symlink_request).is_err());
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
    }
}
