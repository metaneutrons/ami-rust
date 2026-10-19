//! The two executable names enter this same parser and dispatcher.
use crate::{Refusal, Result};
use serde::Serialize;
use std::{
    ffi::OsString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// The unimplemented entries are migration debt, never successful no-op commands.
pub struct Capability {
    pub name: &'static str,
    pub command: &'static str,
    pub implemented: bool,
}

pub const CAPABILITIES: &[Capability] = &[
    Capability {
        name: "version",
        command: "--version",
        implemented: true,
    },
    Capability {
        name: "verify package",
        command: "verify-package",
        implemented: false,
    },
    Capability {
        name: "prepare",
        command: "prepare",
        implemented: false,
    },
    Capability {
        name: "new project",
        command: "new",
        implemented: false,
    },
    Capability {
        name: "build project",
        command: "build",
        implemented: false,
    },
    Capability {
        name: "check inputs",
        command: "check-inputs",
        implemented: false,
    },
    Capability {
        name: "verify SDK lock",
        command: "verify",
        implemented: false,
    },
    Capability {
        name: "build with SDK lock",
        command: "build",
        implemented: false,
    },
    Capability {
        name: "verify release",
        command: "verify",
        implemented: true,
    },
    Capability {
        name: "install release",
        command: "install",
        implemented: false,
    },
    Capability {
        name: "lock project",
        command: "lock",
        implemented: false,
    },
    Capability {
        name: "uninstall",
        command: "uninstall",
        implemented: false,
    },
    Capability {
        name: "inspect or migrate",
        command: "migrate",
        implemented: false,
    },
];

#[derive(Debug, Eq, PartialEq)]
pub enum Invocation {
    Help,
    Version,
    VerifyRelease { bundle: PathBuf, policy: PathBuf },
}

/// Preserve OS path arguments. Cargo injects `ami` only for the plugin name.
pub fn parse(executable: &Path, arguments: &[OsString]) -> Result<Invocation> {
    let plugin = executable
        .file_name()
        .is_some_and(|name| name == "cargo-ami");
    let args = if plugin && arguments.first().is_some_and(|arg| arg == "ami") {
        &arguments[1..]
    } else {
        arguments
    };
    if args.len() == 1 {
        if args[0] == "--version" {
            return Ok(Invocation::Version);
        }
        if args[0] == "--help" || args[0] == "-h" {
            return Ok(Invocation::Help);
        }
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        return parse_verify_release(&args[1..]);
    }
    if let Some(arg) = args.first()
        && CAPABILITIES.iter().any(|item| {
            !item.implemented
                && arg == item.command
                && !CAPABILITIES
                    .iter()
                    .any(|candidate| candidate.command == item.command && candidate.implemented)
        })
    {
        return Err(Refusal::new(
            "command is not implemented in this development build",
        ));
    }
    Err(Refusal::new(
        "expected --version, --help, or verify --bundle PATH --policy EXTERNAL_POLICY",
    ))
}

fn parse_verify_release(arguments: &[OsString]) -> Result<Invocation> {
    if arguments.first().is_some_and(|arg| arg == "--sdk-lock") {
        return Err(Refusal::new(
            "verify SDK lock is not implemented in this development build",
        ));
    }
    let mut bundle = None;
    let mut policy = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = &arguments[index];
        let slot = if option == "--bundle" {
            &mut bundle
        } else if option == "--policy" {
            &mut policy
        } else {
            return Err(Refusal::new("verify accepts only --bundle and --policy"));
        };
        if slot.is_some() {
            return Err(Refusal::new("verify options may be supplied only once"));
        }
        index += 1;
        let value = arguments
            .get(index)
            .filter(|value| !value.as_bytes().starts_with(b"-"))
            .ok_or_else(|| Refusal::new(format!("{option:?} requires a path argument")))?;
        *slot = Some(PathBuf::from(value.as_os_str()));
        index += 1;
    }
    let bundle = bundle.ok_or_else(|| Refusal::new("verify requires --bundle PATH"))?;
    let policy = policy.ok_or_else(|| Refusal::new("verify requires --policy PATH"))?;
    Ok(Invocation::VerifyRelease { bundle, policy })
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Version<'a> {
    schema: &'a str,
    cli_version: &'a str,
    sdk_version: &'a str,
    packaging_revision: u32,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct VerifyReleaseOutput<'a> {
    schema: &'static str,
    status: &'static str,
    verification_scope: &'static str,
    publisher: &'a crate::receipts::Authentication,
    release_cosign_bundle: ArtifactIdentity,
    manifest: ManifestSummary<'a>,
    sdk: &'a crate::sdk::VerifiedSdkV2Summary,
    resource_reports: &'a [crate::resource_capture::ResourceReport],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    bytes: usize,
    sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestSummary<'a> {
    schema: &'static str,
    version: &'a str,
    qualification_only: bool,
    sdk_archive: &'a str,
    sdk_manifest_sha256: &'a crate::records::Sha256,
    manifest_sha256: String,
    assets: Vec<AssetSummary<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AssetSummary<'a> {
    path: &'a str,
    bytes: u64,
    sha256: &'a crate::records::Sha256,
}

pub fn render(invocation: Invocation) -> Result<Vec<u8>> {
    match invocation {
        Invocation::Help => Ok(b"ami-rust native host tooling\n\nUsage:\n  ami-rust --version\n  ami-rust --help\n  ami-rust verify --bundle PATH --policy EXTERNAL_POLICY\n\n`verify --sdk-lock FILE` is not implemented. Release verification authenticates the publisher and checks SDK-v2 structure; it does not claim R1 acceptance or native build qualification.\n".to_vec()),
        Invocation::Version => {
            let mut output = serde_json::to_vec(&Version {
                schema: "ami-rust-version-v1",
                cli_version: env!("CARGO_PKG_VERSION"),
                // This bare development binary references the immutable SDK;
                // revision zero means no package adapter is installed by it.
                sdk_version: "0.1.0",
                packaging_revision: 0,
            }).map_err(|error| Refusal::new(format!("cannot encode version: {error}")))?;
            output.push(b'\n');
            Ok(output)
        }
        Invocation::VerifyRelease { bundle, policy } => render_verify_release(&bundle, &policy),
    }
}

fn render_verify_release(bundle_path: &Path, policy_path: &Path) -> Result<Vec<u8>> {
    let guard = crate::signals::SigtermGuard::acquire()?;
    let result = (|| {
        guard.check()?;
        let bundle_path = std::fs::canonicalize(bundle_path)
            .map_err(|error| Refusal::new(format!("could not resolve release bundle: {error}")))?;
        let policy_path = std::fs::canonicalize(policy_path)
            .map_err(|error| Refusal::new(format!("could not resolve external policy: {error}")))?;
        guard.check()?;
        let verified =
            crate::publisher::verify_publisher_bundle(&bundle_path, &policy_path, || {
                guard.requested()
            })?;
        guard.check()?;
        let sdk = crate::sdk::compose_verified_sdk_v2(&verified)?;
        guard.check()?;

        let manifest = verified.manifest();
        let assets = manifest
            .assets
            .iter()
            .map(|asset| AssetSummary {
                path: &asset.path,
                bytes: asset.bytes,
                sha256: &asset.sha256,
            })
            .collect();
        let signature = verified.release_signature();
        let output = VerifyReleaseOutput {
            schema: "ami-rust-release-verification-v1",
            status: "verified",
            verification_scope: "publisher authentication and SDK-v2 structural verification only; R1 acceptance and native build qualification were not assessed",
            publisher: verified.authentication(),
            release_cosign_bundle: ArtifactIdentity {
                bytes: signature.len(),
                sha256: crate::digest::sha256_bytes(signature),
            },
            manifest: ManifestSummary {
                schema: "ami-rust-release-v2",
                version: &manifest.version,
                qualification_only: manifest.qualification_only,
                sdk_archive: &manifest.sdk_archive,
                sdk_manifest_sha256: &manifest.sdk_manifest_sha256,
                manifest_sha256: crate::digest::sha256_bytes(verified.raw_manifest()),
                assets,
            },
            sdk: &sdk,
            resource_reports: verified.resource_reports(),
        };
        let mut bytes = serde_json::to_vec(&output)
            .map_err(|error| Refusal::new(format!("cannot encode verification result: {error}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    })();
    let finish = guard.finish();
    match (result, finish) {
        (Err(error), Err(cleanup)) => Err(Refusal::new(format!(
            "{error}; SIGTERM handler restoration also failed: {cleanup}"
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(output), Ok(())) => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::ffi::OsStringExt;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn both_names_share_parser_and_exact_separator_rules() {
        for (argv, expected) in [
            (args(&["--version"]), Some(Invocation::Version)),
            (args(&["--help"]), Some(Invocation::Help)),
            (args(&["-h"]), Some(Invocation::Help)),
            (args(&[]), None),
            (args(&["--version", "--version"]), None),
            (args(&["--version", "extra"]), None),
            (args(&["--", "--version"]), None),
            (args(&["unknown"]), None),
            (args(&["ami", "--version"]), None),
        ] {
            assert_eq!(parse(Path::new("ami-rust"), &argv).ok(), expected);
            // Cargo's token is prepended once, then removed once.
            let mut injected = args(&["ami"]);
            injected.extend(argv.clone());
            assert_eq!(parse(Path::new("cargo-ami"), &injected).ok(), expected);
        }
        assert_eq!(
            parse(Path::new("cargo-ami"), &args(&["--version"])).unwrap(),
            Invocation::Version
        );
    }

    #[test]
    fn verify_release_requires_one_bundle_and_policy_in_either_order() {
        let expected = Invocation::VerifyRelease {
            bundle: PathBuf::from("bundle-dir"),
            policy: PathBuf::from("policy.json"),
        };
        for argv in [
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--policy",
                "policy.json",
            ]),
            args(&[
                "verify",
                "--policy",
                "policy.json",
                "--bundle",
                "bundle-dir",
            ]),
        ] {
            assert_eq!(parse(Path::new("ami-rust"), &argv).unwrap(), expected);
            let mut injected = args(&["ami"]);
            injected.extend(argv);
            assert_eq!(parse(Path::new("cargo-ami"), &injected).unwrap(), expected);
        }
    }

    #[test]
    fn verify_release_preserves_non_utf8_paths_and_refuses_ambiguous_arguments() {
        let bundle = OsString::from_vec(b"bundle-\xff".to_vec());
        let parsed = parse(
            Path::new("ami-rust"),
            &[
                OsString::from("verify"),
                OsString::from("--bundle"),
                bundle.clone(),
                OsString::from("--policy"),
                OsString::from("policy.json"),
            ],
        )
        .unwrap();
        assert_eq!(
            parsed,
            Invocation::VerifyRelease {
                bundle: PathBuf::from(bundle),
                policy: PathBuf::from("policy.json"),
            }
        );

        for argv in [
            args(&["verify"]),
            args(&["verify", "--bundle"]),
            args(&["verify", "--bundle", "bundle-dir"]),
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--bundle",
                "other-dir",
                "--policy",
                "policy.json",
            ]),
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--policy",
                "policy.json",
                "--policy",
                "other.json",
            ]),
            args(&["verify", "--bundle", "--policy", "policy.json"]),
            args(&["verify", "--bundle", "--unknown", "--policy", "policy.json"]),
            args(&["verify", "--unknown", "value"]),
            args(&["verify", "bundle-dir", "--policy", "policy.json"]),
            args(&["verify", "--sdk-lock", "lock.json"]),
        ] {
            assert!(parse(Path::new("ami-rust"), &argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn capability_ledger_matches_normative_contract_and_refuses_pending_work() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/rust-cli-migration/contracts-v1.json"
        ))
        .unwrap();
        let expected: BTreeSet<_> = contract["future_frontend_contract"]["capability_matrix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["capability"].as_str().unwrap())
            .collect();
        let actual: BTreeSet<_> = CAPABILITIES.iter().map(|item| item.name).collect();
        assert_eq!(actual.len(), CAPABILITIES.len());
        assert_eq!(actual, expected);
        assert_eq!(
            CAPABILITIES.iter().filter(|item| item.implemented).count(),
            2
        );
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "verify release" && item.command == "verify" && item.implemented
        }));
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "verify SDK lock" && item.command == "verify" && !item.implemented
        }));
        assert!(
            parse(
                Path::new("ami-rust"),
                &args(&["verify", "--sdk-lock", "lock.json"])
            )
            .unwrap_err()
            .to_string()
            .contains("verify SDK lock is not implemented")
        );
        for item in CAPABILITIES.iter().filter(|item| !item.implemented) {
            if CAPABILITIES
                .iter()
                .any(|candidate| candidate.command == item.command && candidate.implemented)
            {
                continue;
            }
            let error = parse(Path::new("ami-rust"), &args(&[item.command])).unwrap_err();
            assert!(error.to_string().contains("not implemented"));
        }
    }
}
