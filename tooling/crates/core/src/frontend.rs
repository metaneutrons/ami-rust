//! The two executable names enter this same parser and dispatcher.
use crate::{Refusal, Result};
use serde::Serialize;
use std::{ffi::OsString, path::Path};

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
        implemented: false,
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
    if let Some(arg) = args.first()
        && CAPABILITIES
            .iter()
            .any(|item| !item.implemented && arg == item.command)
    {
        return Err(Refusal::new(
            "command is not implemented in this development build",
        ));
    }
    Err(Refusal::new(
        "expected --version or --help as the only argument",
    ))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Version<'a> {
    schema: &'a str,
    cli_version: &'a str,
    sdk_version: &'a str,
    packaging_revision: u32,
}

pub fn render(invocation: Invocation) -> Result<Vec<u8>> {
    match invocation {
        Invocation::Help => Ok(b"ami-rust native host tooling (development)\n\nUsage: ami-rust --version\n       ami-rust --help\n\nOnly help and version are implemented in this development slice.\n".to_vec()),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
            1
        );
        for item in CAPABILITIES.iter().filter(|item| !item.implemented) {
            let error = parse(Path::new("ami-rust"), &args(&[item.command])).unwrap_err();
            assert!(error.to_string().contains("not implemented"));
        }
    }
}
