//! Parse the small portion of rustc's native linker argument vector owned by
//! this crate. This is argument extraction only: callers must separately
//! validate native-object records, toolchain policy, and output ownership.

use crate::{Refusal, Result};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// The extracted paths and remaining linker arguments.
///
/// Every retained argument is copied byte-for-byte and in its original order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLink {
    pub output: PathBuf,
    pub native_objects: PathBuf,
    pub rust_arguments: Vec<OsString>,
}

/// Extract one output, one native-object directory association, and rust-lld's
/// GNU flavor selector. This does not authorize any retained argument.
pub fn parse(arguments: &[OsString]) -> Result<ParsedLink> {
    let mut output = None;
    let mut native_objects = None;
    let mut flavor_seen = false;
    let mut retained = Vec::new();
    let mut args = arguments.iter();

    while let Some(arg) = args.next() {
        if arg == OsStr::new("-o") {
            if output.is_some() {
                return Err(Refusal::new("duplicate linker output"));
            }
            let value = args
                .next()
                .ok_or_else(|| Refusal::new("missing linker output"))?;
            let path = PathBuf::from(value);
            normalized_absolute(&path)?;
            output = Some(path);
            continue;
        }

        if arg == OsStr::new("-flavor") {
            if flavor_seen {
                return Err(Refusal::new("duplicate linker flavor"));
            }
            flavor_seen = true;
            if args.next().map(OsString::as_os_str) != Some(OsStr::new("gnu")) {
                return Err(Refusal::new("linker flavor must be GNU"));
            }
            continue;
        }

        let raw = arg.as_os_str().as_bytes();
        if let Some(value) = raw.strip_prefix(b"--ami-native-objects=") {
            if native_objects.is_some() {
                return Err(Refusal::new("duplicate native-object directory"));
            }
            let path = PathBuf::from(OsStr::from_bytes(value));
            normalized_absolute(&path)?;
            native_objects = Some(path);
            continue;
        }

        if raw.starts_with(b"--ami-native-objects") {
            return Err(Refusal::new("malformed native-object directory argument"));
        }
        if raw.starts_with(b"--output") || raw.starts_with(b"-o") {
            return Err(Refusal::new("ambiguous linker output argument"));
        }
        if raw.starts_with(b"@") {
            return Err(Refusal::new("linker response files are not accepted"));
        }
        if raw.starts_with(b"--sysroot") || raw.starts_with(b"-m") {
            return Err(Refusal::new(
                "linker sysroot and machine overrides are reserved",
            ));
        }

        retained.push(arg.clone());
    }

    if !flavor_seen {
        return Err(Refusal::new("missing linker flavor"));
    }

    Ok(ParsedLink {
        output: output.ok_or_else(|| Refusal::new("missing linker output"))?,
        native_objects: native_objects
            .ok_or_else(|| Refusal::new("missing native-object directory"))?,
        rust_arguments: retained,
    })
}

/// Require an absolute, normalized, non-root Unix path. Rejecting empty,
/// dot, and parent components keeps path spelling deterministic without
/// resolving symlinks or asserting anything about filesystem ownership.
fn normalized_absolute(path: &Path) -> Result<()> {
    let raw = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || raw == b"/"
        || raw.contains(&0)
        || raw[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(Refusal::new(
            "linker path must be normalized absolute and non-root",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn actual_rustc_shape() -> Vec<OsString> {
        [
            "-flavor",
            "gnu",
            "/target root/one.rcgu.o",
            "-Bstatic",
            "/rust root/liballoc.rlib",
            "--gc-sections",
            "-o",
            "/target root/release/app",
            "--no-gc-sections",
            "--ami-native-objects=/build root/native",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn extracts_rustc_shape_and_preserves_argument_order() {
        let parsed = parse(&actual_rustc_shape()).unwrap();

        assert_eq!(parsed.output, Path::new("/target root/release/app"));
        assert_eq!(parsed.native_objects, Path::new("/build root/native"));
        assert_eq!(
            parsed.rust_arguments,
            [
                "/target root/one.rcgu.o",
                "-Bstatic",
                "/rust root/liballoc.rlib",
                "--gc-sections",
                "--no-gc-sections",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn preserves_non_utf8_arguments_and_path_bytes() {
        let output = b"/target \xff/app";
        let native_objects = b"/build \xfe/native";
        let object = b"/target \xfd/unit.o";
        let arguments = vec![
            OsString::from("-flavor"),
            OsString::from("gnu"),
            OsString::from_vec(object.to_vec()),
            OsString::from("-o"),
            OsString::from_vec(output.to_vec()),
            OsString::from_vec([b"--ami-native-objects=".as_slice(), native_objects].concat()),
        ];

        let parsed = parse(&arguments).unwrap();

        assert_eq!(parsed.output.as_os_str().as_bytes(), output);
        assert_eq!(parsed.native_objects.as_os_str().as_bytes(), native_objects);
        assert_eq!(parsed.rust_arguments, [OsString::from_vec(object.to_vec())]);
    }

    #[test]
    fn rejects_duplicate_and_missing_owned_arguments() {
        for extra in [
            vec!["-o", "/another/output"],
            vec!["-flavor", "gnu"],
            vec!["--ami-native-objects=/another/native"],
        ] {
            let mut arguments = actual_rustc_shape();
            arguments.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&arguments).is_err());
        }

        for missing in ["flavor", "output", "native"] {
            let mut arguments = actual_rustc_shape();
            match missing {
                "flavor" => {
                    arguments.drain(0..2);
                }
                "output" => {
                    arguments.drain(6..8);
                }
                _ => {
                    arguments.pop();
                }
            }
            assert!(parse(&arguments).is_err());
        }
    }

    #[test]
    fn rejects_malformed_paths_flavors_and_markers() {
        for (index, value) in [
            (1, "darwin"),
            (7, "relative/app"),
            (7, "/target/../app"),
            (7, "/target/./app"),
            (7, "/target//app"),
            (7, "/"),
            (9, "--ami-native-objects=relative/native"),
            (9, "--ami-native-objects=/build/../native"),
            (9, "--ami-native-objects=/build//native"),
            (9, "--ami-native-objects"),
            (9, "--ami-native-objects-extra=/build/native"),
        ] {
            let mut arguments = actual_rustc_shape();
            arguments[index] = value.into();
            assert!(parse(&arguments).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_ambiguous_response_and_reserved_arguments() {
        for rejected in [
            "--output=/other/app",
            "--output-file=/other/app",
            "-o/other/app",
            "@hidden.rsp",
            "--sysroot",
            "--sysroot=/sdk",
            "--sysroot-extra=/sdk",
            "-m",
            "-march=x86_64",
        ] {
            let mut arguments = actual_rustc_shape();
            arguments.push(rejected.into());
            assert!(parse(&arguments).is_err(), "{rejected}");
        }
    }
}
