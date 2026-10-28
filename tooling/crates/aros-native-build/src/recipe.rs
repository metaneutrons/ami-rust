//! Pure descriptions of the fixed AROS native build commands.
//!
//! Callers select and verify every input before constructing a recipe, then
//! create directories and supervise the described commands. This module does
//! not inspect the filesystem or execute tools.

use crate::{Refusal, Result};
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

/// A program and its exact argument vector, ready for an external supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRecipe {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
}

/// Paths selected and verified by the caller for the native build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRecipePaths {
    pub source_root: PathBuf,
    pub toolchain_root: PathBuf,
    pub sdk_root: PathBuf,
    pub collector: PathBuf,
}

/// Inputs that affect the fixed native command recipes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBuildRecipe {
    pub paths: NativeRecipePaths,
    pub testing: bool,
}

/// C translation units in the frozen producer sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CSourceUnit {
    Entry,
    Sdk,
    Layout,
    BindDiagnostics,
}

impl CSourceUnit {
    fn source_relative(self) -> &'static str {
        match self {
            Self::Entry => "native/entry.c",
            Self::Sdk => "native/sdk.c",
            Self::Layout => "native/layout.c",
            Self::BindDiagnostics => "tests/measurement/ami_test_bind_diagnostics.c",
        }
    }

    fn output_name(self) -> &'static str {
        match self {
            Self::Entry => "entry.o",
            Self::Sdk => "sdk.o",
            Self::Layout => "layout.o",
            Self::BindDiagnostics => "bind.o",
        }
    }
}

impl NativeBuildRecipe {
    /// Describe the frozen C compile command with an explicit object directory.
    /// The directory is selected by the caller and need not exist.
    pub fn c_compile_spec_into(
        &self,
        unit: CSourceUnit,
        native_objects: &Path,
    ) -> Result<CommandRecipe> {
        if unit == CSourceUnit::BindDiagnostics && !self.testing {
            return Err(Refusal::new(
                "diagnostic binding C unit is available only to testing builds",
            ));
        }
        validate_explicit_path(&self.paths.source_root)?;
        validate_explicit_path(&self.paths.toolchain_root)?;
        validate_explicit_path(&self.paths.sdk_root)?;
        validate_explicit_path(native_objects)?;

        let mut arguments = vec![
            OsString::from("--target=x86_64-unknown-aros"),
            OsString::from("-D__AROS__=1"),
            OsString::from("-D__AROS_VERSION__=1"),
            OsString::from("-DAMIGA=1"),
            OsString::from("-D_AMIGA=1"),
            OsString::from("-ffreestanding"),
            OsString::from("-fno-stack-protector"),
            OsString::from("-mno-red-zone"),
            OsString::from("-mcmodel=large"),
            OsString::from("-O2"),
            OsString::from("-g0"),
            OsString::from("-fno-ident"),
            OsString::from("-std=gnu11"),
            OsString::from("-Wall"),
            OsString::from("-Wextra"),
            OsString::from("-Werror"),
            prefixed_path("-ffile-prefix-map=", &self.paths.source_root, "=/ami-rust"),
            prefixed_path("-I", &self.paths.sdk_root.join("include/aros/stdc"), ""),
            prefixed_path("-I", &self.paths.sdk_root.join("include"), ""),
        ];
        if self.testing {
            arguments.push(OsString::from("-DAMI_SDK_TESTING=1"));
        }
        arguments.push(OsString::from("-c"));
        arguments.push(
            self.paths
                .source_root
                .join(unit.source_relative())
                .into_os_string(),
        );
        arguments.push(OsString::from("-o"));
        arguments.push(native_objects.join(unit.output_name()).into_os_string());

        Ok(CommandRecipe {
            program: self.paths.toolchain_root.join("bin/clang"),
            arguments,
        })
    }

    /// Describe startup symbol rewriting with an explicit native object
    /// directory. The directory is selected by the caller and need not exist.
    pub fn startup_spec_into(&self, native_objects: &Path) -> Result<CommandRecipe> {
        validate_explicit_path(&self.paths.toolchain_root)?;
        validate_explicit_path(&self.paths.sdk_root)?;
        validate_explicit_path(native_objects)?;

        Ok(CommandRecipe {
            program: self.paths.toolchain_root.join("bin/llvm-objcopy"),
            arguments: vec![
                OsString::from("--redefine-sym"),
                OsString::from("__startup_entry=ami_sdk_startup_entry"),
                self.paths.sdk_root.join("lib/startup.o").into_os_string(),
                native_objects.join("startup.o").into_os_string(),
            ],
        })
    }

    /// Describe the frozen collector command around caller-selected linker
    /// inputs and output paths. Linker inputs are preserved byte-for-byte.
    pub fn collector_spec_for_cargo(
        &self,
        native_objects: &Path,
        link_inputs: &[OsString],
        output: &Path,
        map: &Path,
    ) -> Result<CommandRecipe> {
        validate_explicit_path(&self.paths.sdk_root)?;
        validate_explicit_path(&self.paths.toolchain_root)?;
        validate_explicit_path(&self.paths.collector)?;
        validate_explicit_path(native_objects)?;
        validate_explicit_path(output)?;
        validate_explicit_path(map)?;

        let mut arguments = vec![
            prefixed_path("--sysroot=", &self.paths.sdk_root, ""),
            OsString::from("-m"),
            OsString::from("elf_x86_64"),
            OsString::from("-Map"),
            map.as_os_str().to_os_string(),
            OsString::from("-o"),
            output.as_os_str().to_os_string(),
            native_objects.join("entry.o").into_os_string(),
            native_objects.join("startup.o").into_os_string(),
            native_objects.join("sdk.o").into_os_string(),
            native_objects.join("layout.o").into_os_string(),
        ];
        if self.testing {
            arguments.push(native_objects.join("bind.o").into_os_string());
        }
        arguments.extend(link_inputs.iter().cloned());
        arguments.push(prefixed_path("-L", &self.paths.sdk_root.join("lib"), ""));
        arguments.push(OsString::from("--start-group"));
        arguments.extend(
            [
                "-lmui",
                "-lamiga",
                "-larossupport",
                "-lstdcio",
                "-lstdc",
                "-lposixc",
                "-ldos",
                "-lexec",
                "-lautoinit",
                "-llibinit",
                "-lutility",
                "-laros",
                "-ldebug",
            ]
            .into_iter()
            .map(OsString::from),
        );
        arguments.push(OsString::from("--end-group"));
        arguments.push(
            self.paths
                .toolchain_root
                .join("lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a")
                .into_os_string(),
        );

        Ok(CommandRecipe {
            program: self.paths.collector.clone(),
            arguments,
        })
    }

    /// Describe the frozen strip command with explicit input and output paths.
    /// Both paths are checked lexically and need not exist.
    pub fn strip_spec_for_paths(&self, input: &Path, output: &Path) -> Result<CommandRecipe> {
        validate_explicit_path(&self.paths.toolchain_root)?;
        validate_explicit_path(input)?;
        validate_explicit_path(output)?;

        Ok(CommandRecipe {
            program: self.paths.toolchain_root.join("bin/llvm-strip"),
            arguments: vec![
                OsString::from("--strip-unneeded"),
                OsString::from("--keep-symbol=__startup_entry"),
                OsString::from("-o"),
                output.as_os_str().to_os_string(),
                input.as_os_str().to_os_string(),
            ],
        })
    }
}

fn prefixed_path(prefix: &str, path: &Path, suffix: &str) -> OsString {
    let mut argument = OsString::from(prefix);
    argument.push(path.as_os_str());
    argument.push(suffix);
    argument
}

fn validate_explicit_path(path: &Path) -> Result<()> {
    let components_are_normal = path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    #[cfg(unix)]
    let spelling_is_normal = {
        let bytes = path.as_os_str().as_encoded_bytes();
        bytes.first() == Some(&b'/')
            && !bytes.windows(2).any(|pair| pair == b"//")
            && !bytes
                .split(|byte| *byte == b'/')
                .skip(1)
                .any(|component| component.is_empty() || component == b"." || component == b"..")
    };
    #[cfg(not(unix))]
    let spelling_is_normal = components_are_normal;

    if !path.is_absolute()
        || path.file_name().is_none()
        || !components_are_normal
        || !spelling_is_normal
    {
        return Err(Refusal::new(
            "explicit native path must be absolute, normalized, and non-root",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn recipe(testing: bool) -> NativeBuildRecipe {
        NativeBuildRecipe {
            paths: NativeRecipePaths {
                source_root: PathBuf::from("/source tree"),
                toolchain_root: PathBuf::from("/target tools"),
                sdk_root: PathBuf::from("/sdk root"),
                collector: PathBuf::from("/collector tools/bin/collect-aros"),
            },
            testing,
        }
    }

    fn strings(values: &[OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_str().expect("test arguments are UTF-8").to_owned())
            .collect()
    }

    #[test]
    fn c_recipes_keep_source_names_flags_and_testing_bind_order() {
        let objects = Path::new("/Cargo native output/objects");
        let production = recipe(false);
        let entry = production
            .c_compile_spec_into(CSourceUnit::Entry, objects)
            .unwrap();
        assert_eq!(entry.program, Path::new("/target tools/bin/clang"));
        assert_eq!(
            strings(&entry.arguments),
            [
                "--target=x86_64-unknown-aros",
                "-D__AROS__=1",
                "-D__AROS_VERSION__=1",
                "-DAMIGA=1",
                "-D_AMIGA=1",
                "-ffreestanding",
                "-fno-stack-protector",
                "-mno-red-zone",
                "-mcmodel=large",
                "-O2",
                "-g0",
                "-fno-ident",
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-ffile-prefix-map=/source tree=/ami-rust",
                "-I/sdk root/include/aros/stdc",
                "-I/sdk root/include",
                "-c",
                "/source tree/native/entry.c",
                "-o",
                "/Cargo native output/objects/entry.o",
            ]
        );

        let sources = [
            (CSourceUnit::Entry, "native/entry.c", "entry.o"),
            (CSourceUnit::Sdk, "native/sdk.c", "sdk.o"),
            (CSourceUnit::Layout, "native/layout.c", "layout.o"),
            (
                CSourceUnit::BindDiagnostics,
                "tests/measurement/ami_test_bind_diagnostics.c",
                "bind.o",
            ),
        ];
        for (unit, source, output) in sources {
            if unit == CSourceUnit::BindDiagnostics {
                assert!(production.c_compile_spec_into(unit, objects).is_err());
                continue;
            }
            let command = production.c_compile_spec_into(unit, objects).unwrap();
            let expected_source = OsString::from(format!("/source tree/{source}"));
            let expected_output = OsString::from(format!("/Cargo native output/objects/{output}"));
            assert_eq!(
                command.arguments[command.arguments.len() - 3],
                expected_source
            );
            assert_eq!(command.arguments.last(), Some(&expected_output));
        }

        let testing = recipe(true);
        let bind = testing
            .c_compile_spec_into(CSourceUnit::BindDiagnostics, objects)
            .unwrap();
        assert_eq!(bind.arguments[19], OsStr::new("-DAMI_SDK_TESTING=1"));
        assert_eq!(bind.arguments[20], OsStr::new("-c"));
        assert_eq!(
            bind.arguments[21],
            OsStr::new("/source tree/tests/measurement/ami_test_bind_diagnostics.c")
        );
        assert_eq!(
            bind.arguments[23],
            OsStr::new("/Cargo native output/objects/bind.o")
        );
    }

    #[test]
    fn startup_collector_and_strip_recipes_preserve_argument_order() {
        let production = recipe(false);
        let objects = Path::new("/Cargo native output/objects");
        let startup = production.startup_spec_into(objects).unwrap();
        assert_eq!(startup.program, Path::new("/target tools/bin/llvm-objcopy"));
        assert_eq!(
            strings(&startup.arguments),
            [
                "--redefine-sym",
                "__startup_entry=ami_sdk_startup_entry",
                "/sdk root/lib/startup.o",
                "/Cargo native output/objects/startup.o",
            ]
        );

        let inputs = [OsString::from("/Cargo Rust output/lib application.a")];
        let output = Path::new("/Cargo native output/AMIRUST.unstripped");
        let map = Path::new("/Cargo native output/AMIRUST.map");
        let collector = production
            .collector_spec_for_cargo(objects, &inputs, output, map)
            .unwrap();
        assert_eq!(
            collector.program,
            Path::new("/collector tools/bin/collect-aros")
        );
        assert_eq!(
            strings(&collector.arguments),
            [
                "--sysroot=/sdk root",
                "-m",
                "elf_x86_64",
                "-Map",
                "/Cargo native output/AMIRUST.map",
                "-o",
                "/Cargo native output/AMIRUST.unstripped",
                "/Cargo native output/objects/entry.o",
                "/Cargo native output/objects/startup.o",
                "/Cargo native output/objects/sdk.o",
                "/Cargo native output/objects/layout.o",
                "/Cargo Rust output/lib application.a",
                "-L/sdk root/lib",
                "--start-group",
                "-lmui",
                "-lamiga",
                "-larossupport",
                "-lstdcio",
                "-lstdc",
                "-lposixc",
                "-ldos",
                "-lexec",
                "-lautoinit",
                "-llibinit",
                "-lutility",
                "-laros",
                "-ldebug",
                "--end-group",
                "/target tools/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a",
            ]
        );

        let testing = recipe(true);
        let testing_collector = testing
            .collector_spec_for_cargo(objects, &inputs, output, map)
            .unwrap();
        assert_eq!(
            testing_collector.arguments[11],
            OsStr::new("/Cargo native output/objects/bind.o")
        );
        assert_eq!(testing_collector.arguments[12], inputs[0]);

        let input = Path::new("/Cargo native output/AMIRUST.unstripped");
        let stripped = Path::new("/Cargo native output/AMIRUST.stripped");
        let strip = production.strip_spec_for_paths(input, stripped).unwrap();
        assert_eq!(strip.program, Path::new("/target tools/bin/llvm-strip"));
        assert_eq!(
            strings(&strip.arguments),
            [
                "--strip-unneeded",
                "--keep-symbol=__startup_entry",
                "-o",
                "/Cargo native output/AMIRUST.stripped",
                "/Cargo native output/AMIRUST.unstripped",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn collector_preserves_non_utf8_link_argument_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let opaque = OsString::from_vec(vec![b'/', b'l', b'i', b'b', 0xff, b'.', b'a']);
        let command = recipe(false)
            .collector_spec_for_cargo(
                Path::new("/objects"),
                std::slice::from_ref(&opaque),
                Path::new("/output/AMIRUST.unstripped"),
                Path::new("/output/AMIRUST.map"),
            )
            .unwrap();
        assert_eq!(
            command.arguments[11].as_os_str().as_bytes(),
            opaque.as_bytes()
        );
    }

    #[test]
    fn explicit_paths_must_be_absolute_normalized_and_non_root() {
        let good_objects = Path::new("/native output/objects");
        let recipe = recipe(false);
        let input = Path::new("/native output/AMIRUST.unstripped");
        let output = Path::new("/native output/AMIRUST.stripped");
        let map = Path::new("/native output/AMIRUST.map");

        for bad in [
            Path::new("relative/objects"),
            Path::new("/"),
            Path::new("/native/../objects"),
            Path::new("/native/./objects"),
            Path::new("/native//objects"),
            Path::new("/native/objects/"),
        ] {
            assert!(recipe.startup_spec_into(bad).is_err(), "accepted {bad:?}");
            assert!(
                recipe.c_compile_spec_into(CSourceUnit::Entry, bad).is_err(),
                "accepted {bad:?}"
            );
            assert!(
                recipe
                    .collector_spec_for_cargo(bad, &[], output, map)
                    .is_err(),
                "accepted {bad:?}"
            );
            assert!(recipe.strip_spec_for_paths(bad, output).is_err());
        }

        assert!(
            recipe
                .collector_spec_for_cargo(good_objects, &[], Path::new("/"), map)
                .is_err()
        );
        assert!(
            recipe
                .collector_spec_for_cargo(good_objects, &[], input, Path::new("relative/map"))
                .is_err()
        );
        assert!(
            recipe
                .strip_spec_for_paths(input, Path::new("/native//stripped"))
                .is_err()
        );
    }
}
