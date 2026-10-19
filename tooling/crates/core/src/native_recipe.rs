//! Pure descriptions of the locked native build commands.
//!
//! Callers own input identity checks, directory creation, command supervision,
//! artifact selection, section compaction, and ELF audit. Paths passed here are
//! already selected by the caller; this module does not touch the filesystem.

use crate::{Refusal, Result, process_capture::CommandSpec, records::Host};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

/// The small Cargo argument language accepted by the native build entrypoint.
///
/// The manifest path is preserved as supplied. The caller must resolve it to an
/// absolute path and perform the pinned manifest/lock identity checks before
/// constructing commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoBuildOptions {
    pub manifest_path: PathBuf,
    pub package: OsString,
    pub features: Option<OsString>,
    pub no_default_features: bool,
    /// Original Cargo arguments, including the leading build subcommand.
    pub forwarded_arguments: Vec<OsString>,
}

impl CargoBuildOptions {
    pub fn is_testing_package(&self) -> bool {
        self.package == OsStr::new("ami-rust-qualification")
            || self.package == OsStr::new("ami-rust-dependencies")
    }
}

/// Parse exactly the Cargo option subset accepted by host/build.py.
///
/// The input begins with build; the outer CLI is responsible for removing its
/// own -- separator before calling this function.
pub fn parse_cargo_options(arguments: &[OsString]) -> Result<CargoBuildOptions> {
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new("build")) {
        return Err(Refusal::new(
            "ami-rust currently supports the explicit native build recipe",
        ));
    }

    let mut values = BTreeMap::<&'static str, OsString>::new();
    let mut switches = BTreeSet::<&'static str>::new();
    let mut index = 1;
    while index < arguments.len() {
        let flag = arguments[index].as_os_str();
        let value_key = if flag == OsStr::new("--manifest-path") {
            Some("--manifest-path")
        } else if flag == OsStr::new("--package") || flag == OsStr::new("-p") {
            Some("--package")
        } else if flag == OsStr::new("--features") {
            Some("--features")
        } else {
            None
        };

        if let Some(key) = value_key {
            if values.contains_key(key) || index + 1 == arguments.len() {
                return Err(Refusal::new(format!(
                    "missing/duplicate Cargo argument: {}",
                    flag.to_string_lossy()
                )));
            }
            values.insert(key, arguments[index + 1].clone());
            index += 2;
            continue;
        }

        let switch = if flag == OsStr::new("--release") {
            Some("--release")
        } else if flag == OsStr::new("--locked") {
            Some("--locked")
        } else if flag == OsStr::new("--offline") {
            Some("--offline")
        } else if flag == OsStr::new("--no-default-features") {
            Some("--no-default-features")
        } else {
            None
        };
        if let Some(switch) = switch {
            if !switches.insert(switch) {
                return Err(Refusal::new(format!("duplicate Cargo argument: {switch}")));
            }
            index += 1;
            continue;
        }

        return Err(Refusal::new(format!(
            "unsupported or SDK-owned Cargo option: {}",
            flag.to_string_lossy()
        )));
    }

    if !["--release", "--locked", "--offline"]
        .into_iter()
        .all(|required| switches.contains(required))
        || !values.contains_key("--manifest-path")
        || !values.contains_key("--package")
    {
        return Err(Refusal::new(
            "native builds require --manifest-path, --package, --release, --locked and --offline",
        ));
    }

    Ok(CargoBuildOptions {
        manifest_path: PathBuf::from(values.remove("--manifest-path").expect("required above")),
        package: values.remove("--package").expect("required above"),
        features: values.remove("--features"),
        no_default_features: switches.contains("--no-default-features"),
        forwarded_arguments: arguments.to_vec(),
    })
}

/// Files selected by the caller after it has verified SDK and component
/// identities. The root and work paths follow the native build's private
/// output layout; the caller creates them before executing commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRecipePaths {
    pub source_root: PathBuf,
    pub output_root: PathBuf,
    pub work_dir: PathBuf,
    pub rust_root: PathBuf,
    pub cargo_program: PathBuf,
    pub toolchain_root: PathBuf,
    pub sdk_root: PathBuf,
    pub vendor_root: PathBuf,
}

/// Inputs that affect the fixed host command recipes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBuildRecipe {
    pub paths: NativeRecipePaths,
    pub host: Host,
    pub source_date_epoch: u64,
}

impl NativeBuildRecipe {
    pub fn new(paths: NativeRecipePaths, host: Host, source_date_epoch: u64) -> Self {
        Self {
            paths,
            host,
            source_date_epoch,
        }
    }

    pub fn artifact_dir(&self) -> PathBuf {
        self.paths.output_root.join("artifacts")
    }

    /// Return the exact environment used for every supervised native command.
    ///
    /// This is an allowlist environment. Registry credentials are removed by
    /// key without reading or copying their values.
    pub fn cargo_environment(
        &self,
        options: &CargoBuildOptions,
    ) -> Result<BTreeMap<OsString, OsString>> {
        let manifest_parent = absolute_manifest_parent(&options.manifest_path)?;
        let cargo_parent = self
            .paths
            .cargo_program
            .parent()
            .ok_or_else(|| Refusal::new("selected Cargo path has no parent"))?;
        let path_entries = [
            cargo_parent.to_path_buf(),
            self.paths.rust_root.join("bin"),
            self.paths.toolchain_root.join("bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ];
        let mut path = OsString::new();
        for (index, entry) in path_entries.iter().enumerate() {
            if index != 0 {
                path.push(":");
            }
            path.push(entry.as_os_str());
        }

        let mut rust_flags = vec![
            OsString::from("-Copt-level=2"),
            OsString::from("-Cpanic=abort"),
            OsString::from("-Ccodegen-units=1"),
            OsString::from("-Cembed-bitcode=no"),
            OsString::from("-Clto=off"),
        ];
        rust_flags.extend(self.remap_flags(manifest_parent));
        let mut encoded_rust_flags = OsString::new();
        for (index, flag) in rust_flags.iter().enumerate() {
            if index != 0 {
                encoded_rust_flags.push("\x1f");
            }
            encoded_rust_flags.push(flag);
        }

        let mut environment = BTreeMap::new();
        environment.insert(
            OsString::from("HOME"),
            self.paths.output_root.join("home").into_os_string(),
        );
        environment.insert(OsString::from("PATH"), path);
        environment.insert(
            OsString::from("CARGO"),
            self.paths.cargo_program.as_os_str().to_os_string(),
        );
        environment.insert(
            OsString::from("CARGO_HOME"),
            self.paths.output_root.join("cargo-home").into_os_string(),
        );
        environment.insert(
            OsString::from("RUSTC"),
            self.paths.rust_root.join("bin/rustc").into_os_string(),
        );
        environment.insert(
            OsString::from("RUSTDOC"),
            self.paths.rust_root.join("bin/rustdoc").into_os_string(),
        );
        environment.insert(OsString::from("CARGO_BUILD_JOBS"), OsString::from("2"));
        environment.insert(OsString::from("CARGO_INCREMENTAL"), OsString::from("0"));
        environment.insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
        environment.insert(
            OsString::from("CARGO_TARGET_DIR"),
            self.paths.work_dir.join("target").into_os_string(),
        );
        environment.insert(
            OsString::from("CARGO_ENCODED_RUSTFLAGS"),
            encoded_rust_flags,
        );
        environment.insert(
            OsString::from("TMPDIR"),
            self.paths.output_root.join("tmp").into_os_string(),
        );
        environment.insert(OsString::from("LC_ALL"), OsString::from("C"));
        environment.insert(OsString::from("TZ"), OsString::from("UTC"));
        environment.insert(
            OsString::from("SOURCE_DATE_EPOCH"),
            OsString::from(self.source_date_epoch.to_string()),
        );
        environment.insert(OsString::from("RUSTC_WRAPPER"), OsString::new());
        environment.insert(OsString::from("RUSTC_WORKSPACE_WRAPPER"), OsString::new());

        Ok(remove_registry_credentials(environment))
    }

    /// The caller writes these bytes to CARGO_HOME/config.toml after creating
    /// the private Cargo home. JSON string syntax is valid TOML basic-string
    /// syntax and keeps paths with spaces and quotes intact.
    pub fn cargo_config_toml(&self, options: &CargoBuildOptions) -> Result<String> {
        let manifest_parent = absolute_manifest_parent(&options.manifest_path)?;
        let vendor = path_utf8(&self.paths.vendor_root)?;
        let host = self.host.rust_host_triple();
        let host_flags = self
            .remap_flags(manifest_parent)
            .iter()
            .map(|flag| {
                flag.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Refusal::new("Cargo remap path is not valid UTF-8"))
            })
            .collect::<Result<Vec<_>>>()?;
        let vendor = serde_json::to_string(vendor)
            .map_err(|_| Refusal::new("cannot encode vendored Cargo directory"))?;
        let host_flags = serde_json::to_string(&host_flags)
            .map_err(|_| Refusal::new("cannot encode Cargo host remap flags"))?;
        Ok(format!(
            "target-applies-to-host=false\n[source.crates-io]\nreplace-with=\"vendored\"\n[source.vendored]\ndirectory={vendor}\n[build]\njobs=2\n[host.{host}]\nrustflags={host_flags}\n"
        ))
    }

    pub fn c_compile_commands(&self, options: &CargoBuildOptions) -> Result<Vec<NamedCommand>> {
        let mut units = vec![CSourceUnit::Entry, CSourceUnit::Sdk, CSourceUnit::Layout];
        if options.is_testing_package() {
            units.push(CSourceUnit::BindDiagnostics);
        }
        units
            .into_iter()
            .map(|unit| {
                Ok(NamedCommand {
                    label: unit.label(),
                    spec: self.c_compile_spec(options, unit)?,
                })
            })
            .collect()
    }

    pub fn c_compile_spec(
        &self,
        options: &CargoBuildOptions,
        unit: CSourceUnit,
    ) -> Result<CommandSpec> {
        if unit == CSourceUnit::BindDiagnostics && !options.is_testing_package() {
            return Err(Refusal::new(
                "diagnostic binding C unit is available only to testing packages",
            ));
        }

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
        if options.is_testing_package() {
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
        arguments.push(
            self.artifact_dir()
                .join(unit.output_name())
                .into_os_string(),
        );

        self.command_spec(
            options,
            self.paths.toolchain_root.join("bin/clang"),
            arguments,
        )
    }

    pub fn startup_spec(&self, options: &CargoBuildOptions) -> Result<CommandSpec> {
        self.command_spec(
            options,
            self.paths.toolchain_root.join("bin/llvm-objcopy"),
            vec![
                OsString::from("--redefine-sym"),
                OsString::from("__startup_entry=ami_sdk_startup_entry"),
                self.paths.sdk_root.join("lib/startup.o").into_os_string(),
                self.artifact_dir().join("startup.o").into_os_string(),
            ],
        )
    }

    /// Shared native collector linker arguments. The Cargo linker adapter can
    /// use this same function when it assembles the final target link recipe.
    pub fn collector_link_arguments(&self, options: &CargoBuildOptions) -> Vec<OsString> {
        let artifacts = self.artifact_dir();
        let mut arguments = vec![
            prefixed_path("--sysroot=", &self.paths.sdk_root, ""),
            OsString::from("-m"),
            OsString::from("elf_x86_64"),
            OsString::from("-Map"),
            artifacts.join("AMIRUST.map").into_os_string(),
            OsString::from("-o"),
            artifacts.join("AMIRUST.unstripped").into_os_string(),
            artifacts.join("entry.o").into_os_string(),
            artifacts.join("startup.o").into_os_string(),
            artifacts.join("sdk.o").into_os_string(),
            artifacts.join("layout.o").into_os_string(),
        ];
        if options.is_testing_package() {
            arguments.push(artifacts.join("bind.o").into_os_string());
        }
        arguments.push(artifacts.join("application.a").into_os_string());
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
        arguments
    }

    pub fn collector_spec(&self, options: &CargoBuildOptions) -> Result<CommandSpec> {
        self.command_spec(
            options,
            self.paths.output_root.join("bin/collect-aros"),
            self.collector_link_arguments(options),
        )
    }

    pub fn strip_spec(&self, options: &CargoBuildOptions) -> Result<CommandSpec> {
        let artifacts = self.artifact_dir();
        self.command_spec(
            options,
            self.paths.toolchain_root.join("bin/llvm-strip"),
            vec![
                OsString::from("--strip-unneeded"),
                OsString::from("--keep-symbol=__startup_entry"),
                OsString::from("-o"),
                artifacts.join("AMIRUST.stripped").into_os_string(),
                artifacts.join("AMIRUST.unstripped").into_os_string(),
            ],
        )
    }

    pub fn cargo_spec(&self, options: &CargoBuildOptions) -> Result<CommandSpec> {
        let mut arguments = vec![
            OsString::from("-Zhost-config"),
            OsString::from("-Ztarget-applies-to-host"),
            OsString::from("-Zami-rust-reproducible-cross"),
            OsString::from("-Zbuild-std=core,alloc"),
            OsString::from("-Zbuild-std-features=compiler-builtins-mem"),
            OsString::from("-Zjson-target-spec"),
            OsString::from("build"),
            OsString::from("--manifest-path"),
            options.manifest_path.as_os_str().to_os_string(),
            OsString::from("--package"),
            options.package.clone(),
            OsString::from("--target"),
            self.paths
                .source_root
                .join("targets/x86_64-aros.json")
                .into_os_string(),
            OsString::from("--release"),
            OsString::from("--locked"),
            OsString::from("--offline"),
            OsString::from("-j"),
            OsString::from("2"),
            OsString::from("--message-format=json-render-diagnostics"),
            OsString::from("-vv"),
        ];
        if options.no_default_features {
            arguments.push(OsString::from("--no-default-features"));
        }
        if let Some(features) = &options.features {
            arguments.push(OsString::from("--features"));
            arguments.push(features.clone());
        }
        self.command_spec(options, self.paths.cargo_program.clone(), arguments)
    }

    pub fn section_compaction_paths(&self) -> SectionCompactionPaths {
        SectionCompactionPaths {
            input: self.artifact_dir().join("AMIRUST.stripped"),
            output: self.artifact_dir().join("AMIRUST"),
            receipt: self.paths.output_root.join("metadata-compaction.json"),
        }
    }

    fn command_spec(
        &self,
        options: &CargoBuildOptions,
        program: PathBuf,
        arguments: Vec<OsString>,
    ) -> Result<CommandSpec> {
        Ok(CommandSpec::new(
            program.into_os_string(),
            arguments,
            self.paths.work_dir.clone(),
            self.cargo_environment(options)?,
        ))
    }

    fn remap_flags(&self, manifest_parent: &Path) -> Vec<OsString> {
        [
            (self.paths.source_root.as_path(), "/ami-rust"),
            (self.paths.output_root.as_path(), "/build"),
            (self.paths.vendor_root.as_path(), "/vendor"),
            (self.paths.rust_root.as_path(), "/rust-toolchain"),
            (manifest_parent, "/project"),
        ]
        .into_iter()
        .map(|(source, destination)| remap_path_flag(source, destination))
        .collect()
    }
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

    fn label(self) -> &'static str {
        match self {
            Self::Entry => "C-entry",
            Self::Sdk => "C-sdk",
            Self::Layout => "C-layout",
            Self::BindDiagnostics => "C-bind",
        }
    }
}

/// A named command ready for the caller's command supervisor.
#[derive(Debug)]
pub struct NamedCommand {
    pub label: &'static str,
    pub spec: CommandSpec,
}

/// Paths consumed and produced by the in-process section finalizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SectionCompactionPaths {
    pub input: PathBuf,
    pub output: PathBuf,
    pub receipt: PathBuf,
}

/// Remove the two registry credential keys without reading their values.
pub fn remove_registry_credentials(
    mut environment: BTreeMap<OsString, OsString>,
) -> BTreeMap<OsString, OsString> {
    environment.remove(OsStr::new("CARGO_REGISTRY_TOKEN"));
    environment.remove(OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN"));
    environment
}

fn absolute_manifest_parent(manifest: &Path) -> Result<&Path> {
    if !manifest.is_absolute() {
        return Err(Refusal::new(
            "Cargo manifest path must be resolved before recipe construction",
        ));
    }
    manifest
        .parent()
        .ok_or_else(|| Refusal::new("Cargo manifest path has no parent"))
}

fn path_utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Refusal::new("Cargo configuration path is not valid UTF-8"))
}

fn prefixed_path(prefix: &str, path: &Path, suffix: &str) -> OsString {
    let mut argument = OsString::from(prefix);
    argument.push(path.as_os_str());
    argument.push(suffix);
    argument
}

fn remap_path_flag(source: &Path, destination: &str) -> OsString {
    prefixed_path("--remap-path-prefix=", source, &format!("={destination}"))
}

impl Host {
    fn rust_host_triple(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::MacosAarch64 => "aarch64-apple-darwin",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn options(package: &str, extras: &[&str]) -> CargoBuildOptions {
        let mut values = vec![
            OsString::from("build"),
            OsString::from("--manifest-path"),
            OsString::from("/project space/Cargo.toml"),
            OsString::from("--package"),
            OsString::from(package),
            OsString::from("--release"),
            OsString::from("--locked"),
            OsString::from("--offline"),
        ];
        values.extend(extras.iter().map(OsString::from));
        parse_cargo_options(&values).unwrap()
    }

    fn recipe() -> NativeBuildRecipe {
        NativeBuildRecipe::new(
            NativeRecipePaths {
                source_root: PathBuf::from("/source tree"),
                output_root: PathBuf::from("/build output"),
                work_dir: PathBuf::from("/build output/work"),
                rust_root: PathBuf::from("/rust toolchain"),
                cargo_program: PathBuf::from("/cargo/bin/cargo"),
                toolchain_root: PathBuf::from("/target tools"),
                sdk_root: PathBuf::from("/sdk"),
                vendor_root: PathBuf::from("/vendor tree"),
            },
            Host::LinuxX86_64,
            1_791_936_000,
        )
    }

    fn strings(values: &[OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn cargo_option_parser_accepts_only_the_frozen_subset() {
        let parsed = parse_cargo_options(&args(&[
            "build",
            "--manifest-path",
            "/project/Cargo.toml",
            "-p",
            "hello-aros",
            "--release",
            "--locked",
            "--offline",
            "--features",
            "alloc,serde",
            "--no-default-features",
        ]))
        .unwrap();
        assert_eq!(parsed.manifest_path, PathBuf::from("/project/Cargo.toml"));
        assert_eq!(parsed.package, OsStr::new("hello-aros"));
        assert_eq!(parsed.features.as_deref(), Some(OsStr::new("alloc,serde")));
        assert!(parsed.no_default_features);
        assert_eq!(parsed.forwarded_arguments[0], OsStr::new("build"));
    }

    #[test]
    fn cargo_option_parser_rejects_duplicate_missing_unknown_and_sdk_owned_flags() {
        let valid_prefix = [
            "build",
            "--manifest-path",
            "/project/Cargo.toml",
            "--package",
            "hello-aros",
            "--release",
            "--locked",
            "--offline",
        ];
        let mut duplicate_alias = valid_prefix.map(OsString::from).to_vec();
        duplicate_alias.extend(args(&["-p", "other"]));
        assert!(parse_cargo_options(&duplicate_alias).is_err());

        let mut duplicate_switch = valid_prefix.map(OsString::from).to_vec();
        duplicate_switch.push(OsString::from("--offline"));
        assert!(parse_cargo_options(&duplicate_switch).is_err());

        let mut missing_value = valid_prefix.map(OsString::from).to_vec();
        missing_value.push(OsString::from("--features"));
        assert!(parse_cargo_options(&missing_value).is_err());

        let mut unknown = valid_prefix.map(OsString::from).to_vec();
        unknown.extend(args(&["--target", "x86_64-unknown-linux-gnu"]));
        assert!(parse_cargo_options(&unknown).is_err());

        let mut sdk_owned = valid_prefix.map(OsString::from).to_vec();
        sdk_owned.push(OsString::from("-Zbuild-std=core"));
        assert!(parse_cargo_options(&sdk_owned).is_err());

        assert!(parse_cargo_options(&args(&["check"])).is_err());
        assert!(
            parse_cargo_options(&args(&[
                "build",
                "--manifest-path",
                "/project/Cargo.toml",
                "--package",
                "hello-aros",
                "--locked",
                "--offline",
            ]))
            .is_err()
        );
    }

    #[test]
    fn c_compile_recipe_keeps_frozen_flags_and_testing_unit_order() {
        let recipe = recipe();
        let production = options("hello-aros", &[]);
        let entry = recipe
            .c_compile_spec(&production, CSourceUnit::Entry)
            .unwrap();
        assert_eq!(
            strings(&entry.args),
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
                "-I/sdk/include/aros/stdc",
                "-I/sdk/include",
                "-c",
                "/source tree/native/entry.c",
                "-o",
                "/build output/artifacts/entry.o",
            ]
        );
        assert_eq!(entry.program, OsStr::new("/target tools/bin/clang"));
        assert_eq!(entry.cwd, PathBuf::from("/build output/work"));

        let testing = options("ami-rust-dependencies", &[]);
        let commands = recipe.c_compile_commands(&testing).unwrap();
        assert_eq!(
            commands.iter().map(|item| item.label).collect::<Vec<_>>(),
            ["C-entry", "C-sdk", "C-layout", "C-bind"]
        );
        assert_eq!(commands[3].spec.args[19], OsStr::new("-DAMI_SDK_TESTING=1"));
        assert_eq!(
            commands[3].spec.args[21],
            OsStr::new("/source tree/tests/measurement/ami_test_bind_diagnostics.c")
        );
        assert!(
            recipe
                .c_compile_spec(&production, CSourceUnit::BindDiagnostics)
                .is_err()
        );
    }

    #[test]
    fn startup_collector_and_strip_recipes_are_exact() {
        let recipe = recipe();
        let production = options("hello-aros", &[]);
        let startup = recipe.startup_spec(&production).unwrap();
        assert_eq!(
            strings(&startup.args),
            [
                "--redefine-sym",
                "__startup_entry=ami_sdk_startup_entry",
                "/sdk/lib/startup.o",
                "/build output/artifacts/startup.o",
            ]
        );

        let collector = recipe.collector_spec(&production).unwrap();
        assert_eq!(
            collector.program,
            OsStr::new("/build output/bin/collect-aros")
        );
        assert_eq!(
            strings(&collector.args),
            [
                "--sysroot=/sdk",
                "-m",
                "elf_x86_64",
                "-Map",
                "/build output/artifacts/AMIRUST.map",
                "-o",
                "/build output/artifacts/AMIRUST.unstripped",
                "/build output/artifacts/entry.o",
                "/build output/artifacts/startup.o",
                "/build output/artifacts/sdk.o",
                "/build output/artifacts/layout.o",
                "/build output/artifacts/application.a",
                "-L/sdk/lib",
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
        let strip = recipe.strip_spec(&production).unwrap();
        assert_eq!(
            strings(&strip.args),
            [
                "--strip-unneeded",
                "--keep-symbol=__startup_entry",
                "-o",
                "/build output/artifacts/AMIRUST.stripped",
                "/build output/artifacts/AMIRUST.unstripped",
            ]
        );

        let testing = options("ami-rust-qualification", &[]);
        let link = recipe.collector_link_arguments(&testing);
        assert_eq!(link[11], OsStr::new("/build output/artifacts/bind.o"));
        assert_eq!(
            link[12],
            OsStr::new("/build output/artifacts/application.a")
        );
        assert_eq!(
            link.last().unwrap(),
            OsStr::new("/target tools/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a")
        );
    }

    #[test]
    fn cargo_recipe_and_environment_preserve_flags_remaps_and_credentials_boundary() {
        let recipe = recipe();
        let options = options(
            "hello-aros",
            &["--no-default-features", "--features", "alloc"],
        );
        let cargo = recipe.cargo_spec(&options).unwrap();
        assert_eq!(cargo.program, OsStr::new("/cargo/bin/cargo"));
        assert_eq!(
            strings(&cargo.args),
            [
                "-Zhost-config",
                "-Ztarget-applies-to-host",
                "-Zami-rust-reproducible-cross",
                "-Zbuild-std=core,alloc",
                "-Zbuild-std-features=compiler-builtins-mem",
                "-Zjson-target-spec",
                "build",
                "--manifest-path",
                "/project space/Cargo.toml",
                "--package",
                "hello-aros",
                "--target",
                "/source tree/targets/x86_64-aros.json",
                "--release",
                "--locked",
                "--offline",
                "-j",
                "2",
                "--message-format=json-render-diagnostics",
                "-vv",
                "--no-default-features",
                "--features",
                "alloc",
            ]
        );
        let environment = &cargo.env;
        assert_eq!(
            environment[OsStr::new("PATH")],
            OsStr::new("/cargo/bin:/rust toolchain/bin:/target tools/bin:/usr/bin:/bin")
        );
        assert_eq!(
            environment[OsStr::new("CARGO_ENCODED_RUSTFLAGS")],
            OsStr::new(concat!(
                "-Copt-level=2\u{1f}-Cpanic=abort\u{1f}-Ccodegen-units=1",
                "\u{1f}-Cembed-bitcode=no\u{1f}-Clto=off",
                "\u{1f}--remap-path-prefix=/source tree=/ami-rust",
                "\u{1f}--remap-path-prefix=/build output=/build",
                "\u{1f}--remap-path-prefix=/vendor tree=/vendor",
                "\u{1f}--remap-path-prefix=/rust toolchain=/rust-toolchain",
                "\u{1f}--remap-path-prefix=/project space=/project"
            ))
        );
        assert!(!environment.contains_key(OsStr::new("CARGO_REGISTRY_TOKEN")));
        assert!(!environment.contains_key(OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN")));
        assert!(
            recipe
                .cargo_config_toml(&options)
                .unwrap()
                .contains("[host.x86_64-unknown-linux-gnu]")
        );

        let mut environment = BTreeMap::new();
        environment.insert(
            OsString::from("CARGO_REGISTRY_TOKEN"),
            OsString::from("never-read"),
        );
        environment.insert(
            OsString::from("CARGO_REGISTRIES_CRATES_IO_TOKEN"),
            OsString::from("never-read"),
        );
        assert!(remove_registry_credentials(environment).is_empty());
    }

    #[test]
    fn finalization_paths_follow_the_frozen_artifact_layout() {
        let paths = recipe().section_compaction_paths();
        assert_eq!(
            paths,
            SectionCompactionPaths {
                input: PathBuf::from("/build output/artifacts/AMIRUST.stripped"),
                output: PathBuf::from("/build output/artifacts/AMIRUST"),
                receipt: PathBuf::from("/build output/metadata-compaction.json"),
            }
        );
    }
}
