use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ami-rust-frontends-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn real_frontend_copies_and_cargo_plugin_have_identical_version_and_refusals() {
    let fixture = Fixture::new();
    let direct = fixture.0.join("ami-rust");
    let plugin = fixture.0.join("cargo-ami");
    for path in [&direct, &plugin] {
        fs::copy(env!("CARGO_BIN_EXE_ami-rust"), path).unwrap();
    }
    assert_eq!(fs::read(&direct).unwrap(), fs::read(&plugin).unwrap());
    let run = |binary: &std::path::Path, args: &[&str]| {
        Command::new(binary)
            .args(args)
            .current_dir(&fixture.0)
            .env_clear()
            .env("HOME", &fixture.0)
            .env("CARGO_HOME", fixture.0.join("cargo-home"))
            .env("PATH", format!("{}:/usr/bin:/bin", fixture.0.display()))
            .env("LC_ALL", "C")
            .output()
            .unwrap()
    };
    let reference = run(&direct, &["--version"]);
    assert!(reference.status.success());
    assert!(reference.stderr.is_empty());
    let version: serde_json::Value = serde_json::from_slice(&reference.stdout).unwrap();
    assert_eq!(version.as_object().unwrap().len(), 4);
    assert_eq!(version["schema"], "ami-rust-version-v1");
    assert_eq!(version["cli_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(version["sdk_version"], "0.1.0");
    assert_eq!(version["packaging_revision"], 0);
    assert_eq!(reference.stdout.last(), Some(&b'\n'));
    for (binary, args) in [
        (&plugin, vec!["--version"]),
        (&plugin, vec!["ami", "--version"]),
        (&PathBuf::from(env!("CARGO")), vec!["ami", "--version"]),
    ] {
        let output = run(binary, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, reference.stdout);
        assert!(output.stderr.is_empty());
    }
    let help = run(&direct, &["--help"]);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("ami-rust verify --bundle PATH --policy EXTERNAL_POLICY")
    );
    for (binary, args) in [
        (&plugin, vec!["--help"]),
        (&plugin, vec!["ami", "--help"]),
        (&PathBuf::from(env!("CARGO")), vec!["ami", "--help"]),
    ] {
        let output = run(binary, &args);
        assert!(output.status.success());
        assert_eq!(output.stdout, help.stdout);
        assert!(output.stderr.is_empty());
    }
    for args in [vec!["build"], vec!["--version", "extra"], vec!["unknown"]] {
        let a = run(&direct, &args);
        let mut injected = vec!["ami"];
        injected.extend(&args);
        let b = run(&plugin, &injected);
        let through_cargo = run(&PathBuf::from(env!("CARGO")), &injected);
        assert_eq!(a.status.code(), Some(2));
        assert_eq!(b.status.code(), Some(2));
        assert_eq!(through_cargo.status.code(), Some(2));
        assert!(a.stdout.is_empty());
        assert_eq!(a.stdout, b.stdout);
        assert_eq!(a.stderr, b.stderr);
        assert_eq!(a.stdout, through_cargo.stdout);
        assert_eq!(a.stderr, through_cargo.stderr);
    }

    let malformed = [
        vec!["verify"],
        vec!["verify", "--bundle"],
        vec!["verify", "--bundle", "bundle"],
        vec![
            "verify", "--bundle", "bundle", "--bundle", "other", "--policy", "policy",
        ],
        vec![
            "verify", "--bundle", "bundle", "--policy", "policy", "--policy", "other",
        ],
        vec!["verify", "--bundle", "--policy", "policy"],
        vec!["verify", "--unknown", "value"],
        vec!["verify", "--sdk-lock", "lock.json"],
    ];
    for args in malformed {
        let direct_output = run(&direct, &args);
        let mut plugin_args = vec!["ami"];
        plugin_args.extend(args.iter().copied());
        let plugin_output = run(&plugin, &plugin_args);
        let cargo_output = run(&PathBuf::from(env!("CARGO")), &plugin_args);
        for output in [&direct_output, &plugin_output, &cargo_output] {
            assert_eq!(output.status.code(), Some(2), "args={args:?}");
            assert!(output.stdout.is_empty(), "args={args:?}");
        }
        assert_eq!(direct_output.stdout, plugin_output.stdout);
        assert_eq!(direct_output.stderr, plugin_output.stderr);
        assert_eq!(direct_output.stdout, cargo_output.stdout);
        assert_eq!(direct_output.stderr, cargo_output.stderr);
    }

    // Both option orders reach the real verifier with canonical paths. The
    // deliberately malformed external policy refuses before any verifier is
    // launched; this exercises command dispatch without simulating signature
    // success.
    let bundle_dir = fixture.0.join("empty-release-bundle");
    fs::create_dir(&bundle_dir).unwrap();
    let policy_path = fixture.0.join("malformed-policy.json");
    fs::write(&policy_path, b"{}\n").unwrap();
    let bundle_arg = bundle_dir.to_str().unwrap();
    let policy_arg = policy_path.to_str().unwrap();
    for args in [
        vec!["verify", "--bundle", bundle_arg, "--policy", policy_arg],
        vec!["verify", "--policy", policy_arg, "--bundle", bundle_arg],
    ] {
        let direct_output = run(&direct, &args);
        let mut plugin_args = vec!["ami"];
        plugin_args.extend(args.iter().copied());
        let plugin_output = run(&plugin, &plugin_args);
        let cargo_output = run(&PathBuf::from(env!("CARGO")), &plugin_args);
        for output in [&direct_output, &plugin_output, &cargo_output] {
            assert_eq!(output.status.code(), Some(2), "args={args:?}");
            assert!(output.stdout.is_empty(), "args={args:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("publisher policy"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(direct_output.stderr, plugin_output.stderr);
        assert_eq!(direct_output.stderr, cargo_output.stderr);
    }
    assert!(!fixture.0.join("build.lock").exists());
}
