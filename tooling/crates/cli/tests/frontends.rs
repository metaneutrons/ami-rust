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
    for args in [vec!["build"], vec!["--version", "extra"], vec!["unknown"]] {
        let a = run(&direct, &args);
        let mut injected = vec!["ami"];
        injected.extend(&args);
        let b = run(&plugin, &injected);
        assert_eq!(a.status.code(), Some(2));
        assert_eq!(b.status.code(), Some(2));
        assert!(a.stdout.is_empty());
        assert_eq!(a.stdout, b.stdout);
        assert_eq!(a.stderr, b.stderr);
    }
    assert!(!fixture.0.join("build.lock").exists());
}
