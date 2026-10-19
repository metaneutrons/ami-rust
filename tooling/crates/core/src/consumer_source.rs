//! Exact package-pinned source checkout using native Git and isolated config.
//! Source Python files are inert data; no source helper is imported or run.
use crate::{
    Refusal, Result, consumer_session::ConsumerSession, directory::Directory,
    package_records::NativePackagePins,
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn checkout_package_source(
    session: &mut ConsumerSession<'_>,
    pins: &NativePackagePins,
) -> Result<PathBuf> {
    if pins.repository != "metaneutrons/ami-rust"
        || !git_identity(&pins.source_commit)
        || !git_identity(&pins.source_tree)
    {
        return Err(Refusal::new("invalid pinned consumer source identity"));
    }
    session.recheck_root()?;
    let source = session.path().join("source");
    match std::fs::symlink_metadata(&source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Refusal::new("consumer source checkout must be fresh")),
    }
    let git = Path::new("/usr/bin/git");
    let init = vec![
        "-c".into(),
        "init.defaultBranch=main".into(),
        "-c".into(),
        "core.hooksPath=/dev/null".into(),
        "init".into(),
        "--template=".into(),
        source.clone().into_os_string(),
    ];
    session.run("source-init", git, init, Duration::from_secs(30))?;
    let mut fetch = git_args(&source);
    fetch.extend([
        "fetch".into(),
        "--depth=1".into(),
        "--no-tags".into(),
        "https://github.com/metaneutrons/ami-rust.git".into(),
        pins.source_commit.clone().into(),
    ]);
    session.run("source-fetch", git, fetch, Duration::from_secs(300))?;
    let mut checkout = git_args(&source);
    checkout.extend([
        "checkout".into(),
        "--detach".into(),
        pins.source_commit.clone().into(),
    ]);
    session.run("source-checkout", git, checkout, Duration::from_secs(60))?;
    for (expression, expected, label) in [
        ("HEAD", pins.source_commit.as_str(), "source-commit"),
        ("HEAD^{tree}", pins.source_tree.as_str(), "source-tree"),
    ] {
        let mut args = git_args(&source);
        args.extend(["rev-parse".into(), "--verify".into(), expression.into()]);
        let actual = session.run(label, git, args, Duration::from_secs(30))?;
        if actual.stdout != format!("{expected}\n").as_bytes() {
            return Err(Refusal::new(
                "consumer source differs from package-pinned Git identity",
            ));
        }
    }
    Directory::open(&source)?;
    session.recheck_root()?;
    Ok(source)
}

fn git_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git_args(source: &Path) -> Vec<OsString> {
    vec![
        "-C".into(),
        source.as_os_str().into(),
        "-c".into(),
        "core.hooksPath=/dev/null".into(),
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        "submodule.recurse=false".into(),
        "-c".into(),
        "protocol.file.allow=never".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_git_identity_and_disabled_optional_execution_are_explicit() {
        assert!(git_identity(&"a".repeat(40)));
        assert!(!git_identity("main"));
        assert!(!git_identity(&"a".repeat(39)));
        assert!(!git_identity(&"A".repeat(40)));
        let args = git_args(Path::new("/tmp/source with spaces"));
        assert!(args.contains(&OsString::from("core.hooksPath=/dev/null")));
        assert!(args.contains(&OsString::from("core.fsmonitor=false")));
        assert!(args.contains(&OsString::from("submodule.recurse=false")));
    }
}
