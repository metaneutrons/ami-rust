use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Return a unique child of the canonical system temporary directory.
///
/// Production path validation intentionally refuses symlinked ancestors. On
/// macOS, `std::env::temp_dir()` commonly spells `/private/var` as `/var`, so
/// fixtures must canonicalize the existing parent before creating their root.
pub(crate) fn temporary_root(label: &str) -> PathBuf {
    let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after Unix epoch")
        .as_nanos();
    parent.join(format!(
        "ami-rust-{label}-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
