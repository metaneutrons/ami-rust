use ami_rust_core::{
    inventory::FileIdentity,
    transaction::{InstallFile, publish_install, remove_verified_installation},
};
use serde::Deserialize;
use serde_json::json;
use std::{env, fs, path::PathBuf};

#[derive(Deserialize)]
struct Plan {
    operation: String,
    prefix: PathBuf,
    bundle: Option<PathBuf>,
    receipt_path: Option<PathBuf>,
    pin: Option<PathBuf>,
    files: Option<Vec<FileSpec>>,
    inventory: Option<Vec<IdentitySpec>>,
    receipt_digest: Option<String>,
}

#[derive(Deserialize)]
struct FileSpec {
    path: String,
    source: PathBuf,
    mode: u32,
}

#[derive(Deserialize)]
struct IdentitySpec {
    path: String,
    bytes: u64,
    sha256: String,
}

pub fn main() {
    let result = run();
    let path = PathBuf::from(
        env::var_os("AMI_RUST_TRANSACTION_PLAN").expect("explicit isolated transaction plan"),
    );
    fs::write(
        path.with_extension("result.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    if result["status"] == "refusal" {
        std::process::exit(result["exit_code"].as_i64().unwrap_or(2) as i32);
    }
}

fn run() -> serde_json::Value {
    let Some(plan_path) = env::var_os("AMI_RUST_TRANSACTION_PLAN") else {
        return json!({"status":"bridge-error", "reason":"missing plan"});
    };
    let plan: Plan = match fs::read(plan_path)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other))
    {
        Ok(plan) => plan,
        Err(error) => return json!({"status":"bridge-error", "reason":error.to_string()}),
    };
    match plan.operation.as_str() {
        "publish" => publish(plan),
        "remove" => remove(plan),
        _ => json!({"status":"bridge-error", "reason":"unknown operation"}),
    }
}

fn publish(plan: Plan) -> serde_json::Value {
    let bundle = match plan.bundle.as_deref() {
        Some(bundle) => bundle,
        None => return json!({"status":"bridge-error", "reason":"missing bundle"}),
    };
    let receipt_path = match plan.receipt_path {
        Some(path) => path,
        None => return json!({"status":"bridge-error", "reason":"missing receipt"}),
    };
    let receipt = match fs::read(receipt_path) {
        Ok(bytes) => bytes,
        Err(error) => return json!({"status":"bridge-error", "reason":error.to_string()}),
    };
    let specs = plan.files.unwrap_or_default();
    let mut owned = Vec::with_capacity(specs.len());
    for spec in specs {
        match fs::read(&spec.source) {
            Ok(contents) => owned.push((spec.path, contents, spec.mode)),
            Err(error) => return json!({"status":"bridge-error", "reason":error.to_string()}),
        }
    }
    let files: Vec<_> = owned
        .iter()
        .map(|(path, contents, mode)| InstallFile {
            path,
            contents,
            mode: *mode,
        })
        .collect();
    match publish_install(&plan.prefix, bundle, plan.pin.as_deref(), &files, &receipt) {
        Ok(published) => json!({
            "status":"ok",
            "prefix":published.prefix,
            "receipt_sha256":published.receipt_sha256,
            "receipt_pin":published.receipt_pin,
        }),
        Err(failure) => json!({
            "status":"refusal",
            "exit_code":failure.exit_code(),
            "reason":failure.reason.to_string(),
            "published":failure.published.map(|published| json!({
                "prefix":published.prefix,
                "receipt_sha256":published.receipt_sha256,
                "receipt_pin":published.receipt_pin,
            })),
            "recovery":failure.recovery.map(|recovery| json!({
                "entry_name":recovery.entry_name.to_string_lossy(),
                "last_known_parent":recovery.last_known_parent,
                "verified_path":recovery.verified_path,
            })),
        }),
    }
}

fn remove(plan: Plan) -> serde_json::Value {
    let inventory: Vec<FileIdentity> = plan
        .inventory
        .unwrap_or_default()
        .into_iter()
        .map(|item| FileIdentity {
            path: item.path,
            bytes: item.bytes,
            sha256: item.sha256,
            mode: None,
        })
        .collect();
    let digest = match plan.receipt_digest {
        Some(digest) => digest,
        None => return json!({"status":"bridge-error", "reason":"missing receipt digest"}),
    };
    match remove_verified_installation(&plan.prefix, &inventory, &digest) {
        Ok(()) => json!({"status":"ok"}),
        Err(failure) => json!({
            "status":"refusal",
            "reason":failure.reason.to_string(),
            "recovery":failure.recovery.map(|recovery| json!({
                "entry_name":recovery.entry_name.to_string_lossy(),
                "last_known_parent":recovery.last_known_parent,
                "verified_path":recovery.verified_path,
            })),
        }),
    }
}
