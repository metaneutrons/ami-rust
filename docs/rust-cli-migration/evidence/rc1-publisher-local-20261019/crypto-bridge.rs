use ami_rust_core::publisher::{inspect_legacy_publisher_bundle, verify_publisher_bundle};
use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        eprintln!("expected explicit schema flavor, bundle, external policy");
        return ExitCode::from(2);
    }
    let result = match args[0].to_str() {
        Some("legacy-inspection") => inspect_legacy_publisher_bundle(Path::new(&args[1]), Path::new(&args[2]), || false)
            .map(|inspection| serde_json::to_string(&inspection).expect("serialize inspection")),
        Some("native") => verify_publisher_bundle(Path::new(&args[1]), Path::new(&args[2]), || false)
            .map(|verified| serde_json::to_string(verified.authentication()).expect("serialize native report")),
        _ => return ExitCode::from(2),
    };
    match result {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
