use ami_rust_core::frontend;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let executable = PathBuf::from(arguments.next().unwrap_or_default());
    let args: Vec<_> = arguments.collect();
    let result = frontend::parse(&executable, &args).and_then(frontend::render);
    match result {
        Ok(output) => match io::stdout().lock().write_all(&output.stdout) {
            Ok(()) => ExitCode::from(output.exit_code),
            Err(_) => ExitCode::from(2),
        },
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "ami-rust: {error}");
            ExitCode::from(2)
        }
    }
}
