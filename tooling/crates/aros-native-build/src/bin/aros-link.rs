fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match aros_native_build::link(&arguments) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aros-link: {error}");
            std::process::ExitCode::from(error.exit_code())
        }
    }
}
