//! Target linker for the pinned AROS x86-64 targets.
//!
//! Cargo runs this binary as the linker. It passes every command-line argument
//! to [`aros_native_build::link`], which runs the fixed native link recipe and
//! publishes the audited ELF. On success it exits with status 0. On refusal it
//! prints `aros-link: <message>` to standard error and exits with the refusal's
//! exit status.

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
