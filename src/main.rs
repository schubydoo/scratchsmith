use std::process::ExitCode;

// Thin entry point: parse, dispatch, and turn an error into a non-zero exit.
// Errors print with their full cause chain so a failure names its own fix (TAD 5.4).
fn main() -> ExitCode {
    match scratchsmith::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
