use std::process::ExitCode;

// Thin entry point: parse, dispatch, and turn an error into a non-zero exit.
// Errors print with their full cause chain so a failure names its own fix.
// A usage refusal made after the parse exits 2, the same code clap uses for a parse error.
fn main() -> ExitCode {
    match scratchsmith::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            if scratchsmith::cli::is_usage(&err) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
