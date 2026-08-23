//! Scratchsmith: pack a prebuilt dynamic Linux ELF binary into a minimal,
//! daemonless `FROM scratch` OCI image.
//!
//! Logic lives in the library so it can be unit-tested; `main.rs` is a thin shell.
//! Modules mirror the pack pipeline: resolver -> stager -> image -> registry, with
//! lint / supplychain / report as cross-cutting steps.

pub mod cli;

// Pipeline stages, stubbed until their tasks land. Each file states its own scope.
pub mod config;
pub mod image;
pub mod lint;
pub mod registry;
pub mod report;
pub mod resolver;
pub mod stager;
pub mod supplychain;
