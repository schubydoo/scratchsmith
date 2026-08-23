//! Scratchsmith: pack a prebuilt dynamic Linux ELF binary into a minimal,
//! daemonless `FROM scratch` OCI image.
//!
//! Logic lives in the library so it can be unit-tested; `main.rs` is a thin shell.
//! Modules mirror the pack pipeline: resolver -> stager -> image -> registry, with
//! lint / supplychain / report as cross-cutting steps.

pub mod cli;

// Implemented pipeline stages.
pub mod config;
pub mod doctor;
pub mod image;
pub mod lint;
pub mod pack;
pub mod resolver;
pub mod stager;
pub mod supplychain;

// Stages still stubbed until their tasks land. Each file states its own scope.
pub mod registry;
pub mod report;
