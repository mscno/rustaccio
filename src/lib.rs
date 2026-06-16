#![forbid(unsafe_code)]
// Large async runtime futures push rustc's layout query depth past the default
// recursion limit on recent toolchains; raise it for the library crate.
#![recursion_limit = "256"]

pub mod acl;
pub mod api;
pub mod app;
pub mod auth;
pub mod auth_plugin;
pub mod config;
pub mod constants;
pub mod error;
pub mod events;
pub mod examples;
pub mod governance;
pub mod models;
pub mod observability;
pub mod policy;
pub mod runtime;
pub mod startup_checks;
pub mod state_coordination;
pub mod storage;
pub mod tarball_backend;
pub mod upstream;
pub mod web_ui;
