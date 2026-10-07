//! Customs: a package firewall for AI coding agents.
//!
//! The `customs` binary is a thin wrapper over this library so integration tests can run
//! the server in-process with a stand-in scanner and a mock registry.

pub mod api;
pub mod audit;
pub mod cli;
pub mod client;
pub mod config;
pub mod engine;
pub mod history;
pub mod hook;
pub mod metrics;
pub mod policy;
pub mod proxy;
pub mod registry;
pub mod resolve;
pub mod server;
pub mod store;
pub mod util;
pub mod verdict;
