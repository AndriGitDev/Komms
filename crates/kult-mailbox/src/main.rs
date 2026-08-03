//! Command-line entry point for the dedicated mailbox-v2 service.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kult_mailbox::{initialize, inspect, probe_health, run, Config, MailboxError};

#[derive(Debug, Parser)]
#[command(
    name = "kult-mailbox",
    about = "Bounded dedicated Komms mailbox-v2 service"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize new service-only key material and durable state.
    Initialize {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the mailbox-v2 service.
    Run {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Print non-secret service identity and schema information.
    Inspect {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate configuration without opening state or listeners.
    Check {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Query the loopback-only aggregate health endpoint.
    Probe {
        /// Loopback health listener from the service configuration.
        #[arg(long)]
        address: SocketAddr,
    },
}

fn report(error: MailboxError) -> ExitCode {
    eprintln!("mailbox service: {error}");
    ExitCode::FAILURE
}

fn print_inspection(
    result: kult_mailbox::Result<kult_mailbox::MailboxServiceInspection>,
) -> ExitCode {
    match result {
        Ok(info) => {
            println!("peer_id={}", info.peer_id);
            println!("schema_version={}", info.schema_version);
            ExitCode::SUCCESS
        }
        Err(error) => report(error),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse().command {
        Command::Initialize { config } => match Config::open(&config) {
            Ok(config) => print_inspection(initialize(&config)),
            Err(error) => report(error),
        },
        Command::Run { config } => match Config::open(&config) {
            Ok(config) => run(config).await.map_or_else(report, |_| ExitCode::SUCCESS),
            Err(error) => report(error),
        },
        Command::Inspect { config } => match Config::open(&config) {
            Ok(config) => print_inspection(inspect(&config)),
            Err(error) => report(error),
        },
        Command::Check { config } => match Config::open(&config) {
            Ok(_) => {
                println!("configuration valid");
                ExitCode::SUCCESS
            }
            Err(error) => report(error),
        },
        Command::Probe { address } => match probe_health(address).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => report(error),
        },
    }
}
