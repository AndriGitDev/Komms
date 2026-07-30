//! Command-line entry point for the operator-minimized reference service.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kult_reference_service::{
    generate_libp2p_identity, inspect_service_keys, probe_health, run, Config, ServiceError,
};

#[derive(Debug, Parser)]
#[command(
    name = "kult-reference-service",
    about = "Bounded Komms bootstrap/DHT-cache and rendezvous service"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the two-role reference service.
    Run {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a new owner-only libp2p service identity.
    GenerateLibp2pIdentity {
        /// New output file; an existing path is never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print non-secret service fingerprints for an operator record.
    Inspect {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate configuration and key material without opening listeners.
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

fn report(error: ServiceError) -> ExitCode {
    eprintln!("reference service: {error}");
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse().command {
        Command::Run { config } => match Config::open(&config).and_then(|config| {
            inspect_service_keys(&config)?;
            Ok(config)
        }) {
            Ok(config) => run(config).await.map_or_else(report, |_| ExitCode::SUCCESS),
            Err(error) => report(error),
        },
        Command::GenerateLibp2pIdentity { output } => match generate_libp2p_identity(&output) {
            Ok(info) => {
                println!("peer_id={}", info.libp2p_peer_id);
                println!("libp2p_public_key_sha256={}", info.libp2p_public_key_sha256);
                ExitCode::SUCCESS
            }
            Err(error) => report(error),
        },
        Command::Inspect { config } => {
            match Config::open(&config).and_then(|config| inspect_service_keys(&config)) {
                Ok(info) => {
                    println!("peer_id={}", info.libp2p_peer_id);
                    println!("libp2p_public_key_sha256={}", info.libp2p_public_key_sha256);
                    println!("tls_certificate_sha256={}", info.tls_certificate_sha256);
                    println!("provider_static_key={}", info.provider_static_key);
                    ExitCode::SUCCESS
                }
                Err(error) => report(error),
            }
        }
        Command::Check { config } => {
            match Config::open(&config).and_then(|config| {
                inspect_service_keys(&config)?;
                Ok(())
            }) {
                Ok(()) => {
                    println!("configuration valid");
                    ExitCode::SUCCESS
                }
                Err(error) => report(error),
            }
        }
        Command::Probe { address } => match probe_health(address).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => report(error),
        },
    }
}
