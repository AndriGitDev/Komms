//! Command-line entry point for the least-authority OHTTP relay.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kult_ohttp_relay::{
    check_configuration, inspect_configuration, probe_health, run, Config, RelayError,
};

#[derive(Debug, Parser)]
#[command(
    name = "kult-ohttp-relay",
    about = "Bounded fixed-mapping RFC 9458 Oblivious HTTP relay"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the standalone relay.
    Run {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Print only non-secret TLS and mapping fingerprints.
    Inspect {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate configuration and credentials without opening listeners.
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

fn report(error: RelayError) -> ExitCode {
    eprintln!("OHTTP relay: {error}");
    ExitCode::FAILURE
}

fn print_info(info: &kult_ohttp_relay::RelayServiceKeyInfo) {
    println!("tls_certificate_sha256={}", info.tls_certificate_sha256);
    println!("gateway_ca_bundle_sha256={}", info.gateway_ca_bundle_sha256);
    println!("mapping_sha256={}", info.mapping_sha256);
}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse().command {
        Command::Run { config } => match Config::open(&config) {
            Ok(config) => run(config).await.map_or_else(report, |_| ExitCode::SUCCESS),
            Err(error) => report(error),
        },
        Command::Inspect { config } => {
            match Config::open(&config).and_then(|config| inspect_configuration(&config)) {
                Ok(info) => {
                    print_info(&info);
                    ExitCode::SUCCESS
                }
                Err(error) => report(error),
            }
        }
        Command::Check { config } => match check_configuration(&config) {
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
