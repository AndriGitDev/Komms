//! Command-line entry point for the least-authority native-wake gateway.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rand_core::OsRng;

use kult_wake::{
    check_configuration, generate_capability_key, inspect_configuration, probe_health, run, Config,
    WakeError,
};

#[derive(Debug, Parser)]
#[command(
    name = "kult-wake",
    about = "Bounded capability-gated Komms native-wake gateway"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the standalone wake gateway.
    Run {
        /// Strict versioned TOML configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate one new owner-only capability-encryption key.
    GenerateCapabilityKey {
        /// New absolute output path; an existing file is never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Non-zero versioned key id.
        #[arg(long)]
        key_id: u32,
        /// Unix activation time; defaults to the current time.
        #[arg(long)]
        activated_at: Option<u64>,
    },
    /// Print only non-secret service-key fingerprints.
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

fn report(error: WakeError) -> ExitCode {
    eprintln!("wake gateway: {error}");
    ExitCode::FAILURE
}

fn print_info(info: &kult_wake::WakeServiceKeyInfo) {
    println!("tls_certificate_sha256={}", info.tls_certificate_sha256);
    println!("active_capability_key_id={}", info.active_capability_key_id);
    for key in &info.capability_keys {
        println!("capability_key={key}");
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse().command {
        Command::Run { config } => match Config::open(&config) {
            Ok(config) => run(config).await.map_or_else(report, |_| ExitCode::SUCCESS),
            Err(error) => report(error),
        },
        Command::GenerateCapabilityKey {
            output,
            key_id,
            activated_at,
        } => {
            let activated_at = activated_at.unwrap_or_else(unix_now);
            match generate_capability_key(&output, key_id, activated_at, &mut OsRng) {
                Ok(metadata) => {
                    println!("key_id={}", metadata.key_id);
                    println!("activated_at={}", metadata.activated_at);
                    println!("fingerprint={}", hex::encode(metadata.fingerprint));
                    ExitCode::SUCCESS
                }
                Err(error) => report(error),
            }
        }
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
