//! The Komms headless daemon binary. `kultd --help` for usage.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use kultd::{read_secret_file, AuthorityStartup, Daemon, DaemonConfig};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler failed; waiting for Ctrl+C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// A secret-file path taken from the environment. Treated exactly like the
/// corresponding command-line flag, including the permissions check.
fn secret_path_env(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

const USAGE: &str = "\
kultd — Komms headless daemon

USAGE:
    kultd --data-dir DIR [OPTIONS]

The store passphrase comes from --passphrase-file, the KULTD_PASSPHRASE_FILE
environment variable, or the KULTD_PASSPHRASE environment variable, in that
order (a trailing newline is trimmed). Secret files must not be group- or
world-accessible (chmod 600); this also makes systemd LoadCredential= work
naturally (KULTD_PASSPHRASE_FILE=%d/passphrase). Prefer the *_FILE forms:
plain environment variables are visible in /proc/<pid>/environ and to
process inspection tools on some systems.

OPTIONS:
    --data-dir DIR          node.db and the default socket live here (required)
    --socket PATH           RPC socket path        [default: DATA_DIR/kultd.sock]
    --passphrase-file PATH  read the store passphrase from this file
    --listen MULTIADDR      listen address, repeatable
                            [default: /ip4/0.0.0.0/udp/0/quic-v1 and /ip4/0.0.0.0/tcp/0]
    --bootstrap MULTIADDR   DHT bootstrap peer (with /p2p/…), repeatable
    --relay MULTIADDR       relay for circuit reservation when NAT-ed
                            [default: first bootstrap peer]
    --mailbox MULTIADDR     mailbox relay to check in with, repeatable
    --serve-mailbox         volunteer bounded mailbox service for others
    --no-mdns               do not announce/discover peers on the local network
    --spool DIR             also receive sneakernet bundles from this directory
    --meshtastic-serial DEV attach a Meshtastic radio on this USB-serial port
                            (/dev/ttyUSB0, /dev/ttyACM0, …) as an off-grid carrier
    --meshtastic-tcp ADDR   attach a Meshtastic radio via its network API (host:4403)
    --no-bridge             with a radio attached, do NOT bridge third-party sealed
                            traffic between mesh and internet (bridging is otherwise
                            on whenever a radio is configured)
    --restore FILE          first run only: restore the store from this encrypted
                            root-free backup; also requires the separately held
                            offline recovery authority and both mnemonics. The
                            backup mnemonic comes from --restore-mnemonic-file,
                            the
                            KULTD_RESTORE_MNEMONIC_FILE environment variable,
                            or the KULTD_RESTORE_MNEMONIC environment variable,
                            in that order. Refused if node.db already exists.
    --restore-mnemonic-file PATH
                            read the backup's 24-word mnemonic from this file
    --recovery-authority FILE
                            encrypted offline account-authority package
    --recovery-authority-mnemonic-file PATH
                            read its separate 24-word mnemonic from this file
    --prepare-authority-migration FILE
                            one-shot: write the offline authority for an
                            undistributed single-device Alpha root and exit
    --prepare-authority-reset FILE
                            one-shot: write a fresh-identity offline authority,
                            show the new address, and exit
    --migrate-authority FILE
                            complete a prepared in-place authority migration
                            before starting network service
    --reset-authority FILE  complete a confirmed copied-root new-identity reset
                            before starting network service
    --authority-mnemonic-file PATH
                            read the confirmed phrase for --migrate-authority
                            or --reset-authority
    --kdf desktop|mobile    Argon2id profile for store creation [default: desktop]
    --tick-secs N           delivery-engine heartbeat [default: 0.5s granularity]
    --checkin-secs N        mailbox check-in cadence  [default: 300]
    -h, --help              this text

Runtime diagnostics go to stderr and are controlled by RUST_LOG
[default: info], e.g. RUST_LOG=kultd=debug,kult_transport=debug. Logs never
contain message content, keys, or contact identities.
";

enum StartupAction {
    Run(Box<DaemonConfig>),
    PrepareMigration {
        db_path: PathBuf,
        passphrase: Zeroizing<Vec<u8>>,
        destination: PathBuf,
    },
    PrepareReset {
        db_path: PathBuf,
        passphrase: Zeroizing<Vec<u8>>,
        destination: PathBuf,
    },
}

fn parse_args() -> Result<StartupAction, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut socket: Option<PathBuf> = None;
    let mut passphrase_file: Option<PathBuf> = None;
    let mut listen: Vec<String> = Vec::new();
    let mut bootstrap: Vec<String> = Vec::new();
    let mut relay: Option<String> = None;
    let mut mailboxes: Vec<String> = Vec::new();
    let mut serve_mailbox = false;
    let mut mdns = true;
    let mut spool: Option<PathBuf> = None;
    let mut meshtastic_serial: Option<String> = None;
    let mut meshtastic_tcp: Option<String> = None;
    let mut bridge = true;
    let mut restore: Option<PathBuf> = None;
    let mut restore_mnemonic_file: Option<PathBuf> = None;
    let mut recovery_authority: Option<PathBuf> = None;
    let mut recovery_authority_mnemonic_file: Option<PathBuf> = None;
    let mut prepare_authority_migration: Option<PathBuf> = None;
    let mut prepare_authority_reset: Option<PathBuf> = None;
    let mut migrate_authority: Option<PathBuf> = None;
    let mut reset_authority: Option<PathBuf> = None;
    let mut authority_mnemonic_file: Option<PathBuf> = None;
    let mut kdf = kult_crypto::KDF_PROFILE_DESKTOP;
    let mut tick_secs: Option<u64> = None;
    let mut checkin_secs: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> Result<String, String> {
            args.next().ok_or(format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--data-dir" => data_dir = Some(value("--data-dir")?.into()),
            "--socket" => socket = Some(value("--socket")?.into()),
            "--passphrase-file" => passphrase_file = Some(value("--passphrase-file")?.into()),
            "--listen" => listen.push(value("--listen")?),
            "--bootstrap" => bootstrap.push(value("--bootstrap")?),
            "--relay" => relay = Some(value("--relay")?),
            "--mailbox" => mailboxes.push(value("--mailbox")?),
            "--serve-mailbox" => serve_mailbox = true,
            "--no-mdns" => mdns = false,
            "--spool" => spool = Some(value("--spool")?.into()),
            "--meshtastic-serial" => meshtastic_serial = Some(value("--meshtastic-serial")?),
            "--meshtastic-tcp" => meshtastic_tcp = Some(value("--meshtastic-tcp")?),
            "--no-bridge" => bridge = false,
            "--restore" => restore = Some(value("--restore")?.into()),
            "--restore-mnemonic-file" => {
                restore_mnemonic_file = Some(value("--restore-mnemonic-file")?.into())
            }
            "--recovery-authority" => {
                recovery_authority = Some(value("--recovery-authority")?.into())
            }
            "--recovery-authority-mnemonic-file" => {
                recovery_authority_mnemonic_file =
                    Some(value("--recovery-authority-mnemonic-file")?.into())
            }
            "--prepare-authority-migration" => {
                prepare_authority_migration = Some(value("--prepare-authority-migration")?.into())
            }
            "--prepare-authority-reset" => {
                prepare_authority_reset = Some(value("--prepare-authority-reset")?.into())
            }
            "--migrate-authority" => migrate_authority = Some(value("--migrate-authority")?.into()),
            "--reset-authority" => reset_authority = Some(value("--reset-authority")?.into()),
            "--authority-mnemonic-file" => {
                authority_mnemonic_file = Some(value("--authority-mnemonic-file")?.into())
            }
            "--kdf" => {
                kdf = match value("--kdf")?.as_str() {
                    "desktop" => kult_crypto::KDF_PROFILE_DESKTOP,
                    "mobile" => kult_crypto::KDF_PROFILE_MOBILE,
                    other => return Err(format!("unknown KDF profile: {other}")),
                }
            }
            "--tick-secs" => {
                tick_secs = Some(
                    value("--tick-secs")?
                        .parse()
                        .map_err(|_| "bad --tick-secs")?,
                )
            }
            "--checkin-secs" => {
                checkin_secs = Some(
                    value("--checkin-secs")?
                        .parse()
                        .map_err(|_| "bad --checkin-secs")?,
                )
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let data_dir = data_dir.ok_or("--data-dir is required")?;
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("cannot create data dir: {e}"))?;

    let passphrase_file = passphrase_file.or_else(|| secret_path_env("KULTD_PASSPHRASE_FILE"));
    let passphrase = match passphrase_file {
        Some(path) => {
            let mut raw = read_secret_file(&path, "passphrase file")?;
            while raw.last() == Some(&b'\n') || raw.last() == Some(&b'\r') {
                raw.pop();
            }
            Zeroizing::new(raw)
        }
        None => Zeroizing::new(
            std::env::var("KULTD_PASSPHRASE")
                .map_err(|_| {
                    "no passphrase: set --passphrase-file, KULTD_PASSPHRASE_FILE, \
                     or KULTD_PASSPHRASE"
                })?
                .into_bytes(),
        ),
    };
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".to_owned());
    }

    let authority_mode_count = [
        prepare_authority_migration.is_some(),
        prepare_authority_reset.is_some(),
        migrate_authority.is_some(),
        reset_authority.is_some(),
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count();
    if authority_mode_count > 1 {
        return Err("choose exactly one authority migration/reset mode".to_owned());
    }
    if authority_mode_count > 0
        && (restore.is_some()
            || restore_mnemonic_file.is_some()
            || recovery_authority.is_some()
            || recovery_authority_mnemonic_file.is_some())
    {
        return Err(
            "authority migration/reset and backup restore are mutually exclusive".to_owned(),
        );
    }
    if let Some(destination) = prepare_authority_migration {
        if authority_mnemonic_file.is_some() {
            return Err("--authority-mnemonic-file is only for completing an upgrade".to_owned());
        }
        return Ok(StartupAction::PrepareMigration {
            db_path: data_dir.join("node.db"),
            passphrase,
            destination,
        });
    }
    if let Some(destination) = prepare_authority_reset {
        if authority_mnemonic_file.is_some() {
            return Err("--authority-mnemonic-file is only for completing an upgrade".to_owned());
        }
        return Ok(StartupAction::PrepareReset {
            db_path: data_dir.join("node.db"),
            passphrase,
            destination,
        });
    }

    let restore_mnemonic = if restore.is_some() {
        let restore_mnemonic_file =
            restore_mnemonic_file.or_else(|| secret_path_env("KULTD_RESTORE_MNEMONIC_FILE"));
        let phrase = match restore_mnemonic_file {
            Some(path) => {
                let raw = read_secret_file(&path, "restore mnemonic file")?;
                Zeroizing::new(
                    String::from_utf8(raw)
                        .map_err(|_| "restore mnemonic file: not valid UTF-8".to_owned())?,
                )
            }
            None => Zeroizing::new(std::env::var("KULTD_RESTORE_MNEMONIC").map_err(|_| {
                "restore needs its mnemonic: set --restore-mnemonic-file, \
                 KULTD_RESTORE_MNEMONIC_FILE, or KULTD_RESTORE_MNEMONIC"
            })?),
        };
        Some(Zeroizing::new(phrase.trim().to_owned()))
    } else {
        None
    };
    let recovery_authority_mnemonic = if restore.is_some() {
        let path = recovery_authority_mnemonic_file
            .or_else(|| secret_path_env("KULTD_RECOVERY_AUTHORITY_MNEMONIC_FILE"));
        let phrase =
            match path {
                Some(path) => {
                    let raw = read_secret_file(&path, "recovery authority mnemonic file")?;
                    Zeroizing::new(String::from_utf8(raw).map_err(|_| {
                        "recovery authority mnemonic file: not valid UTF-8".to_owned()
                    })?)
                }
                None => Zeroizing::new(
                    std::env::var("KULTD_RECOVERY_AUTHORITY_MNEMONIC").map_err(|_| {
                        "restore needs the recovery authority mnemonic: set \
                     --recovery-authority-mnemonic-file, \
                     KULTD_RECOVERY_AUTHORITY_MNEMONIC_FILE, or \
                     KULTD_RECOVERY_AUTHORITY_MNEMONIC"
                    })?,
                ),
            };
        Some(Zeroizing::new(phrase.trim().to_owned()))
    } else {
        if recovery_authority.is_some() || recovery_authority_mnemonic_file.is_some() {
            return Err("--recovery-authority is valid only with --restore".to_owned());
        }
        None
    };
    if restore.is_some() && recovery_authority.is_none() {
        return Err("restore needs --recovery-authority FILE".to_owned());
    }

    let authority_mnemonic = if migrate_authority.is_some() || reset_authority.is_some() {
        let path =
            authority_mnemonic_file.or_else(|| secret_path_env("KULTD_AUTHORITY_MNEMONIC_FILE"));
        let phrase = match path {
            Some(path) => {
                let raw = read_secret_file(&path, "authority mnemonic file")?;
                Zeroizing::new(
                    String::from_utf8(raw)
                        .map_err(|_| "authority mnemonic file: not valid UTF-8".to_owned())?,
                )
            }
            None => Zeroizing::new(std::env::var("KULTD_AUTHORITY_MNEMONIC").map_err(|_| {
                "authority upgrade needs its confirmed phrase: set \
                 --authority-mnemonic-file, KULTD_AUTHORITY_MNEMONIC_FILE, or \
                 KULTD_AUTHORITY_MNEMONIC"
            })?),
        };
        Some(Zeroizing::new(phrase.trim().to_owned()))
    } else {
        if authority_mnemonic_file.is_some() {
            return Err(
                "--authority-mnemonic-file requires --migrate-authority or --reset-authority"
                    .to_owned(),
            );
        }
        None
    };

    let mut cfg = DaemonConfig::new(&data_dir, passphrase);
    cfg.kdf = kdf;
    cfg.restore_from = restore;
    cfg.restore_mnemonic = restore_mnemonic;
    cfg.recovery_authority_from = recovery_authority;
    cfg.recovery_authority_mnemonic = recovery_authority_mnemonic;
    cfg.authority_startup = match (migrate_authority, reset_authority, authority_mnemonic) {
        (Some(package), None, Some(mnemonic)) => {
            Some(AuthorityStartup::Migrate { package, mnemonic })
        }
        (None, Some(package), Some(mnemonic)) => {
            Some(AuthorityStartup::Reset { package, mnemonic })
        }
        (None, None, None) => None,
        _ => return Err("invalid authority startup selection".to_owned()),
    };
    if let Some(socket) = socket {
        cfg.socket_path = socket;
    }
    if !listen.is_empty() {
        cfg.listen = listen;
    }
    cfg.bootstrap = bootstrap;
    cfg.relay = relay;
    cfg.mailboxes = mailboxes;
    cfg.serve_mailbox = serve_mailbox;
    cfg.mdns = mdns;
    cfg.spool = spool;
    cfg.meshtastic_serial = meshtastic_serial;
    cfg.meshtastic_tcp = meshtastic_tcp;
    cfg.bridge = bridge;
    if let Some(secs) = tick_secs {
        cfg.tick_interval = Duration::from_secs(secs.max(1));
    }
    if let Some(secs) = checkin_secs {
        cfg.checkin_interval = Duration::from_secs(secs.max(1));
    }
    Ok(StartupAction::Run(Box::new(cfg)))
}

#[tokio::main]
async fn main() -> ExitCode {
    let action = match parse_args() {
        Ok(action) => action,
        Err(message) => {
            eprintln!("kultd: {message}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = match action {
        StartupAction::Run(cfg) => *cfg,
        StartupAction::PrepareMigration {
            db_path,
            passphrase,
            destination,
        } => match kult_node::Node::prepare_authority_migration(
            &db_path,
            &passphrase,
            &destination,
            &mut OsRng,
        ) {
            Ok(mnemonic) => {
                println!("Offline authority written to {}", destination.display());
                println!("Recovery mnemonic (shown once): {}", mnemonic.as_str());
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("kultd: authority migration preparation failed: {error}");
                return ExitCode::FAILURE;
            }
        },
        StartupAction::PrepareReset {
            db_path,
            passphrase,
            destination,
        } => match kult_node::Node::prepare_authority_reset(
            &db_path,
            &passphrase,
            &destination,
            &mut OsRng,
        ) {
            Ok(prepared) => {
                println!("Offline authority written to {}", destination.display());
                println!("New account address: {}", prepared.new_address);
                println!(
                    "Recovery mnemonic (shown once): {}",
                    prepared.mnemonic.as_str()
                );
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("kultd: authority reset preparation failed: {error}");
                return ExitCode::FAILURE;
            }
        },
    };

    // Logging policy (docs/09-implementation-guide.md): events describe only
    // what an on-path observer or the operator already knows — never message
    // content, keys, passphrases, contact addresses, or store data.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let daemon = match Daemon::start(cfg).await {
        Ok(daemon) => daemon,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(address = %daemon.address, "kultd running");
    tracing::info!(socket = %daemon.socket_path.display(), "rpc socket bound");
    for addr in daemon.net.listen_addrs() {
        tracing::info!(%addr, "listening");
    }

    shutdown_signal().await;
    tracing::info!("shutting down");
    daemon.shutdown().await;
    ExitCode::SUCCESS
}
