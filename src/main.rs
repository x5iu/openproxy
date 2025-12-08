use std::path::PathBuf;

use clap::{Parser, Subcommand};
use signal_hook::consts::signal;
use signal_hook::iterator::exfiltrator::SignalOnly;
use signal_hook::iterator::SignalsInfo;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct OpenProxy {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server
    Start {
        /// Path to the config file
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,

        /// Enable provider health check
        #[arg(long = "enable-health-check")]
        enable_health_check: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let openproxy = OpenProxy::parse();
    if let Some(Command::Start {
        config,
        enable_health_check,
    }) = openproxy.command
    {
        start(config, enable_health_check).await?
    }
    Ok(())
}

async fn start(
    config: PathBuf,
    enable_health_check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    openproxy::load_config(&config, true).await?;
    openproxy::serve(enable_health_check)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    let mut signals =
        SignalsInfo::<SignalOnly>::new([signal::SIGTERM, signal::SIGINT, signal::SIGHUP])?;
    for signal in &mut signals {
        match signal {
            signal::SIGTERM | signal::SIGINT => break,
            signal::SIGHUP => openproxy::force_update_config(&config).await?,
            _ => (),
        }
    }
    log::info!("exit_openproxy");
    Ok(())
}
