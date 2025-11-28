use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use signal_hook::consts::signal;
use signal_hook::iterator::exfiltrator::SignalOnly;
use signal_hook::iterator::SignalsInfo;
use tokio::net::TcpListener;

use openproxy::executor::{Executor, Pool};
use openproxy::worker::{Conn, Worker};

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
    match openproxy.command {
        Some(Command::Start {
                 config,
                 enable_health_check,
             }) => start(config, enable_health_check).await?,
        _ => (),
    }
    Ok(())
}

async fn start(
    config: PathBuf,
    enable_health_check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    openproxy::load_config(&config, true).await?;
    log::info!(tls = true, debug = cfg!(debug_assertions); "start_openproxy");
    run_background(Arc::new(Executor::new(Pool::new())), enable_health_check);
    let mut signals =
        SignalsInfo::<SignalOnly>::new([signal::SIGTERM, signal::SIGINT, signal::SIGHUP])?;
    for signal in &mut signals {
        match signal {
            signal::SIGTERM | signal::SIGINT => break,
            signal::SIGHUP => openproxy::force_update_config(&config).await?,
            _ => (),
        }
    }
    log::info!(tls = true, debug = cfg!(debug_assertions); "exit_openproxy");
    Ok(())
}

fn run_background(executor: Arc<Executor<Pool<Conn>>>, enable_health_check: bool) {
    if enable_health_check {
        executor.run_health_check::<Worker<Pool<Conn>>>();
    }
    tokio::spawn(async move {
        let listener = TcpListener::bind("0.0.0.0:443").await.unwrap();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let executor = Arc::clone(&executor);
                    tokio::spawn(async move {
                        executor.execute::<Worker<Pool<Conn>>>(stream).await;
                    });
                }
                #[cfg_attr(not(debug_assertions), allow(unused))]
                Err(e) => {
                    #[cfg(debug_assertions)]
                    log::error!(error = e.to_string(); "tcp_accept_error")
                }
            }
        }
    });
}
