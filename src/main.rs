use std::path::PathBuf;

use clap::{Parser, Subcommand};
use signal_hook::consts::signal;
use signal_hook::iterator::exfiltrator::SignalOnly;
use signal_hook::iterator::SignalsInfo;

const LONG_ABOUT: &str = "\
OpenProxy is a high-performance LLM (Large Language Model) proxy server written \
in Rust, designed to intelligently route requests between multiple LLM providers.

FEATURES:
  • Multi-Provider Support - Route requests to OpenAI, Gemini, and Anthropic APIs
  • Weighted Load Balancing - Distribute traffic across providers based on weights
  • Health Monitoring - Automatic health checks with failure recovery
  • Connection Pooling - Efficient connection reuse for minimal latency
  • Protocol Support - Full HTTP/1.1 and HTTP/2 with automatic negotiation
  • WebSocket Support - Transparent proxying including OpenAI Realtime API
  • OAuth Support - Dynamic auth with shell command execution for tokens
  • Hot Reload - Update configuration via SIGHUP without restart

ROUTING:
  Requests are routed based on the 'Host' header. Configure each provider with
  a unique host name, and clients specify which provider to use via this header.

SIGNALS:
  SIGTERM/SIGINT  Graceful shutdown
  SIGHUP          Reload configuration without restart

For more information, visit: https://github.com/x5iu/openproxy";

#[derive(Parser)]
#[command(
    name = "openproxy",
    version,
    about = "A high-performance LLM proxy server for OpenAI, Gemini, and Anthropic",
    long_about = LONG_ABOUT,
    after_help = "Use 'openproxy <command> --help' for more information about a command."
)]
struct OpenProxy {
    #[command(subcommand)]
    command: Option<Command>,
}

const START_LONG_ABOUT: &str = "\
Start the OpenProxy server with the specified configuration file.

The server will listen on the ports configured in the YAML config file:
  • https_port - HTTPS with TLS (requires cert_file and private_key_file)
  • http_port  - Plain HTTP without TLS (HTTP/1.1 only)

At least one port must be configured. Both can be enabled simultaneously.

EXAMPLES:
  openproxy start -c config.yml
  openproxy start -c config.yml --enable-health-check

NOTE: HTTP or HTTPS mode is determined by the config file, not command-line args.
  • Set 'https_port' in config for HTTPS (requires cert_file and private_key_file)
  • Set 'http_port' in config for plain HTTP (no TLS certificates needed)

CONFIG FILE FORMAT:
  The configuration file uses YAML format. Required fields:
    • providers[]  - List of LLM provider configurations
    • https_port or http_port - At least one port must be specified

  For HTTPS, also required:
    • cert_file         - Path to TLS certificate (PEM format)
    • private_key_file  - Path to TLS private key (PEM format)

  See the project README for full configuration documentation.";

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server
    #[command(long_about = START_LONG_ABOUT)]
    Start {
        /// Path to the YAML configuration file
        ///
        /// The config file defines provider endpoints, authentication keys,
        /// TLS certificates, ports, and health check settings.
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,

        /// Enable automatic health checks for providers
        ///
        /// When enabled, the proxy periodically checks each provider's health
        /// endpoint and excludes unhealthy providers from load balancing.
        /// The check interval is configured via 'health_check_interval' in
        /// the config file (default: 60 seconds).
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
