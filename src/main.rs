mod auth;
mod client;
mod config;
mod conn;
mod utils;

use std::{path::PathBuf, time::{Duration, Instant}};

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::{auth::Auth, config::Config, utils::chat::AutoResponder};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config_path: PathBuf = std::env::args().nth(1).unwrap_or_else(|| "config.toml".into()).into();
    let config = Config::load(&config_path)?;
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    if config.debug { filter = filter.add_directive("rafk=debug".parse()?) }
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut auth = Auth::new(&config.auth)?;
    let mut responder = AutoResponder::new(&config.chat.rules)?;
    let (chat_tx, mut chat_rx) = mpsc::channel(16);
    if config.stdin { spawn_stdin_reader(chat_tx.clone()) }

    tokio::select! {
        result = reconnect_loop(&config, &mut auth, &mut responder, &mut chat_rx) => result,
        _ = shutdown_signal() => {
            info!("shutting down");
            Ok(())
        }
    }
}

async fn reconnect_loop(config: &Config, auth: &mut Auth, responder: &mut AutoResponder, chat_rx: &mut mpsc::Receiver<String>) -> Result<()> {
    let reconnect = &config.reconnect;
    let mut attempt = 0;

    loop {
        let started = Instant::now();
        match client::run(config, auth, responder, chat_rx).await {
            Ok(reason) => {
                warn!(%reason, "disconnected");
                if reconnect.is_fatal(&reason) {
                    info!("kick reason matches fatal_kick_patterns, not reconnecting");
                    return Ok(());
                }
            }
            Err(err) => warn!("connection error: {err:#}"),
        }

        if started.elapsed() >= Duration::from_secs(reconnect.stable_after_secs) { attempt = 0 }
        let delay = reconnect.delay(attempt);
        attempt += 1;
        info!("reconnecting in {}s", delay.as_secs());
        tokio::time::sleep(delay).await;
    }
}

fn spawn_stdin_reader(chat_tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() { continue }
            if chat_tx.blocking_send(line.to_string()).is_err() {
                break;
            }
        }
    });
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}