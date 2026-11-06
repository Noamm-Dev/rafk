use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use tokio::{net::TcpStream, sync::mpsc, time::{self, timeout, MissedTickBehavior}};
use tracing::{debug, info, warn};

use crate::{
    auth::Auth,
    config::Config,
    conn::Connection,
    utils::{
        chat::{self, AutoResponder},
        codec::{Reader, Writer},
    },
};

const PROTOCOL_VERSION: i32 = 47; // Minecraft 1.8.9
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(50);
const MAX_CHAT_LEN: usize = 100;
const LIMBO_MESSAGES: [&str; 2] = [
    "You were spawned in Limbo.",
    "You are AFK. Move around to return from AFK.",
];

mod login {
    pub const DISCONNECT: i32 = 0x00;
    pub const ENCRYPTION_REQUEST: i32 = 0x01;
    pub const SUCCESS: i32 = 0x02;
    pub const SET_COMPRESSION: i32 = 0x03;
    pub const ALL: &[i32] = &[DISCONNECT, ENCRYPTION_REQUEST, SUCCESS, SET_COMPRESSION];

    pub const START: i32 = 0x00;
    pub const ENCRYPTION_RESPONSE: i32 = 0x01;
}

mod clientbound {
    pub const KEEP_ALIVE: i32 = 0x00;
    pub const JOIN_GAME: i32 = 0x01;
    pub const CHAT: i32 = 0x02;
    pub const RESPAWN: i32 = 0x07;
    pub const POSITION_LOOK: i32 = 0x08;
    pub const CONFIRM_TRANSACTION: i32 = 0x32;
    pub const DISCONNECT: i32 = 0x40;
    pub const SET_COMPRESSION: i32 = 0x46;
    pub const ALL: &[i32] = &[
        KEEP_ALIVE,
        JOIN_GAME,
        CHAT,
        RESPAWN,
        POSITION_LOOK,
        CONFIRM_TRANSACTION,
        DISCONNECT,
        SET_COMPRESSION,
    ];
}

mod serverbound {
    pub const HANDSHAKE: i32 = 0x00;
    pub const KEEP_ALIVE: i32 = 0x00;
    pub const CHAT: i32 = 0x01;
    pub const PLAYER: i32 = 0x03;
    pub const POSITION: i32 = 0x04;
    pub const POSITION_LOOK: i32 = 0x06;
    pub const CONFIRM_TRANSACTION: i32 = 0x0F;
    pub const CLIENT_SETTINGS: i32 = 0x15;
    pub const PLUGIN_MESSAGE: i32 = 0x17;
}

#[derive(Clone, Copy, Default)]
struct Position {
    x: f64,
    y: f64,
    z: f64,
    yaw: f32,
    pitch: f32,
}

/// Runs one connection until the server disconnects us. `Ok` carries the kick reason, `Err` a network/auth failure.
pub async fn run(config: &Config, auth: &mut Auth, responder: &mut AutoResponder, chat_rx: &mut mpsc::Receiver<String>) -> Result<String> {
    auth.login().await?;
    let mut session = Session::connect(config, auth.name()).await?;

    let kicked = timeout(LOGIN_TIMEOUT, session.login(auth)).await.context("login timed out")??;
    if let Some(reason) = kicked { return Ok(reason) }
    session.play(responder, chat_rx).await
}

struct Session<'a> {
    config: &'a Config,
    conn: Connection,
    position: Option<Position>,
    ticks_since_position: u32,
}

impl<'a> Session<'a> {
    async fn connect(config: &'a Config, name: &str) -> Result<Self> {
        let server = &config.server;
        info!("connecting to {}:{} as {name}", server.host, server.port);

        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((server.host.as_str(), server.port))).await.context("connect timed out")??;
        stream.set_nodelay(true)?;

        let mut conn = Connection::new(stream);
        let handshake = Writer::default()
            .varint(PROTOCOL_VERSION)
            .string(&server.host)
            .u16(server.port)
            .varint(2);

        conn.write_packet(serverbound::HANDSHAKE, &handshake.0).await?;
        conn.write_packet(login::START, &Writer::default().string(name).0).await?;

        Ok(Self {
            config,
            conn,
            position: None,
            ticks_since_position: 0,
        })
    }

    async fn login(&mut self, auth: &mut Auth) -> Result<Option<String>> {
        loop {
            let (id, data) = self.conn.read_packet(login::ALL).await?;
            let mut reader = Reader::new(&data);
            match id {
                login::DISCONNECT => return Ok(Some(chat::parse(reader.string()?))),
                login::ENCRYPTION_REQUEST => self.encrypt(auth, &mut reader).await?,
                login::SET_COMPRESSION => self.conn.set_compression(reader.varint()?),
                login::SUCCESS => {
                    let uuid = reader.string()?;
                    let name = reader.string()?;
                    info!(%name, %uuid, "logged in");
                    return Ok(None);
                }
                _ => {}
            }
        }
    }

    async fn encrypt(&mut self, auth: &mut Auth, reader: &mut Reader<'_>) -> Result<()> {
        let server_id = reader.string()?;
        let public_key = reader.byte_array()?;
        let verify_token = reader.byte_array()?;
        let secret: [u8; 16] = rand::random();

        auth.join_server(server_id, &secret, public_key).await?;

        let key = RsaPublicKey::from_public_key_der(public_key).map_err(|err| anyhow!("invalid server key: {err}"))?;
        let response = Writer::default()
            .byte_array(&key.encrypt(&mut OsRng, Pkcs1v15Encrypt, &secret)?)
            .byte_array(&key.encrypt(&mut OsRng, Pkcs1v15Encrypt, verify_token)?);

        self.conn.write_packet(login::ENCRYPTION_RESPONSE, &response.0).await?;
        self.conn.enable_encryption(&secret);
        Ok(())
    }

    async fn play(&mut self, responder: &mut AutoResponder, chat_rx: &mut mpsc::Receiver<String>) -> Result<String> {
        while let Ok(line) = chat_rx.try_recv() { warn!("dropping chat typed while disconnected: {line}") }

        let mut tick = time::interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_packet = Instant::now();
        let join_commands = time::sleep(Duration::from_secs(self.config.join_commands_delay_secs));
        tokio::pin!(join_commands);
        let mut join_commands_pending = !self.config.join_commands.is_empty();

        loop {
            tokio::select! {
                packet = self.conn.read_packet(clientbound::ALL) => {
                    let (id, data) = packet?;
                    last_packet = Instant::now();
                    if let Some(reason) = self.handle(id, &data, responder).await? { return Ok(reason) }
                }
                _ = tick.tick() => {
                    if last_packet.elapsed() > READ_TIMEOUT { bail!("timed out: no packets from server for {}s", READ_TIMEOUT.as_secs()) }
                    self.send_movement().await?;
                }
                _ = &mut join_commands, if join_commands_pending => {
                    join_commands_pending = false;
                    self.send_join_commands().await?;
                }
                Some(line) = chat_rx.recv() => self.send_chat(&line).await?,
            }
        }
    }

    async fn handle(&mut self, id: i32, data: &[u8], responder: &mut AutoResponder) -> Result<Option<String>> {
        let mut reader = Reader::new(data);
        match id {
            clientbound::KEEP_ALIVE => {
                let keep_alive = Writer::default().varint(reader.varint()?);
                self.conn.write_packet(serverbound::KEEP_ALIVE, &keep_alive.0).await?;
            }
            clientbound::JOIN_GAME => self.on_join_game().await?,
            clientbound::CHAT => self.on_chat(&mut reader, responder).await?,
            clientbound::RESPAWN => self.position = None,
            clientbound::POSITION_LOOK => self.on_position(&mut reader).await?,
            clientbound::CONFIRM_TRANSACTION => self.on_transaction(&mut reader).await?,
            clientbound::DISCONNECT => return Ok(Some(chat::parse(reader.string()?))),
            clientbound::SET_COMPRESSION => self.conn.set_compression(reader.varint()?),
            _ => {}
        }
        Ok(None)
    }

    async fn on_join_game(&mut self) -> Result<()> {
        let settings = Writer::default().string("en_US").i8(2).varint(0).bool(true).u8(0x7f);
        self.conn.write_packet(serverbound::CLIENT_SETTINGS, &settings.0).await?;
        let brand = Writer::default().string("MC|Brand").string("vanilla");
        self.conn.write_packet(serverbound::PLUGIN_MESSAGE, &brand.0).await
    }

    async fn send_join_commands(&mut self) -> Result<()> {
        for command in &self.config.join_commands { self.send_chat(command).await? }
        Ok(())
    }

    async fn on_chat(&mut self, reader: &mut Reader<'_>, responder: &mut AutoResponder) -> Result<()> {
        let message = chat::parse(reader.string()?);
        if reader.i8()? == 2 || message.trim().is_empty() { return Ok(()) }

        info!(target: "chat", "{message}");
        if LIMBO_MESSAGES.iter().any(|limbo| message.contains(limbo)) { info!("now in Limbo") }

        let Some(reply) = responder.respond(&message) else { return Ok(()) };
        info!(%reply, "auto-reply");
        self.send_chat(&reply).await
    }

    async fn on_position(&mut self, reader: &mut Reader<'_>) -> Result<()> {
        let (x, y, z) = (reader.f64()?, reader.f64()?, reader.f64()?);
        let (yaw, pitch) = (reader.f32()?, reader.f32()?);
        let flags = reader.u8()?;

        let old = self.position.unwrap_or_default();
        let relative = |bit: u8| flags & bit != 0;
        let position = Position {
            x: if relative(0x01) { old.x + x } else { x },
            y: if relative(0x02) { old.y + y } else { y },
            z: if relative(0x04) { old.z + z } else { z },
            yaw: if relative(0x08) { old.yaw + yaw } else { yaw },
            pitch: if relative(0x10) { old.pitch + pitch } else { pitch }
        };
        self.position = Some(position);

        let echo = Writer::default()
            .f64(position.x)
            .f64(position.y)
            .f64(position.z)
            .f32(position.yaw)
            .f32(position.pitch)
            .bool(false);
        self.conn.write_packet(serverbound::POSITION_LOOK, &echo.0).await
    }

    async fn on_transaction(&mut self, reader: &mut Reader<'_>) -> Result<()> {
        let window_id = reader.i8()?;
        let action = reader.i16()?;
        if reader.u8()? != 0 { return Ok(()) }
        let reply = Writer::default().i8(window_id).i16(action).bool(true);
        self.conn.write_packet(serverbound::CONFIRM_TRANSACTION, &reply.0).await
    }

    async fn send_movement(&mut self) -> Result<()> {
        let Some(position) = self.position else { return Ok(()) };

        if self.ticks_since_position < 20 {
            self.ticks_since_position += 1;
            return self.conn.write_packet(serverbound::PLAYER, &Writer::default().bool(true).0).await;
        }
        self.ticks_since_position = 0;
        let packet = Writer::default().f64(position.x).f64(position.y).f64(position.z).bool(true);
        self.conn.write_packet(serverbound::POSITION, &packet.0).await
    }

    async fn send_chat(&mut self, message: &str) -> Result<()> {
        let message: String = message.chars().take(MAX_CHAT_LEN).collect();
        debug!(%message, "sending chat");
        self.conn.write_packet(serverbound::CHAT, &Writer::default().string(&message).0).await
    }
}