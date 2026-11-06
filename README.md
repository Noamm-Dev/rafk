# rafk

A headless Minecraft AFK client written in Rust. It logs into a Microsoft account, joins Hypixel, and stays in Limbo indefinitely. It has no rendering and no world state: about 5 MB on disk and a few MB of RAM.

- **Minecraft 1.8.9 (protocol 47).** Hypixel runs 1.8.9 natively. It is also the simplest protocol (no configuration phase, no registries, no chat signing).
- **Hand-rolled protocol** instead of azalea: azalea only supports 1.20+, and a full bot framework would keep world state we don't need. rafk handles about 20 packet IDs. For every other packet it inflates only the packet ID and then drops the frame, so chunk and entity data is never decompressed.
- Microsoft device code login with a cached refresh token, auto-reconnect with capped exponential backoff, plain-text chat logging, a regex auto-responder, and chat from stdin.

## Build

```sh
cargo build --release                                       # native
cargo build --release --target x86_64-unknown-linux-musl    # static Linux binary
```

TLS is rustls with bundled roots, so the binary needs no OpenSSL or CA bundle. `ring` needs a C compiler for the musl target, so build that target on Linux (the VPS or Docker) rather than cross-compiling from Windows.

## First run (auth)

```sh
./rafk config.toml
```

On first run it logs something like:

```
WARN rafk::auth: Microsoft login required: open https://www.microsoft.com/link and enter code ABCD1234
```

Open the URL on any device, enter the code, and sign in with the Microsoft account that owns Minecraft. The tokens go to `auth.cache_path` (mode `0600` on Linux). Later runs log in silently and refresh the token when it expires. If the refresh token stops working, the device code prompt appears again.

The config path defaults to `./config.toml`. Stdin lines are sent as chat; prefix with `/` for commands, e.g. `/locraw`.

## Getting into Limbo

The example config runs `/limbo` 10 seconds after each (re)connect (`join_commands` and `join_commands_delay_secs`). Even without that, Hypixel sends idle players from a lobby to Limbo after a few minutes, and rafk never moves. The log shows `now in Limbo` when Hypixel confirms it.

## systemd

```sh
sudo useradd --system --home /var/lib/rafk --create-home rafk
sudo install -m 755 target/x86_64-unknown-linux-musl/release/rafk /usr/local/bin/rafk
sudo install -m 640 -o rafk config.toml /var/lib/rafk/config.toml
# do the first login interactively so the token cache exists:
sudo -u rafk sh -c 'cd /var/lib/rafk && /usr/local/bin/rafk config.toml'   # Ctrl+C once it has joined
```

`/etc/systemd/system/rafk.service`:

```ini
[Unit]
Description=rafk Minecraft AFK client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rafk
WorkingDirectory=/var/lib/rafk
ExecStart=/usr/local/bin/rafk /var/lib/rafk/config.toml
Restart=on-failure
RestartSec=30
StandardInput=null
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/rafk

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now rafk
journalctl -fu rafk
```

If you skip the interactive first login, the device code shows up in `journalctl -fu rafk` instead.

When a kick reason matches `fatal_kick_patterns`, rafk exits with code 0. `Restart=on-failure` then leaves it stopped. Start it again with `systemctl start rafk` when you're done playing.

## Docker

```dockerfile
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release

FROM scratch
COPY --from=build /src/target/release/rafk /rafk
WORKDIR /data
ENTRYPOINT ["/rafk", "/data/config.toml"]
```

```sh
docker build -t rafk .
docker run -it --rm -v "$PWD/data:/data" rafk                 # first run: complete the device code
docker run -d --restart on-failure -v "$PWD/data:/data" rafk  # afterwards
```

Put `config.toml` in `./data`. `cache_path = "token.json"` then resolves to `./data/token.json`.

## Hypixel caveats

1. **Rules.** Hypixel only allows approved client modifications. A custom headless client is technically outside that, and the auto-responder is chat automation, which raises the risk further. Idling in Limbo is low-visibility, but the account risk is not zero. Use it at your own risk.
2. **Logging in on your real client kicks the bot** with "You logged in from another location". If the bot reconnected, it would kick *you*, so that reason is a fatal pattern by default and the process exits.
3. **Watchdog** has nothing to check in Limbo. rafk mimics the vanilla packet pattern anyway: brand `vanilla`, client settings on join, an on-ground packet every tick, and a position packet every 20 ticks.
4. **Microsoft client ID.** New Azure apps need Mojang's approval to use the Minecraft API, so rafk defaults to the official Minecraft launcher's client ID, `00000000402b5328`. The ID azalea uses (`00000000441cc96b`) now fails on fresh sign-ins with "users are not permitted to consent to first party applications". You can change the ID in `[auth]`.
5. It's not confirmed whether Hypixel ever kicks long-term Limbo idlers. If it does, rafk reconnects and drifts back into Limbo.

## Logging

`log_level` in the config, or `RUST_LOG`, which takes priority. Chat is logged under the `chat` target, so `info,chat=off` silences it and `debug` shows teleports and outgoing chat.
