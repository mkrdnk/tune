# Tune

Tune publishes a local HTTP service through an outbound WebSocket connection.
The client works behind NAT and CGNAT. A single Tune Server routes public
hostnames to connected clients, with streamed request/response bodies and bounded
flow control. There are two binaries, no database and no required client config.

The server supports anonymous access or Ed25519 client authentication. It can
obtain and renew individual TLS certificates using Let's Encrypt HTTP-01, or run
behind an existing HTTPS reverse proxy. License: GPL-3.0-only.

## Quick start

Build the binaries, then try the complete tunnel locally in separate terminals:

```sh
shards build
python3 -m http.server 8000 --bind 127.0.0.1
```

```sh
./bin/tune-server start 9000 --config examples/local.yml
```

```sh
./bin/tune localhost:8000 --server http://localhost:9000 --insecure-local
```

Use the hostname printed by the client as the Host header:

```sh
curl -H 'Host: REPLACE-WITH-PRINTED-HOSTNAME' http://127.0.0.1:9000/
```

This example explicitly enables unencrypted, loopback-only development mode.
For internet access use the self-hosted HTTPS configuration below.

## Installation and building

Requirements: Crystal **1.21.1 or newer**, Shards, OpenSSL **3.x** development
libraries, CA certificates, and Crystal's usual compiler/linker dependencies.
There are no third-party shard dependencies. The implementation targets Linux
x86_64 and ARM64, including 64-bit Raspberry Pi systems. CI includes both
architectures; 32-bit ARM and other operating systems are not release targets.

```sh
shards build --release
sudo install -m 0755 bin/tune bin/tune-server /usr/local/bin/
```

Build on each target architecture. These binaries dynamically link system
libraries; this repository does not provide static or cross-compiled releases.

## Using a public server

No project-operated public server is currently configured. Supply an actual
server you operate or have permission to use:

```sh
tune 8000 --server https://YOUR-TUNE-DOMAIN
export TUNE_SERVER=https://YOUR-TUNE-DOMAIN
tune http://localhost:8000
```

Server selection is `--server`, then runtime `TUNE_SERVER`, then a compile-time
`TUNE_DEFAULT_SERVER`. An empty default fails with an explanation; example
domains are never treated as an operating public service.

```sh
TUNE_DEFAULT_SERVER=https://YOUR-TUNE-DOMAIN shards build --release
```

Anonymous clients receive a cryptographically random, 32-hex-character name.
They cannot request `--name`. A reconnect can change an anonymous URL.

## Client commands

```sh
tune localhost:8000 --server https://YOUR-TUNE-DOMAIN
tune 8000 --server https://YOUR-TUNE-DOMAIN --name raspberry
tune https://localhost:8443 --identity ~/.config/tune/id_ed25519
tune keygen
tune keygen --identity ./another-identity
tune --help
tune --version
```

TARGET accepts a port, hostname, host:port, or HTTP/HTTPS origin. A port alone
means `http://localhost:PORT`; a hostname without a scheme means HTTP. IPv6
addresses in URLs must be bracketed. URL credentials, base paths, query strings
and fragments are rejected. HTTPS upstream certificates are verified.

`--debug` enables diagnostic logging. `--insecure-local` permits HTTP only to a
loopback control server. SIGINT/SIGTERM stop the client. Temporary disconnections
use exponential backoff with jitter, up to 30 seconds; explicit server cooldowns
can require longer waits. Existing HTTP requests are cancelled, never replayed.

## Self-hosted HTTPS with built-in ACME

Your Tune Server needs a public address. Point the base domain and its wildcard
DNS record to that address. Allow inbound TCP **80** and **443** and outbound
HTTPS to the CA. Publish AAAA records only if IPv6 actually reaches this server.

1. Generate an identity on each client with `tune keygen`.
2. Put only the `.pub` files in `/etc/tune/authorized_keys` on the server.
3. Copy `examples/server.yml` to `/etc/tune/server.yml`.
4. Replace the example domain and email. Set `terms_agreed: true` after reviewing
   the CA subscriber agreement. Make the ACME directory writable by the server.
5. Start the service using the systemd instructions below.

The effective server command is:

```sh
tune-server start 443 --config /etc/tune/server.yml
```

Tune starts the HTTP-01 listener first and obtains the base-domain certificate.
It then accepts HTTPS/WSS. Each authenticated registration reserves its hostname,
obtains or loads that hostname's certificate, and only then returns WELCOME.
Unknown Host/SNI requests cannot trigger certificate issuance. Initial setup can
take several seconds; a failed order does not publish a broken HTTPS URL.

HTTP-01 tokens are served only for active challenges. Known HTTPS hostnames are
redirected from HTTP with 308; unknown names and unknown challenge tokens get 404.
The main HTTPS listener serves both public requests and the control WebSocket.

Account keys, certificates and TLS keys persist in `tls.acme.data_dir`. Keep this
directory across upgrades and back it up securely. A process lock prevents two
Tune Servers sharing it. Files containing keys have mode 0600; the directory must
have mode 0700. No client identity private keys are stored on the server.

Certificates are renewed after roughly 65% of their actual lifetime. Renewal
replaces the TLS context without restarting or disconnecting established TLS
connections. A failed renewal retains a still-valid certificate and retries after
a cooldown. Expired certificates are never accepted for new handshakes, and Tune
does not downgrade to HTTP or self-signed certificates.

CA quotas apply independently of Tune's session limit. Let's Encrypt normally
allows **50 new certificates per registered domain per seven days**, shared by
all its subdomains and ACME accounts. Random names consume that quota. The local
default budget is ten new certificate attempts per UTC day. Neither restarting
Tune nor changing accounts bypasses the CA limit. See [Let's Encrypt rate
limits](https://letsencrypt.org/docs/rate-limits/).

For deployment troubleshooting, use a separate ACME directory with
`https://acme-staging-v02.api.letsencrypt.org/directory`. Staging certificates are
not browser-trusted; do not disable production certificate verification to use
them. The local Pebble test harness provides an isolated trusted test CA instead.

## Running behind nginx, Caddy or Via

Use `examples/external.yml` with:

```sh
tune-server start 8000 --config /etc/tune/server.yml
```

`tls.mode: external` is the default. The reverse proxy handles certificates and
TLS, preserves the original hostname, enables WebSocket Upgrade, disables
request/response buffering, and uses a timeout longer than the heartbeat interval. Tune's backend
listener should remain private. `examples/nginx.conf` is a complete nginx server
block for an existing base-domain plus wildcard certificate.

For Via 0.4.2 use [`examples/via-config.yaml`](examples/via-config.yaml).
Via replaces `Host` with the backend address and sends the original value in
`X-Forwarded-Host`. In Tune's `examples/external.yml` configuration, set
`server.trust_forwarded_host: true` and list only Via's backend source addresses
in `server.trusted_proxies` (for this example, `["127.0.0.1"]`). Via forwards
WebSocket upgrades and streams bodies automatically. Its route host matching is
exact, so the example forwards all hosts to Tune for domain validation/routing.

Via 0.4.2 uses one certificate per listener. Provision a certificate covering
both the base domain and `*.DOMAIN` with external DNS-01 ACME tooling, then deploy
the full chain and key to the PEM path in the example. Renew it externally;
Via watches the certificate files for reload. This deployment uses external TLS,
so Tune does not issue individual certificates. See the
[Via TLS documentation](https://via.makridenko.com/docs/0.4.2/tls/).

```sh
via check -c examples/via-config.yaml
via run -c examples/via-config.yaml
```

List only actual proxy addresses in `server.trusted_proxies`. This setting
accepts individual IP addresses, not CIDRs. Tune removes untrusted forwarded
headers. From a listed proxy, it validates X-Forwarded-For and takes the rightmost
untrusted address; X-Forwarded-Proto must be exactly `http` or `https`. Routing
uses `Host` by default. The explicit `server.trust_forwarded_host` option allows
a single valid `X-Forwarded-Host` from a listed proxy to select the control or
tunnel hostname; untrusted peers cannot override Host. Duplicate or malformed
forwarded hosts from trusted proxies are rejected with 400. When the header is
absent, Host is used. Enable this only with external TLS and a proxy that
overwrites client-supplied `X-Forwarded-Host`, as Via does. For forwarded client
IPs, Tune uses the rightmost untrusted address in the chain appended by Via.

## Docker Compose: Via + automatic wildcard TLS + Tune

The root `compose.yaml` runs a private Tune Server behind Via 0.4.2 and a Lego
4.26.0 certificate worker. Use Docker Engine with Compose **2.23.1 or newer** on
Linux. Tune and the certificate worker build locally; Via uses its published
image. Only HTTPS port **443** is published. DNS-01 does not require port 80;
this stack does not provide an HTTP redirect listener.

Point `DOMAIN` and `*.DOMAIN` to your server and allow inbound TCP 443. The ACME
worker needs outbound HTTPS and DNS access. Choose your DNS provider's identifier
and credential variables from the [Lego provider list](https://go-acme.github.io/lego/dns/).
The provider must be supported by the pinned Lego version. The same Compose file
works with different providers; only the settings and credentials change.

```sh
cp .env.example .env
cp dns.env.example dns.env
chmod 600 .env dns.env
# Edit .env: TUNE_DOMAIN, ACME_EMAIL, DNS_PROVIDER, ACME_ACCEPT_TOS.
# Edit dns.env: credentials required by that DNS provider.
```

Set `ACME_ACCEPT_TOS=true` after reviewing your CA's subscriber agreement.
`dns.env` is supplied only to the ACME container. It is a Docker environment
file, not a shell script; use `NAME=value` entries without `export`. Both local
env files and the authorized-key directory contents are ignored by Git and
excluded from Docker build contexts.

Generate an identity **on your client** with `tune keygen`, then copy its `.pub`
contents to `deploy/keys/authorized_keys` on the server (one key per line). Make
the directory traversable and the public-key file readable by container uid
10001; do not copy the private key to the server:

```sh
chmod 755 deploy/keys
chmod 644 deploy/keys/authorized_keys
docker compose up -d --build
docker compose logs -f acme via tune
```

Tune rejects a missing, empty or malformed authorized-key file. Via waits for
the first usable certificate before starting; DNS propagation can take minutes.
If Compose times out waiting, inspect the ACME logs, correct the DNS credentials
or settings, and run `docker compose up -d` again. Connect from your client:

```sh
tune localhost:8000 --server https://YOUR-TUNE-DOMAIN --name raspberry
```

The ACME worker obtains one certificate covering both `DOMAIN` and `*.DOMAIN`.
It checks renewal every twelve hours using Lego's lifetime-based renewal/ARI
logic and retries failures after one hour. It validates the certificate and key,
then atomically deploys a single PEM bundle that Via reloads without restarting.
A failed renewal preserves the deployed certificate. Monitor ACME logs and
container health; the ACME health check fails when the deployed certificate has
less than one day remaining. An unhealthy worker does not stop an already
running Via container.

The `acme_state` volume stores the ACME account and issued certificates;
`certificates` stores the restricted PEM copy mounted read-only by Via. Preserve
and securely back up both volumes across upgrades. `docker compose down` retains
them; **`docker compose down -v` deletes them**. Do not scale the ACME worker or
run multiple workers against the same volumes.

The backend uses fixed IPs because Tune trusts individual proxy addresses, not
CIDRs. If `172.30.80.0/24` overlaps an existing network, set `TUNE_SUBNET`,
`VIA_IP`, and `TUNE_IP` together in `.env`. Tune's port 8000 is not published.
The ACME worker has a separate network and cannot connect directly to Tune.

To replace or revoke client keys, update `deploy/keys/authorized_keys`, then:

```sh
docker compose kill -s SIGHUP tune
```

The whole key directory is mounted so atomic file replacements are visible.
On SELinux hosts, label that directory for container access (for example,
`chcon -Rt container_file_t deploy/keys`).

Test real DNS issuance against Let's Encrypt staging **before** starting the
production stack. Use a separate project so its untrusted certificates and
account state cannot replace production data:

```sh
ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory \
  docker compose -p tune-staging run --rm --no-deps acme once
docker compose -p tune-staging down -v
```

Do not change a running production project's CA URL to staging. Staging
certificates are not browser-trusted. Changing DNS providers only requires
editing `DNS_PROVIDER` and `dns.env`, then recreating the worker with
`docker compose up -d acme`; existing certificates remain valid.

## Keys and private access

`tune keygen` creates `~/.config/tune/id_ed25519` and its `.pub` file. Existing
files are never overwritten. `--identity` selects another path. If the default
identity exists, the client uses it automatically. Unencrypted OpenSSH Ed25519
keys from `ssh-keygen -t ed25519 -N ''` are also supported.

Authorized-key files contain one standard `ssh-ed25519 BASE64 optional-comment`
line per client. Blank lines and comments are accepted; key options and other
key types are rejected. An absent, empty or malformed private-mode key file
prevents startup. There is no fallback to public mode.

```sh
tune localhost:8000 --server https://YOUR-TUNE-DOMAIN --name raspberry
sudo systemctl reload tune-server
```

SIGHUP rereads the key file. Removed keys lose their active sessions and cannot
reconnect. If rereading a private-mode key file fails, private access closes until
a successful reload. Changes to `auth.mode`, `auth.allow_anonymous`,
`auth.authorized_keys` and `tunnels.blocked_names` can also be reloaded from YAML.
Other configuration changes require a restart. CLI overrides remain effective.

Every authorized key may request any valid free private-mode name. Names are
temporary and released when the session ends. Another authorized client may then
take the name. A cached TLS certificate does **not** reserve or confer ownership
of a name. There are no persistent name reservations in this version.

## Configuration

CLI values take priority over YAML; unspecified values use defaults. Unknown YAML
keys and invalid values fail startup. `start PORT` always sets the listener port.

| YAML key | Default | Meaning |
| --- | --- | --- |
| `server.bind` | `127.0.0.1` | Listener address; also used by HTTP-01 |
| `server.port` | `8000` | Port, overridden by positional PORT |
| `server.domain` | required | Base domain/control hostname, at most 180 bytes |
| `server.public_url` | `https://DOMAIN` | External origin; must use the base domain |
| `server.trusted_proxies` | `[]` | Individual trusted forwarding-proxy IPs |
| `server.trust_forwarded_host` | `false` | Accept X-Forwarded-Host for routing only from trusted proxies; requires external TLS |
| `server.insecure_local` | `false` | Allow loopback-only development HTTP |
| `auth.mode` | `private` | `private` or explicitly enabled `public` |
| `auth.authorized_keys` | `/etc/tune/authorized_keys` | Private-mode key file |
| `auth.allow_anonymous` | `true` | Admission switch in public mode |
| `tls.mode` | `external` | `external` or built-in `acme` |
| `tls.acme.directory_url` | Let's Encrypt production directory | ACME v2 HTTPS directory |
| `tls.acme.email` | absent | Optional CA account contact |
| `tls.acme.terms_agreed` | `false` | Explicit subscriber-agreement acceptance |
| `tls.acme.data_dir` | required for ACME | Persistent private storage |
| `tls.acme.http_port` | `80` | HTTP-01/redirect listener; public validation uses port 80 |
| `tls.acme.max_pending_orders` | `16` | Maximum active/queued certificate jobs |
| `tls.acme.max_new_certificates_per_day` | `10` | Persistent budget for new names |
| `tunnels.max_sessions` | `100` | Includes registrations awaiting certificates |
| `tunnels.max_streams_per_session` | `32` | Concurrent requests per tunnel |
| `tunnels.blocked_names` | `[]` | Denied labels; reload also disconnects them |
| `limits.max_connections` | `512` | Combined accepted TCP connections |
| `limits.max_header_size` | `16384` | Maximum public request head size, 1024–16384 |
| `limits.max_request_body` | `104857600` | Decoded body bytes, including chunked uploads |
| `limits.connections_per_minute` | `30` | Control connections per source IP; same-size burst |
| `limits.requests_per_second` | `60` | Per tunnel, with a two-second burst |
| `limits.bytes_per_second` | `10485760` | Each direction per tunnel; paced with bounded burst |
| `logging.level` | `info` | `debug`, `info`, `warn`, `error` |

`--bind`, `--domain`, `--authorized-keys`, `--debug`, `--insecure-local`,
`--config`, `--help` and `--version` are supported server options.

Protocol limits are fixed: 65,536-byte frames including their header, 16 KiB DATA
chunks, 64 KiB per-stream receive windows and 1 MiB session windows. The writer
has 128 control and 64 data queue slots. HTTP connect/header timeouts are ten
seconds initially; upstream response headers and stream progress have 60-second
timeouts. A stalled shared queue fails after ten seconds. Setup permits up to
three minutes for certificates. ACME transactions are serialized and queued
jobs wait at most 20 seconds for the worker. The certificate cache is capped at
1,000 names. There is no tunnel idle timeout: heartbeat keeps idle tunnels alive.

## systemd

Create a `tune` system user/group, install the binaries, and make the configuration
and authorized-key file readable by it. Install `examples/tune-server.service`:

```sh
sudo install -m 0644 examples/tune-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tune-server
sudo journalctl -u tune-server -f
```

The unit creates `/var/lib/tune` with mode 0700 and grants only
`CAP_NET_BIND_SERVICE` for ports 80/443. For external TLS, change ExecStart's port
to 8000 and use the external YAML example; the bind capability is unnecessary.
SIGINT/SIGTERM stop accepting requests, allow up to ten seconds for active streams
and close remaining connections.

## Anonymous service operation

`examples/public.yml` explicitly enables anonymous access. Keep admission, body,
connection, request, traffic and certificate budgets finite. A public tunnel can
host phishing, malware, copyrighted material or other abuse under your domain;
the operator is responsible for handling reports and capacity. Anonymous users
can consume certificate quotas even with application-level limits.

Set `auth.allow_anonymous: false` and reload to close anonymous access and active
sessions. Add a label to `tunnels.blocked_names` and reload to close that tunnel.
This blocks the name, not the anonymous person: they can request a different
random tunnel while anonymous admission remains enabled.

## Current limitations

- HTTP/1.0 and HTTP/1.1 forwarding; one upstream socket per request, no pooling.
  Public HTTP connections close after each response. No CONNECT, TCP/UDP
  tunnelling, HTTP/2/3, WebSocket application Upgrade or forwarded trailers.
- HTTP-01 ACME only, individual certificates for the base domain and its direct
  tunnel subdomains. No wildcard issuance, DNS API, TLS-ALPN-01, EAB, ARI,
  automatic account-key rollover or arbitrary custom-domain mappings.
- Unencrypted OpenSSH Ed25519 keys only; no SSH agent or password prompts.
- No permanent names, cluster state, database, dashboard or telemetry.
- Session addresses disappear on disconnect. HTTP errors after response headers
  have been sent truncate/close the connection instead of changing the status.
- Certificate Transparency makes issued names publicly discoverable. Random
  addresses are not an application access-control mechanism.

## Development and tests

```sh
crystal tool format --check
crystal spec
shards build --release
python3 scripts/test-process.py
```

Specs use real loopback sockets and random free ports, without public DNS. They
cover framing, flow control, Ed25519, OpenSSH compatibility, HTTP streaming,
concurrency, early responses, limits, reconnect and revocation. `ssh-keygen` is a
test-only requirement. A sandbox must permit local TCP sockets.

The optional ACME test uses a local Pebble CA, a local DNS responder, real HTTP-01
callbacks and an isolated CA trust bundle. It also checks renewal, badNonce
recovery, certificate persistence, SNI, and an HTTPS request over a WSS tunnel:

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
python3 -m venv /tmp/tune-test-env
/tmp/tune-test-env/bin/pip install cryptography
/tmp/tune-test-env/bin/python scripts/test-acme.py --pebble "$HOME/go/bin/pebble"
```

Go, Python's cryptography package and Pebble are needed only for this test. Tests
never request production certificates. See [PROTOCOL.md](PROTOCOL.md) for wire
format, authentication context and cancellation semantics.

The Compose tests use disposable local certificates and no public DNS or ACME
account. On Linux with Docker and Compose available:

```sh
docker build -t tune:test .
docker build -t tune-acme:test deploy/acme
docker run --rm --network none --entrypoint sh -i tune-acme:test < scripts/test-acme-deploy.sh
python3 scripts/test-compose.py
```

These exercise ACME worker persistence and failure handling, a private WSS
tunnel through Via, HTTPS hostname routing, and certificate reload with an
active tunnel. The smoke test publishes a random loopback port, uses the test
subnet `172.30.81.0/24`, and removes its own containers and volumes afterwards.
DNS-provider credentials and real issuance are tested separately against staging.
