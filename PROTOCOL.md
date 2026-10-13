# tune/1

Tune uses one RFC 6455 connection at `/_tune/connect` on the configured control
hostname. TLS certificate verification is mandatory outside explicit loopback
development mode. WebSocket compression and text messages are not supported.
The protocol version is carried in HELLO, not in a WebSocket subprotocol token.

## Frames

One binary WebSocket message carries exactly one Tune frame. WebSocket fragments
are accepted, with a cumulative message limit of 65,536 bytes. Every frame is:

```
type:u8 | stream_id:u32 | payload_length:u32 | payload:bytes
```

Integers use network byte order. Maximum payload is 65,527 bytes. A string is a
u32 byte length followed by UTF-8 bytes. A header list is a u32 pair count followed
by name/value strings. Repeated headers retain separate entries. Decoders reject
truncation, trailing fields, oversized values and unknown types.

| ID | Message | Stream | Payload |
| --- | --- | --- | --- |
| 1 | HELLO | 0 | version, requested name (empty for random), key fingerprint (empty for anonymous), server origin: strings |
| 2 | CHALLENGE | 0 | 32 random bytes |
| 3 | AUTH | 0 | 64-byte Ed25519 signature |
| 4 | WELCOME | 0 | public URL:string, maximum streams:u32 |
| 5 | OPEN | nonzero | method:string, origin-form request target:string, headers:list |
| 6 | HEADERS | nonzero | final status:u32, headers:list |
| 7 | DATA | nonzero | 1–16,384 body bytes |
| 8 | END | nonzero | empty |
| 9 | RESET | nonzero | directions:u32, HTTP error status:u32 |
| 10 | WINDOW_UPDATE | any | positive byte credit:u32 |
| 11 | PING | 0 | 8 random bytes |
| 12 | PONG | 0 | matching PING payload |
| 13 | ERROR | 0 | diagnostic:string, retry delay in seconds:u32 (0 means fatal) |

OPEN carries decoded HTTP framing: Transfer-Encoding is removed, while a known
Content-Length is retained. A request without a body explicitly has length zero.
An absent Content-Length denotes a streamed body terminated by END. The local
HTTP connection encodes an unknown-length request using chunked transfer coding.

## Authentication and registration

Private: HELLO → CHALLENGE → AUTH → WELCOME. Public: HELLO → WELCOME. In public
mode key fingerprints are ignored and requested names are rejected. No OPEN is
allowed before WELCOME. Setup PING/PONG may occur while a certificate is issued.

The signed bytes are the concatenation of length-prefixed strings:

1. `Tune client authentication`
2. `tune/1`
3. Configured server origin, without a trailing slash
4. OpenSSH SHA256 public-key fingerprint
5. Requested name, or the empty string
6. The raw 32-byte challenge (without a length prefix)

Each challenge belongs to one connection, expires after 30 seconds and can be
verified once. A registry reservation is created only after successful
authentication. ACME provisioning can delay WELCOME. Issuance failure releases
the reservation. ERROR closes the control connection; a positive retry delay
instructs the client to wait at least that long before reconnecting.

## Streams and cancellation

The server assigns strictly increasing, nonzero stream IDs, never reusing an ID
on the same connection. One stream is one HTTP exchange. Only the server sends
OPEN; only the client sends HEADERS. There is one final HEADERS message, followed
by response DATA and END. Request DATA and END are independent of the response.
Informational upstream responses are consumed locally, with a limit of 16.

RESET directions is a bitmask: 1 cancels the request direction, 2 the response,
and 3 both. A completed early response may cancel the remaining upload. DATA
already in flight after cancellation is discarded and its connection credit
returned. DATA after an ordinary END is a protocol error. Late frames for retired
IDs are discarded within bounded framing rules; future IDs are rejected.

Each direction starts with 65,536 bytes of per-stream credit and 1,048,576 bytes
of per-session credit. DATA consumes both. WINDOW_UPDATE restores credit only
after bytes are read or discarded. Credits cannot exceed their initial windows.
Control messages do not consume body credit. The connection reader never waits
for a downstream application's receive queue; inbound DATA is bounded by credit.

The writer has bounded control and data queues. END shares the DATA queue to
preserve ordering; RESET and window updates have control priority. Stream read
and write progress is limited to 60 seconds. A stalled shared writer closes the
session. Heartbeat runs every 15 seconds and fails after 45 seconds without a
matching PONG. Disconnect cancels all streams; HTTP requests are never replayed.
