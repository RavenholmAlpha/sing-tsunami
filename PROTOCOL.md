# TSUNAMI protocol specification

Status: stable, protocol version **3**.

This document specifies the TSUNAMI proxy protocol as implemented by the
reference implementation (<https://github.com/RavenholmAlpha/tsunami>) and by
this library. It is intended to be a complete description of the wire format
so that independent implementations can interoperate.

TSUNAMI is an AnyTLS-derived protocol. The framing and stream model are close
to AnyTLS, but the transport (HTTPS fronting), the padding system (v2) and the
settings/version negotiation differ; TSUNAMI peers are **not** wire-compatible
with AnyTLS peers. Section 12 lists the differences in detail.

## 1. Overview

A TSUNAMI deployment has two roles:

- **client**: a local proxy (SOCKS5/HTTP inbound, or an embedded proxy such as
  sing-box) that opens one or more long-lived TLS connections to the server
  and multiplexes proxied connections ("streams") over them.
- **server**: accepts the TLS connection (optionally behind the HTTP fronting
  layer), authenticates the client, and connects every stream to its
  destination.

Two transports are defined:

- **fronted** (default, recommended): the session is carried inside an
  authenticated HTTPS request: an HTTP/2 `POST` or an HTTP/1.1 WebSocket
  upgrade. Unauthenticated traffic is answered by a decoy website.
- **raw**: the session starts directly after a TLS handshake. This mode is
  intended for controlled/testing networks only; it does not hide the
  protocol from active probes.

## 2. Transport layer

- TCP, then TLS. TLS 1.3 is recommended; TLS 1.2 is tolerated by the fronting
  layer for compatibility.
- Fronted transport:
  - HTTP/2: ALPN **`h2`**.
  - WebSocket: ALPN **`http/1.1`** (the upgrade requires HTTP/1.1).
- Raw transport: no ALPN requirement. A fronting-capable server may advertise
  `h2`/`http/1.1` for its HTTP layer.
- Production deployments MUST use a certificate that is valid for the server
  name. A fronted session is an ordinary HTTPS request, so it must be
  indistinguishable from normal HTTPS at the TLS layer (certificate chain,
  SNI, ALPN, handshake).

The TLS version, cipher suites and certificate are deployment concerns; they
are not negotiated by this protocol.

## 3. HTTP fronting layer (fronted transport)

### 3.1 Request signing

Every fronting request carries HMAC-SHA256 authentication of the HTTP request
itself. This is independent from the TSUNAMI password used inside the tunnel.

The shared key is:

```
key = SHA-256(secret)
```

where `secret` is the fronting secret. Implementations commonly default it to
the user password, but a separate secret is recommended.

The MAC input is the UTF-8 string:

```
method + "\n" + escapedPath + "\n" + lowercase(host) + "\n" + timestamp + "\n" + nonce
```

- `method`: HTTP method, uppercase (`GET`, `POST`).
- `escapedPath`: the percent-encoded request path (empty path becomes `/`).
- `host`: the `Host` / `:authority` value, lowercased.
- `timestamp`: Unix time in seconds, decimal.
- `nonce`: random identifier, hex encoded, 16 to 128 characters.

The signature is the lowercase hex HMAC-SHA256 digest. Requests carry:

| Header | Value |
|:--|:--|
| `X-Api-Version` | `v1` |
| `X-Date` | Unix seconds |
| `X-Trace-Id` | nonce, hex |
| `Authorization` | `HMAC-SHA256 Signature=<hex>` |

The server MUST reject the request if:

- the version, timestamp, nonce or signature header is missing or malformed;
- the timestamp is outside a two-minute clock-skew window;
- the signature does not match for any configured key;
- the nonce was already seen within the replay window (server keeps a nonce
  cache; a TTL of two minutes plus clock skew is recommended).

Signature comparison MUST be constant time.

### 3.2 HTTP/2 tunnel

- Request: `POST <path>` (`path` is deployment configuration; a
  build-hashed-looking path such as `/static/js/main.<hex>.js` is
  recommended). Headers include the signature above, a browser-like
  `User-Agent`, `Content-Type: application/octet-stream`, and
  `Cache-Control: no-store`.
- The request body is a continuous stream of tunnel bytes (TSUNAMI frames).
  There is no `Content-Length`; the body lasts for the lifetime of the
  session.
- The server responds `200` and then writes tunnel bytes to the response body
  until the session ends. Streaming/flushing must not be buffered, otherwise
  the interaction pattern becomes suspicious.
- A signed request to the configured path is the only way to obtain a tunnel;
  everything else is decoy traffic (section 3.4).

### 3.3 WebSocket tunnel

- Request: HTTP/1.1 `GET <path>` with the same signed headers, plus
  `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13`,
  `Sec-WebSocket-Key: <base64 16 bytes>`.
- The server validates the signature and the path, answers
  `101 Switching Protocols` with the correct `Sec-WebSocket-Accept`, and then
  exchanges binary WebSocket frames. Client-to-server frames MUST be masked;
  server-to-client frames MUST NOT be masked. The payload of binary frames is
  the tunnel byte stream; control frames (ping/pong/close) are handled by the
  WebSocket layer itself.
- Because the upgrade is HTTP/1.1, the client MUST restrict TLS ALPN to
  `http/1.1` to make the server negotiate HTTP/1.1. (A browser-like ClientHello
  is still recommended; only the ALPN list is reduced.)

### 3.4 Decoy and site camouflage

Requests that do not carry a valid signature, or that do not target the
configured path, are answered as an ordinary website:

- `builtin`: a generated page (zero dependency; least realistic);
- `local`: reverse proxy to a website running on the same host (same-IP
  camouflage site);
- `remote`: reverse proxy to another website (borrowed content; the upstream
  `Host` is rewritten by default).

Reverse proxy behaviour mirrors a normal web server: `Host` handling,
`X-Forwarded-*`, upstream failure fallback to the built-in page, and stripping
of the fronting headers before forwarding. The decoy is optional for private
deployments but strongly recommended for public ones.

## 4. Session establishment

### 4.1 Authentication message

Immediately after the transport is ready (raw TLS, or after `200`/`101` in the
fronted transport), the client sends, in a single write:

```
+--------------------------+---------------------+---------------------+
| SHA-256(password) [32]   | padding length [2]  | padding [N]         |
+--------------------------+---------------------+---------------------+
```

- The hash is the raw 32-byte SHA-256 digest of the TSUNAMI user password.
- The padding length is a big-endian `uint16`; the following `N` bytes are
  ignored by the server. Uses of padding here are implementation-defined;
  randomizing the length (for example 24-88 bytes) is recommended. The total
  message must not exceed 65535 + 34 bytes.
- Authentication failure is silent from the protocol's point of view: in the
  fronted transport the server answers as decoy or closes; in raw mode it
  closes. There is no error frame for bad credentials.

### 4.2 Settings exchange

The **first frame** sent by the client after the authentication message MUST be
a `cmdSettings` frame (`streamID = 0`) whose payload is a UTF-8 text block:

```
v=<protocol version>
client=<implementation identifier>
padding-md5=<optional, md5 of the active padding scheme text>
surge-bandwidth=<optional, Mbps>
shaping=<optional, 1>
padding-v2=<optional, 1>
```

- `v` MUST be `3`. The server rejects any other version and closes.
- Unknown keys MUST be ignored by both sides.
- `padding-md5` is the lowercase hex MD5 of the exact padding scheme text the
  client is currently using (see section 7.4).
- `padding-v2=1` advertises support for the v2 padding scheme syntax. Servers
  MUST NOT push v2 scheme text to clients that did not advertise it, because
  old clients cannot parse it and would close the session.
- `shaping=1` requests the optional constant-rate shaping extension. The
  extension is deployment-specific; peers that do not implement it must ignore
  the key.

The server verifies the user hash and the version, then replies with a
`cmdServerSettings` frame (`streamID = 0`), payload:

```
v=<protocol version>
surge-mode=<none|auto>
max-connections=<n>
threshold=<n>
shaping=<optional, 1>
```

`cmdServerSettings` is the authentication-success signal: the client MUST NOT
treat the session as established before receiving it. On failure the server
closes the connection (and, in the fronted transport, may answer decoy
instead).

After sending `cmdServerSettings`, if the client advertised `padding-v2` and
its `padding-md5` differs from the server's active scheme, the server sends a
`cmdUpdatePaddingScheme` frame whose payload is the new scheme text. The client
parses it and applies it to the next writes. If the client is pre-v2, no scheme
is pushed; it keeps its own scheme.

### 4.3 Ordering diagram

```
client                                   server
  | TLS / fronting transport ready         |
  |-- auth message ----------------------->|
  |-- cmdSettings ------------------------>|
  |                                        | verify auth + version
  |<-------------------- cmdServerSettings -|
  |<------------- cmdUpdatePaddingScheme --| (optional)
  |-- SYN/PSH/FIN ... -------------------->|  streams
```

Padding frames (`cmdWaste`) may appear between any two frames and are ignored
by the receiver; implementations that pad the control writes may therefore
send `cmdWaste` before the first `cmdPSH` and after the settings exchange.

## 5. Frame layer

Every frame has a 7-byte header:

```
+---------+-------------------+-------------------+-------------+
| command | stream ID         | data length       | data        |
| u8      | u32 big-endian    | u16 big-endian    | <length>    |
+---------+-------------------+-------------------+-------------+
```

- Maximum data length is 65535 bytes.
- Frames with `streamID = 0` are session-level control frames.
- Frames with a non-zero `streamID` belong to that stream.
- An implementation MUST ignore frames with unknown command values (forward
  compatibility). Unknown commands are not an error.

Commands:

| Value | Name | Direction | Purpose |
|:--|:--|:--|:--|
| `0x00` | `cmdWaste` | both | padding; payload MUST be read and discarded |
| `0x01` | `cmdSYN` | client→server | open a stream |
| `0x02` | `cmdPSH` | both | stream payload |
| `0x03` | `cmdFIN` | both | close a stream |
| `0x04` | `cmdSettings` | client→server | client settings |
| `0x05` | `cmdAlert` | server→client | warning; session is closed |
| `0x06` | `cmdUpdatePaddingScheme` | server→client | push a padding scheme |
| `0x07` | `cmdSYNACK` | server→client | stream accepted |
| `0x08` | `cmdHeartRequest` | both | keep-alive ping |
| `0x09` | `cmdHeartResponse` | both | keep-alive pong |
| `0x0A` | `cmdServerSettings` | server→client | server settings |
| `0x0B` | `cmdSurgeCtrl` | both | reserved: connection scaling signalling |
| `0x0C` | `cmdBandwidthReport` | both | reserved: bandwidth statistics |
| `0x0D` | `cmdStreamPriority` | both | reserved: stream priority |

`0x0B`-`0x0D` are v3 extensions. The base protocol ignores them; an
implementation that does not use them MUST NOT require them.

## 6. Stream multiplexing

- The client allocates stream IDs, monotonically increasing, starting at 1.
- To open a stream, the client sends `cmdSYN` with the new stream ID and empty
  payload.
- The server replies `cmdSYNACK` with the same stream ID. The stream is not
  open for data until the client receives `cmdSYNACK`; senders should wait,
  but receivers MUST tolerate early `cmdPSH`.
- Data is carried in `cmdPSH` frames. Frame boundaries are not message
  boundaries: the receiver reassembles the stream as a byte stream.
- Either side closes a stream with `cmdFIN`; no `cmdFIN` reply is required.
  After `cmdFIN` the stream ID MUST NOT be reused.
- The first payload bytes the client writes on a stream are the destination in
  SOCKS5 address format (section 9). Everything after that is the proxied
  connection's bytes.
- Flow control is implementation-defined (a bounded per-stream read buffer with
  backpressure is the reference behaviour). There is no window-update frame in
  this protocol; a slow receiver applies backpressure by not reading from the
  transport. Implementations SHOULD bound per-stream buffering and MUST close
  the session if a peer violates framing invariants.

## 7. Padding subsystem (scheme v2)

Padding exists to hide the payload's size and timing pattern, in particular the
"TLS-in-TLS" signature of a TLS handshake carried inside the tunnel.

### 7.1 Scheme text format

A scheme is a newline-separated list of rules. `#` starts a comment. Known
keys:

```
stop=<n>
stream_bytes=<n>
ctl=<segments>
c<idx>=<segments>
s<idx>=<segments>
<idx>=<segments>
keepalive=<min>-<max>:<min>-<max>
```

- `stop`: number of data writes per stream that may be padded (per-stream
  epoch length, default 6).
- `stream_bytes`: per-stream padded-byte budget (default 12288). Padding stops
  for a stream once it has written that many bytes.
- `ctl`: the single rule used for every control write (settings, SYN, SYNACK,
  FIN, heartbeat, scheme updates, keepalive) for the whole session lifetime.
  It is not limited by `stop` or `stream_bytes`. An empty value disables
  control padding.
- `c<idx>` / `s<idx>`: client→server and server→client overrides for data-write
  index `<idx>`. Plain `<idx>` rules apply to both directions when no
  direction-specific rule is present.
- `keepalive`: idle-period `cmdWaste` generation: random interval range in
  milliseconds and random payload size range in bytes.

A rule value is a comma-separated segment list. Segment forms:

| Syntax | Meaning |
|:--|:--|
| `min-max` | emit a segment of a random size in `[min,max]`: user bytes first, then `cmdWaste` for the remainder, as a separate write |
| `c` | checkpoint: if no user data remains, stop processing this rule |
| `~min-max` | pad-to: emit the whole remaining user data plus `cmdWaste` as **one** write whose total size is at least a random size in `[min,max]`; never split. If the data is already larger, send it unchanged. `~n` means `n-n`. |

`~` is only meaningful as the last segment of a rule (the first pad-to segment
consumes the remaining payload and ends the rule). Targets are clamped to the
TLS record plaintext limit (16384 bytes).

### 7.2 Application semantics

- Each direction has its own padding writer (client role: client→server, server
  role: server→client).
- Every **data write** on a stream advances that stream's own epoch: rule 0
  applies to the first data write of a stream, rule 1 to the second, and so
  on, until `stop` writes or `stream_bytes` bytes have been processed. The
  epoch is per stream, not per session.
- Control writes use the `ctl` rule unconditionally.
- The reference default scheme:

```
stop=6
stream_bytes=12288
ctl=~40-160
c0=~80-200
c1=~900-1200
c2=~500-1200
s0=~2600-4200
s1=~700-1400
s2=~700-1400
3=~300-800
4=~300-800
5=~300-800
keepalive=45000-90000:4-8
```

This masks the first client data write (the inner ClientHello) to a
browser-plausible record size, the first server data write (the inner server
flight) to another, and the control frames to 40-160 bytes.

### 7.3 Wire interaction

Padding is written as `cmdWaste` frames, inside the same transport write as the
data they pad (so it does not create a separate TLS record). Receivers MUST
read and discard the payload. The waste payload is zero-filled by the reference
implementation (the transport already encrypts it); the content is irrelevant.

### 7.4 Negotiation

- Both sides start from their local default scheme (or a configured one) and
  the client sends its scheme MD5 in `cmdSettings`.
- If the server's active scheme differs and the client advertised
  `padding-v2=1`, the server pushes the new scheme text; the client replaces
  its scheme for subsequent writes (existing per-stream epochs keep their
  progress).
- The padding scheme does not need to be identical on both sides for the
  tunnel to work: receivers only discard `cmdWaste`. Matching schemes are
  required for the intended traffic shape.
- Old (pre-v2) clients may only be sent legacy (`min-max`/`c`) scheme text;
  servers must not send `~`, `ctl`, `stream_bytes`, `c<idx>` or `s<idx>` to
  them.

## 8. Keep-alive

- `cmdHeartRequest` is a ping; the receiver of a ping SHOULD answer with
  `cmdHeartResponse` echoing the stream ID 0.
- Intervals are implementation-defined. The reference client sends a ping only
  after a quiet period (25-55 s randomized), suppresses pings while data flows,
  and closes a session that does not answer within 90 s. Fixed, short periods
  are discouraged: they are an easy synthetic-traffic fingerprint.
- An idle client SHOULD eventually close its sessions; a permanent idle
  connection is also a fingerprint.

## 9. Destination address

The first bytes of a stream (inside `cmdPSH`) are a SOCKS5 address:

```
+------+------+----------+----------+
| ATYP | ...  | port     |          |
+------+------+----------+----------+
```

- `ATYP = 0x01`: 4-byte IPv4 address, then 2-byte big-endian port.
- `ATYP = 0x03`: 1-byte length, then that many bytes of domain, then port.
- `ATYP = 0x04`: 16-byte IPv6 address, then port.

The server connects the stream to that destination and relays bytes in both
directions. No protocol-level response confirms the destination connection;
connection failures are signalled by closing the stream (`cmdFIN`).

## 10. UDP over TCP (UoT)

UDP is carried over a normal stream using sing-box's UoT v2 framing
(`github.com/sagernet/sing/common/uot`). The stream destination is the magic
address:

- current: `sp.v2.udp-over-tcp.arpa`
- legacy, accepted during migration: `love.uot.world.anytls`

The client opens a stream to the magic address and then exchanges UoT v2
packets; the server treats them as UDP destinations. Implementations that do
not support UDP may reject the magic address.

## 11. Versioning and compatibility

- The current protocol version is **3**. Servers reject other client versions.
- Settings are line-based `key=value` text; unknown keys MUST be ignored.
- Unknown frame commands MUST be ignored.
- Feature flags are carried in settings (`padding-v2`, `shaping`) and are
  opt-in; a peer that does not understand a flag ignores it.
- A server that wants to support old clients may keep pushing legacy padding
  scheme text to them; new clients parse both formats.
- Reserved commands `0x0B`-`0x0D` may be used by future extensions without
  changing the frame format.

## 12. Differences from AnyTLS

TSUNAMI's frame format and stream model derive from AnyTLS, but the protocol
is not wire-compatible with it:

1. **Transport**: TSUNAMI's default transport is an HTTPS fronting session
   (signed HTTP/2 POST or WebSocket upgrade) with a decoy website for
   unauthenticated traffic. AnyTLS runs directly over TLS.
2. **Padding**: TSUNAMI uses scheme v2 (per-stream epochs, control rule,
   directional rules, exact-size pad-to) and negotiates it with
   `padding-v2` capability; the AnyTLS padding scheme has a different,
   session-oriented syntax.
3. **Settings**: TSUNAMI requires version 3 and a settings exchange
   (`cmdSettings`/`cmdServerSettings`); the content and the exact-version check
   differ.
4. **Site camouflage**: the server may reverse-proxy unauthenticated requests
   to a local or remote cover site.
5. **Extensions**: v3 reserves commands for connection scaling, bandwidth
   reporting and stream priority.

The projects also evolve independently; TSUNAMI implementations should be
treated as a separate protocol.

## 13. Security considerations

- The password hash is sent only inside TLS; it is equivalent to the password
  for authentication purposes. Passwords should be long and random.
- The fronting HMAC protects against off-path tunnel creation, not against a
  TLS-terminating observer that can read the request. Use a secret independent
  from the password where possible.
- Replay protection is required on the server (timestamp window + nonce cache).
- Padding adds bandwidth overhead and must not be used as a substitute for
  transport security.
- A fronted server should behave like a normal website for all unauthenticated
  requests; leaking different status codes, headers or timings for the tunnel
  path defeats the camouflage.
- Raw mode has no camouflage value; do not expose it to the public Internet.

## 14. References

- Reference implementation: <https://github.com/RavenholmAlpha/tsunami> (MIT)
- This library (GPL-3.0-or-later, includes MIT-derived portions):
  <https://github.com/RavenholmAlpha/sing-tsunami>
- AnyTLS: <https://github.com/anytls/anytls-go>
- UoT v2: <https://github.com/SagerNet/sing/tree/main/common/uot>
