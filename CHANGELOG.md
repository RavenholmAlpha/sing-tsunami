# Changelog

All notable changes to `sing-tsunami` are documented here. The module follows
semantic versioning; protocol-visible behaviour is called out explicitly.

## [0.1.2] - 2026-11-03

### Security

- **Fronting replay protection (memory DoS):** `VerifyRequest` now inserts a
  nonce into the replay cache only after the HMAC signature verifies, and
  `NonceCache` has a hard entry cap with eviction. Unauthenticated probes can no
  longer grow the cache without bound. Callers that share a cache between
  handlers keep replay protection for valid requests.
- **Session stream limits (resource exhaustion):** `protocol.Session` now has a
  `DefaultMaxStreams` of 256, `SetMaxStreams`/`MaxStreams`, and `ErrTooManyStreams`.
  Incoming `cmdSYN` frames beyond the limit are rejected with a non-empty
  `cmdSYNACK`; client-side opens fail fast. The per-stream receive queue is
  bounded to 4 frames (~256 KiB), and `Service`/`Client` expose `MaxStreams`
  configuration (client default 0 = unlimited, server default 256).
- **No-destination timeout:** a stream that has not sent its destination
  address within 10 seconds is closed, so idle streams cannot pin a handler
  goroutine.
- **Smaller relay buffers:** `protocol.RelayBufPool` now uses 64 KiB buffers
  instead of 256 KiB.

### Changed

- `ServiceConfig.MaxStreams` and `ClientConfig.MaxStreams` added (additive).
- `PROTOCOL.md` documents the recommended concurrent-stream bound, the
  no-destination timeout, and the rejection semantics for excess `cmdSYN`.

## [0.1.1] - 2026-10-31

### Added

- `PROTOCOL.md`, a complete public wire specification.
- GPL-3.0-or-later license (MIT-derived portions attributed in `NOTICE`).

### Fixed

- WebSocket fronting advertises `http/1.1` only in the TLS ALPN extension.

## [0.1.0] - 2026-10-22

### Added

- Initial protocol library: framing, authentication, settings, session/stream
  multiplexing, padding v2, HTTPS/HTTP2/WebSocket fronting, decoy site handler,
  client and service.
