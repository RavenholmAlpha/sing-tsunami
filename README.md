# sing-tsunami

TSUNAMI proxy protocol client/server library, extracted from the TSUNAMI
implementation (<https://github.com/RavenholmAlpha/tsunami>, MIT) so it can be
embedded in [sing-box](https://github.com/SagerNet/sing-box) and other Go
programs.

The library implements the wire protocol only. Transport concerns (TCP, TLS,
uTLS fingerprints, sing-box routing/accounting) belong to the caller:

- **[PROTOCOL.md](PROTOCOL.md)** — the public wire specification (framing,
  authentication, settings, padding v2, HTTPS fronting, UoT, versioning, and
  the differences from AnyTLS).
- `protocol/` — frame format, commands, authentication, settings, session
  multiplexing and streams.
- `padding/` — TSUNAMI padding scheme v2 parser and per-stream padding writer.
- `fronting/` — HTTPS/HTTP2 (and WebSocket) fronting: request signing and
  verification, client tunnel conn, server-side HTTP/2 handler, and the decoy
  site handler (`builtin`, `local`, `remote` camouflage modes).
- root package `tsunami` — `Client` (session pool, `Dial`/`CreateStream`) and
  `Service` (server-side authentication and per-stream handler).

## License

This module is licensed under the GNU General Public License, version 3 or
later (see [LICENSE](LICENSE)). Portions are derived from the MIT-licensed
TSUNAMI reference implementation; see [NOTICE](NOTICE) for the attribution and
the MIT text.

## Usage sketch

```go
client, err := tsunami.NewClient(ctx, tsunami.ClientConfig{
    Password: "secret",
    DialOut: func(ctx context.Context) (net.Conn, error) {
        conn, err := tlsDialer.DialContext(ctx, "tcp", serverAddr)
        if err != nil {
            return nil, err
        }
        if frontingEnabled {
            return fronting.NewClientConn(conn, fronting.Config{...})
        }
        return conn, nil
    },
})
conn, err := client.Dial(ctx, "example.com:443")
```

```go
service, err := tsunami.NewService(tsunami.ServiceConfig{
    Users: []tsunami.User{{Name: "alice", Password: "secret"}},
    Handler: func(ctx context.Context, conn net.Conn, source net.Addr, destination string) {
        // route conn to destination
    },
})
err = service.NewConnection(ctx, conn, remoteAddr)
```

See `DESIGN.md` for the full API and sing-box integration contract.
