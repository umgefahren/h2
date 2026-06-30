# h2-zero

A **sans-I/O** HTTP/2 client & server implementation for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/h2-zero.svg)](https://crates.io/crates/h2-zero)
[![Documentation](https://docs.rs/h2-zero/badge.svg)][dox]

More information about this crate can be found in the [crate documentation][dox].

[dox]: https://docs.rs/h2-zero

## Features

* Client and server HTTP/2 implementation.
* Implements the HTTP/2 framing, HPACK, flow-control, and stream state logic.
* **Sans-I/O**: the library performs no I/O and runs no async runtime. The
  caller owns the transport and drives the connection by feeding it bytes and
  pulling bytes and events back out.
* **No cryptography**: TLS is entirely out of scope, which makes it a natural
  fit for kernel TLS (kTLS) or any externally-terminated TLS.

## How it works

A connection is an explicit state machine driven by three primitives:

* `recv(&[u8])` — feed bytes received from the peer.
* `poll_transmit(&mut BytesMut)` — drain bytes that must be written to the peer.
* `poll_event()` — pull the next protocol event (a request/response, body data,
  trailers, a reset, ...).

This makes the library transport-agnostic: wire it to a blocking socket, an
async socket, a kTLS socket, or an in-memory pipe — the protocol logic does not
care.

## Non goals

This crate is intended to only be an implementation of the HTTP/2
specification. It does not handle:

* Managing TCP (or any other) connections.
* HTTP 1.0/1.1 upgrades.
* TLS or any other cryptography.
* Any feature not described by the HTTP/2 specification.

## Usage

To use `h2-zero`, first add this to your `Cargo.toml`:

```toml
[dependencies]
h2-zero = "0.4"
```

Then drive a connection over whatever transport you like. See
[`examples/sansio.rs`](examples/sansio.rs) for a complete, runnable client +
server demo that exchanges a request and response purely through in-memory
buffers:

```rust
use bytes::BytesMut;
use h2_zero::client;
use http::Request;

let mut conn = client::handshake();

let request = Request::get("https://example.com/").body(()).unwrap();
let (_stream_id, _body) = conn.send_request(request, true).unwrap();

// Write what the connection wants to send to your transport...
let mut out = BytesMut::new();
conn.poll_transmit(&mut out);
// socket.write_all(&out)?;

// ...read bytes back and feed them in, then drain events.
// conn.recv(&bytes)?;
// while let Some(event) = conn.poll_event() { /* handle */ }
```

On the server side, `server::handshake()` gives a `server::Connection` with the
same `recv` / `poll_transmit` / `poll_event` loop; requests arrive as
`server::Event::Request` and responses are sent with
`Connection::send_response` / `send_data` / `send_trailers`.

## Minimum supported Rust version

The current MSRV is **1.65**.

## FAQ

**Is this an embedded Java SQL database engine?**

[No](https://www.h2database.com).
