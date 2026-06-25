//! A sans-I/O HTTP/2 server and client implementation.
//!
//! This library implements the [HTTP/2] specification as a pure state machine.
//! It performs **no** I/O and contains **no** cryptography: the caller owns the
//! transport (a plain socket, a kTLS socket, an in-memory pipe, ...) and is
//! responsible for ALPN, TLS, and HTTP/1.1 upgrades.
//!
//! A connection is driven through three primitives:
//!
//! * `recv(&[u8])` feeds bytes received from the peer into the state machine.
//! * `poll_transmit(&mut BytesMut)` drains bytes that must be written to the
//!   peer.
//! * `poll_event()` pulls the next protocol event (a request/response, a chunk
//!   of body data, trailers, a reset, ...).
//!
//! See the [`client`] and [`server`] modules for the respective connection
//! types, and [`SendStream`] for streaming request/response bodies.
//!
//! # Getting started
//!
//! Add the following to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! h2 = "0.4"
//! ```
//!
//! # Layout
//!
//! The crate is split into [`client`] and [`server`] modules. Types that are
//! common to both clients and servers are located at the root of the crate.
//!
//! See module level documentation for more details on how to use `h2`.
//!
//! # Handshake
//!
//! This library assumes the transport is already in a state ready to start the
//! HTTP/2 handshake; reaching that state (a plaintext connection with prior
//! knowledge, a TLS connection negotiated via ALPN, or an HTTP/1.1 upgrade) is
//! the caller's responsibility.
//!
//! A connection is created with [`client::handshake`] or
//! [`server::handshake`]. The handshake bytes are then exchanged through the
//! normal `recv` / `poll_transmit` cycle:
//!
//! * The client sends the connection preface (a predefined sequence of 24
//!   octets), which the server consumes transparently in `recv`.
//! * Both the client and the server send a SETTINGS frame.
//!
//! Both of these are queued automatically when the connection is created and
//! emitted by the first call to `poll_transmit`. See [Starting HTTP/2] in the
//! specification for more details.
//!
//! # Flow control
//!
//! [Flow control] is a fundamental feature of HTTP/2. An endpoint may not send
//! unlimited data to the peer: each stream has a window size, and a connection
//! level window governs data across all streams. The peer replenishes a window
//! by sending `WINDOW_UPDATE` frames.
//!
//! For **outbound** data, [`SendStream`] exposes the current capacity and lets
//! the caller reserve capacity before sending; if more data is sent than there
//! is capacity for, the excess is buffered until the peer grants more.
//!
//! For **inbound** data, the library automatically releases stream and
//! connection capacity as `Data` events are surfaced, replenishing the peer's
//! window as the application consumes data.
//!
//! [HTTP/2]: https://http2.github.io/
//! [`client`]: client/index.html
//! [`server`]: server/index.html
//! [Flow control]: http://httpwg.org/specs/rfc7540.html#FlowControl
//! [`SendStream`]: struct.SendStream.html
//! [Starting HTTP/2]: http://httpwg.org/specs/rfc7540.html#starting
//! [`server::handshake`]: server/fn.handshake.html
//! [`client::handshake`]: client/fn.handshake.html

#![deny(
    missing_debug_implementations,
    missing_docs,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::type_complexity, clippy::manual_range_contains)]
// The sans-I/O rewrite retains internal protocol machinery (push promises,
// informational responses, user pings, ...) that is not yet surfaced by the
// event-based public API. Keep it around rather than deleting working code.
#![allow(dead_code)]
#![cfg_attr(test, deny(warnings))]

macro_rules! proto_err {
    (conn: $($msg:tt)+) => {
        tracing::debug!("connection error PROTOCOL_ERROR -- {};", format_args!($($msg)+))
    };
    (stream: $($msg:tt)+) => {
        tracing::debug!("stream error PROTOCOL_ERROR -- {};", format_args!($($msg)+))
    };
}

macro_rules! ready {
    ($e:expr) => {
        match $e {
            ::std::task::Poll::Ready(r) => r,
            ::std::task::Poll::Pending => return ::std::task::Poll::Pending,
        }
    };
}

#[cfg_attr(feature = "unstable", allow(missing_docs))]
mod codec;
mod error;
mod hpack;

#[cfg(not(feature = "unstable"))]
mod proto;

#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod proto;

#[cfg(not(feature = "unstable"))]
mod frame;

#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod frame;

pub mod client;
pub mod ext;
pub mod server;
mod share;

#[cfg(fuzzing)]
#[cfg_attr(feature = "unstable", allow(missing_docs))]
pub mod fuzz_bridge;

pub use crate::error::{Error, Reason};
pub use crate::share::{SendStream, StreamId};

#[cfg(feature = "unstable")]
pub use codec::{Codec, SendError, UserError};

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::task::{RawWaker, RawWakerVTable, Waker};

/// Creates a future from a function that returns `Poll`.
fn poll_fn<T, F: FnMut(&mut Context<'_>) -> T>(f: F) -> PollFn<F> {
    PollFn(f)
}

/// The future created by `poll_fn`.
struct PollFn<F>(F);

impl<F> Unpin for PollFn<F> {}

impl<T, F: FnMut(&mut Context<'_>) -> Poll<T>> Future for PollFn<F> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        (self.0)(cx)
    }
}

/// Returns a `Waker` that does nothing when woken.
///
/// The sans-I/O state machine is driven synchronously: callers feed bytes in,
/// pull bytes out, and pull protocol events out. Internally the protocol logic
/// is still structured around `Poll`, so we hand it a waker that never needs to
/// schedule anything — `Poll::Pending` simply means "no further progress can be
/// made until more input arrives".
fn noop_waker() -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
    const RAW: RawWaker = RawWaker::new(std::ptr::null(), &VTABLE);
    // SAFETY: the vtable functions are all no-ops that ignore the (null) data
    // pointer, so the resulting `Waker` is sound to use and clone.
    unsafe { Waker::from_raw(RAW) }
}
