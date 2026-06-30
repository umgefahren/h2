//! Sans-I/O server implementation of the HTTP/2 protocol.
//!
//! This module exposes an HTTP/2 server connection as an explicit state
//! machine. It performs **no** I/O itself: the caller reads and writes bytes on
//! whatever transport it likes (a plain socket, a kTLS socket, an in-memory
//! pipe, ...).
//!
//! # Driving a connection
//!
//! A [`Connection`] is driven with three primitives:
//!
//! * [`Connection::recv`] feeds bytes received from the peer into the state
//!   machine. The client connection preface is consumed automatically.
//! * [`Connection::poll_transmit`] drains bytes that must be written to the
//!   peer.
//! * [`Connection::poll_event`] pulls the next protocol [`Event`] (a new
//!   request, a chunk of request body, trailers, a reset, ...).
//!
//! Responses are sent with [`Connection::send_response`], followed by
//! [`Connection::send_data`] / [`Connection::send_trailers`] to stream the
//! response body.

use crate::codec::{Codec, UserError};
use crate::frame::{self, Pseudo, PushPromiseHeaderError, Reason, Settings, StreamId};
use crate::proto::{self, Error, Prioritized};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Method, Request, Response};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// The HTTP/2 connection preface sent by the client.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A protocol event surfaced to the application by [`Connection::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// A new request was received from the client.
    Request {
        /// The stream the request belongs to. Use this ID to send the response.
        stream_id: crate::StreamId,
        /// The request head.
        request: Request<()>,
        /// Whether the request also ends the stream (no body, no trailers).
        end_stream: bool,
    },
    /// A chunk of request body data was received.
    ///
    /// The library automatically releases flow-control capacity for delivered
    /// data, so the peer's window is replenished as data is surfaced.
    Data {
        /// The stream the data belongs to.
        stream_id: crate::StreamId,
        /// The body bytes.
        data: Bytes,
    },
    /// Trailers were received, ending the request stream.
    Trailers {
        /// The stream the trailers belong to.
        stream_id: crate::StreamId,
        /// The trailer header map.
        trailers: HeaderMap,
    },
    /// The request stream ended cleanly (body fully received, no trailers).
    StreamEnd {
        /// The stream that ended.
        stream_id: crate::StreamId,
    },
    /// The stream was reset, either by the peer or locally.
    Reset {
        /// The stream that was reset.
        stream_id: crate::StreamId,
        /// The reason for the reset.
        reason: Reason,
    },
    /// The connection has closed (gracefully or due to an error).
    GoAway,
}

/// Tracks per-stream progress for event generation and response sending.
struct Tracked<B: Buf> {
    send: proto::StreamRef<B>,
    recv: proto::OpaqueStreamRef,
    phase: Phase,
    send_done: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// Receiving the request body.
    Body,
    /// Finished receiving.
    Done,
}

/// Configures an HTTP/2 server connection before it is created.
#[derive(Clone, Debug)]
pub struct Builder {
    reset_stream_duration: Duration,
    reset_stream_max: usize,
    pending_accept_reset_stream_max: usize,
    initial_target_connection_window_size: Option<u32>,
    max_send_buffer_size: usize,
    settings: Settings,
    local_max_error_reset_streams: Option<usize>,
}

#[derive(Debug)]
pub(crate) struct Peer;

/// A sans-I/O HTTP/2 server connection.
///
/// See the [module documentation](self) for an overview.
pub struct Connection<B: Buf = Bytes> {
    inner: proto::Connection<Peer, B>,
    tracked: HashMap<u32, Tracked<B>>,
    events: VecDeque<Event>,
    closed: bool,
    close_err: Option<crate::Error>,
    waker: Waker,
    preface_pos: usize,
}

/// Creates a new server connection with default settings.
///
/// The initial `SETTINGS` frame is queued immediately; call
/// [`Connection::poll_transmit`] to obtain the bytes to write.
#[must_use]
pub fn handshake() -> Connection<Bytes> {
    Builder::new().handshake()
}

// ===== impl Builder =====

impl Builder {
    /// Returns a new server builder with default configuration values.
    #[must_use]
    pub fn new() -> Builder {
        Builder {
            reset_stream_duration: Duration::from_secs(proto::DEFAULT_RESET_STREAM_SECS),
            reset_stream_max: proto::DEFAULT_RESET_STREAM_MAX,
            pending_accept_reset_stream_max: proto::DEFAULT_REMOTE_RESET_STREAM_MAX,
            initial_target_connection_window_size: None,
            max_send_buffer_size: proto::DEFAULT_MAX_SEND_BUFFER_SIZE,
            settings: Settings::default(),
            local_max_error_reset_streams: Some(proto::DEFAULT_LOCAL_RESET_COUNT_MAX),
        }
    }

    /// Sets the initial stream-level window size (in octets) for received data.
    pub fn initial_window_size(&mut self, size: u32) -> &mut Self {
        self.settings.set_initial_window_size(Some(size));
        self
    }

    /// Sets the initial connection-level window size (in octets) for received
    /// data.
    pub fn initial_connection_window_size(&mut self, size: u32) -> &mut Self {
        self.initial_target_connection_window_size = Some(size);
        self
    }

    /// Sets the max frame size (in octets) this server is willing to receive.
    pub fn max_frame_size(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_frame_size(Some(max));
        self
    }

    /// Sets the maximum size (in octets) of received header lists.
    pub fn max_header_list_size(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_header_list_size(Some(max));
        self
    }

    /// Sets the maximum number of concurrent streams.
    pub fn max_concurrent_streams(&mut self, max: u32) -> &mut Self {
        self.settings.set_max_concurrent_streams(Some(max));
        self
    }

    /// Sets the header table size (in octets) for the HPACK encoder.
    pub fn header_table_size(&mut self, size: u32) -> &mut Self {
        self.settings.set_header_table_size(Some(size));
        self
    }

    /// Sets the maximum number of remotely reset streams allowed in the pending
    /// accept queue.
    pub fn max_pending_accept_reset_streams(&mut self, max: usize) -> &mut Self {
        self.pending_accept_reset_stream_max = max;
        self
    }

    /// Creates a new configured server connection.
    #[must_use]
    pub fn handshake<B: Buf>(&self) -> Connection<B> {
        Connection::new(self.clone())
    }
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new()
    }
}

// ===== impl Connection =====

impl<B> Connection<B>
where
    B: Buf,
{
    fn new(builder: Builder) -> Connection<B> {
        let mut codec = Codec::<Prioritized<B>>::new();

        if let Some(max) = builder.settings.max_frame_size() {
            codec.set_max_recv_frame_size(max as usize);
        }
        if let Some(max) = builder.settings.max_header_list_size() {
            codec.set_max_recv_header_list_size(max as usize);
        }
        codec
            .buffer(builder.settings.clone().into())
            .expect("invalid SETTINGS frame");

        let inner = proto::Connection::new(
            codec,
            proto::Config {
                next_stream_id: 2.into(),
                initial_max_send_streams: 0,
                max_send_buffer_size: builder.max_send_buffer_size,
                reset_stream_duration: builder.reset_stream_duration,
                reset_stream_max: builder.reset_stream_max,
                remote_reset_stream_max: builder.pending_accept_reset_stream_max,
                local_error_reset_streams_max: builder.local_max_error_reset_streams,
                settings: builder.settings.clone(),
            },
        );

        let mut conn = Connection {
            inner,
            tracked: HashMap::new(),
            events: VecDeque::new(),
            closed: false,
            close_err: None,
            waker: crate::noop_waker(),
            preface_pos: 0,
        };

        if let Some(sz) = builder.initial_target_connection_window_size {
            conn.inner.set_target_window_size(sz);
        }

        conn
    }

    /// Feeds bytes received from the peer into the connection.
    ///
    /// The client connection preface is consumed transparently before any
    /// frames are decoded.
    pub fn recv(&mut self, mut src: &[u8]) -> Result<(), crate::Error> {
        if self.preface_pos < PREFACE.len() {
            let need = PREFACE.len() - self.preface_pos;
            let take = need.min(src.len());
            if src[..take] != PREFACE[self.preface_pos..self.preface_pos + take] {
                let err: crate::Error = Error::library_go_away(Reason::PROTOCOL_ERROR).into();
                self.closed = true;
                return Err(err);
            }
            self.preface_pos += take;
            src = &src[take..];
        }
        if !src.is_empty() {
            self.inner.recv_bytes(src);
        }
        self.drive();
        self.take_closed_err()
    }

    /// Drains any bytes that need to be written to the peer into `dst`,
    /// returning the number of bytes written.
    pub fn poll_transmit(&mut self, dst: &mut BytesMut) -> usize {
        self.drive();
        self.inner.poll_transmit(dst)
    }

    /// Returns the next available protocol [`Event`], if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        if self.events.is_empty() {
            self.pump();
        }
        self.events.pop_front()
    }

    /// Sends a response head on the given stream.
    ///
    /// If `end_stream` is `true`, the response has no body and the stream's send
    /// half is closed.
    pub fn send_response(
        &mut self,
        stream_id: crate::StreamId,
        response: Response<()>,
        end_stream: bool,
    ) -> Result<(), crate::Error> {
        let entry = self
            .tracked
            .get_mut(&stream_id.as_u32())
            .ok_or(UserError::InactiveStreamId)?;
        entry.send.send_response(response, end_stream)?;
        if end_stream {
            entry.send_done = true;
        }
        Ok(())
    }

    /// Sends a chunk of response body data on the given stream.
    pub fn send_data(
        &mut self,
        stream_id: crate::StreamId,
        data: B,
        end_stream: bool,
    ) -> Result<(), crate::Error> {
        let entry = self
            .tracked
            .get_mut(&stream_id.as_u32())
            .ok_or(UserError::InactiveStreamId)?;
        entry.send.send_data(data, end_stream)?;
        if end_stream {
            entry.send_done = true;
        }
        Ok(())
    }

    /// Sends trailers on the given stream, closing the send half.
    pub fn send_trailers(
        &mut self,
        stream_id: crate::StreamId,
        trailers: HeaderMap,
    ) -> Result<(), crate::Error> {
        let entry = self
            .tracked
            .get_mut(&stream_id.as_u32())
            .ok_or(UserError::InactiveStreamId)?;
        entry.send.send_trailers(trailers)?;
        entry.send_done = true;
        Ok(())
    }

    /// Resets the given stream with the provided reason.
    pub fn reset_stream(&mut self, stream_id: crate::StreamId, reason: Reason) {
        if let Some(entry) = self.tracked.get_mut(&stream_id.as_u32()) {
            entry.send.send_reset(reason);
            entry.send_done = true;
        }
    }

    /// Returns the current send capacity (in octets) for the given stream.
    pub fn stream_capacity(&self, stream_id: crate::StreamId) -> usize {
        self.tracked
            .get(&stream_id.as_u32())
            .map_or(0, |t| t.send.capacity() as usize)
    }

    /// Returns `true` once the connection has fully closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Sets the connection-level target window size.
    pub fn set_target_window_size(&mut self, size: u32) {
        assert!(size <= proto::MAX_WINDOW_SIZE);
        self.inner.set_target_window_size(size);
    }

    /// Begins a graceful shutdown by sending a GOAWAY frame.
    pub fn go_away(&mut self) {
        self.inner.go_away_gracefully();
    }

    fn take_closed_err(&mut self) -> Result<(), crate::Error> {
        self.close_err.take().map_or(Ok(()), Err)
    }

    fn drive(&mut self) {
        if self.closed {
            return;
        }
        // Unlike the client, a server connection stays open while idle, waiting
        // for the peer to open new streams; it only closes on GOAWAY.
        let waker = self.waker.clone();
        let mut cx = Context::from_waker(&waker);
        match self.inner.poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.closed = true;
                self.events.push_back(Event::GoAway);
            }
            Poll::Ready(Err(e)) => {
                self.closed = true;
                self.close_err = Some(e.into());
                self.events.push_back(Event::GoAway);
            }
        }
    }

    fn pump(&mut self) {
        self.drive();

        // Accept any newly received requests.
        while let Some(stream_ref) = self.inner.next_incoming() {
            let recv = stream_ref.clone_to_opaque();
            let id: u32 = stream_ref.stream_id().into();
            let request = stream_ref.take_request();
            let end = recv.is_end_stream();
            self.events.push_back(Event::Request {
                stream_id: crate::StreamId::from_u32(id),
                request,
                end_stream: end,
            });
            self.tracked.insert(
                id,
                Tracked {
                    send: stream_ref,
                    recv,
                    phase: if end { Phase::Done } else { Phase::Body },
                    send_done: false,
                },
            );
        }

        let waker = self.waker.clone();
        let cx = Context::from_waker(&waker);

        let ids: Vec<u32> = self.tracked.keys().copied().collect();
        for id in ids {
            loop {
                let Some(phase) = self.tracked.get(&id).map(|t| t.phase) else {
                    break;
                };
                if phase == Phase::Done {
                    break;
                }
                let entry = self.tracked.get_mut(&id).unwrap();
                match entry.recv.poll_data(&cx) {
                    Poll::Ready(Some(Ok(data))) => {
                        let len = data.len() as proto::WindowSize;
                        let _ = entry.recv.release_capacity(len);
                        self.events.push_back(Event::Data {
                            stream_id: crate::StreamId::from_u32(id),
                            data,
                        });
                    }
                    Poll::Ready(Some(Err(e))) => {
                        entry.phase = Phase::Done;
                        self.emit_stream_error(id, e);
                        break;
                    }
                    Poll::Ready(None) => {
                        entry.phase = Phase::Done;
                        match entry.recv.poll_trailers(&cx) {
                            Poll::Ready(Some(Ok(trailers))) => {
                                self.events.push_back(Event::Trailers {
                                    stream_id: crate::StreamId::from_u32(id),
                                    trailers,
                                });
                            }
                            _ => {
                                self.events.push_back(Event::StreamEnd {
                                    stream_id: crate::StreamId::from_u32(id),
                                });
                            }
                        }
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }

        // Reclaim streams that are fully finished in both directions.
        self.tracked
            .retain(|_, t| !(t.send_done && t.phase == Phase::Done));
    }

    fn emit_stream_error(&mut self, id: u32, e: proto::Error) {
        let err: crate::Error = e.into();
        let reason = err.reason().unwrap_or(Reason::INTERNAL_ERROR);
        self.events.push_back(Event::Reset {
            stream_id: crate::StreamId::from_u32(id),
            reason,
        });
    }
}

impl<B> fmt::Debug for Connection<B>
where
    B: Buf,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("server::Connection")
            .finish_non_exhaustive()
    }
}

// ===== impl Peer =====

impl Peer {
    pub fn convert_send_message(
        id: StreamId,
        response: Response<()>,
        end_of_stream: bool,
    ) -> frame::Headers {
        use http::response::Parts;

        // Extract the components of the HTTP request
        let (
            Parts {
                status, headers, ..
            },
            (),
        ) = response.into_parts();

        // Build the set pseudo header set. All requests will include `method`
        // and `path`.
        let pseudo = Pseudo::response(status);

        // Create the HEADERS frame
        let mut frame = frame::Headers::new(id, pseudo, headers);

        if end_of_stream {
            frame.set_end_stream();
        }

        frame
    }

    pub fn convert_push_message(
        stream_id: StreamId,
        promised_id: StreamId,
        request: Request<()>,
    ) -> Result<frame::PushPromise, UserError> {
        use http::request::Parts;

        if let Err(e) = frame::PushPromise::validate_request(&request) {
            use PushPromiseHeaderError::{InvalidContentLength, NotSafeAndCacheable};
            match e {
                NotSafeAndCacheable => tracing::debug!(
                    ?promised_id,
                    "convert_push_message: method {} is not safe and cacheable",
                    request.method(),
                ),
                InvalidContentLength(e) => tracing::debug!(
                    ?promised_id,
                    "convert_push_message; promised request has invalid content-length {:?}",
                    e,
                ),
            }
            return Err(UserError::MalformedHeaders);
        }

        // Extract the components of the HTTP request
        let (
            Parts {
                method,
                uri,
                headers,
                ..
            },
            (),
        ) = request.into_parts();

        let pseudo = Pseudo::request(method, uri, None);

        Ok(frame::PushPromise::new(
            stream_id,
            promised_id,
            pseudo,
            headers,
        ))
    }
}

impl proto::Peer for Peer {
    type Poll = Request<()>;

    const NAME: &'static str = "Server";

    fn r#dyn() -> proto::DynPeer {
        proto::DynPeer::Server
    }

    fn convert_poll_message(
        pseudo: Pseudo,
        fields: HeaderMap,
        stream_id: StreamId,
    ) -> Result<Self::Poll, Error> {
        use http::{uri, Version};

        let mut b = Request::builder();

        macro_rules! malformed {
            ($($arg:tt)*) => {{
                tracing::debug!($($arg)*);
                return Err(Error::library_reset(stream_id, Reason::PROTOCOL_ERROR));
            }}
        }

        b = b.version(Version::HTTP_2);

        let is_connect;
        if let Some(method) = pseudo.method {
            is_connect = method == Method::CONNECT;
            b = b.method(method);
        } else {
            malformed!("malformed headers: missing method");
        }

        let has_protocol = pseudo.protocol.is_some();
        if has_protocol {
            if is_connect {
                // Assert that we have the right type.
                b = b.extension::<crate::ext::Protocol>(pseudo.protocol.unwrap());
            } else {
                malformed!("malformed headers: :protocol on non-CONNECT request");
            }
        }

        if pseudo.status.is_some() {
            malformed!("malformed headers: :status field on request");
        }

        // Convert the URI
        let mut parts = uri::Parts::default();

        // A request translated from HTTP/1 must not include the :authority
        // header
        if let Some(authority) = pseudo.authority {
            let maybe_authority = uri::Authority::from_maybe_shared(authority.clone().into_inner());
            parts.authority = Some(maybe_authority.or_else(|why| {
                malformed!(
                    "malformed headers: malformed authority ({:?}): {}",
                    authority,
                    why,
                )
            })?);
        }

        // A :scheme is required, except CONNECT.
        if let Some(scheme) = pseudo.scheme {
            if is_connect && !has_protocol {
                malformed!("malformed headers: :scheme in CONNECT");
            }
            let maybe_scheme = scheme.parse();
            let scheme = maybe_scheme.or_else(|why| {
                malformed!(
                    "malformed headers: malformed scheme ({:?}): {}",
                    scheme,
                    why,
                )
            })?;

            // It's not possible to build an `Uri` from a scheme and path. So,
            // after validating is was a valid scheme, we just have to drop it
            // if there isn't an :authority.
            if parts.authority.is_some() {
                parts.scheme = Some(scheme);
            }
        } else if !is_connect || has_protocol {
            malformed!("malformed headers: missing scheme");
        }

        if let Some(path) = pseudo.path {
            if is_connect && !has_protocol {
                malformed!("malformed headers: :path in CONNECT");
            }

            // This cannot be empty
            if path.is_empty() {
                malformed!("malformed headers: missing path");
            }

            let maybe_path = uri::PathAndQuery::from_maybe_shared(path.clone().into_inner());
            parts.path_and_query = Some(maybe_path.or_else(|why| {
                malformed!("malformed headers: malformed path ({:?}): {}", path, why,)
            })?);
        } else if is_connect && has_protocol {
            malformed!("malformed headers: missing path in extended CONNECT");
        }

        b = b.uri(parts);

        let mut request = match b.body(()) {
            Ok(request) => request,
            Err(e) => {
                // TODO: Should there be more specialized handling for different
                // kinds of errors
                proto_err!(stream: "error building request: {}; stream={:?}", e, stream_id);
                return Err(Error::library_reset(stream_id, Reason::PROTOCOL_ERROR));
            }
        };

        *request.headers_mut() = fields;

        Ok(request)
    }
}
