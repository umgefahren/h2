//! Sans-I/O client implementation of the HTTP/2 protocol.
//!
//! This module exposes an HTTP/2 client connection as an explicit state
//! machine. It performs **no** I/O itself: the caller is responsible for
//! reading and writing bytes on whatever transport it likes (a plain socket,
//! a kTLS socket, an in-memory pipe, ...).
//!
//! # Driving a connection
//!
//! A [`Connection`] is driven with three primitives:
//!
//! * [`Connection::recv`] feeds bytes received from the peer into the state
//!   machine.
//! * [`Connection::poll_transmit`] drains bytes that must be written to the
//!   peer.
//! * [`Connection::poll_event`] pulls the next protocol [`Event`] (a response,
//!   a chunk of body data, trailers, a reset, ...).
//!
//! Requests are initiated with [`Connection::send_request`], which returns a
//! [`SendStream`] used to stream the request body.
//!
//! ```
//! use h2_zero::client;
//! use http::Request;
//! use bytes::BytesMut;
//!
//! # fn doc() -> Result<(), h2_zero::Error> {
//! let mut conn = client::handshake();
//!
//! let request = Request::get("https://example.com/").body(()).unwrap();
//! let (id, mut body) = conn.send_request(request, true)?;
//! let _ = id;
//! let _ = &mut body;
//!
//! // Write whatever the connection wants to send to the transport.
//! let mut out = BytesMut::new();
//! conn.poll_transmit(&mut out);
//! // ... write `out` to the socket, read bytes back, then:
//! // conn.recv(&bytes)?;
//! // while let Some(event) = conn.poll_event() { /* handle */ }
//! # Ok(())
//! # }
//! ```

use crate::codec::{Codec, SendError, UserError};
use crate::ext::Protocol;
use crate::frame::{Headers, Pseudo, Reason, Settings, StreamId};
use crate::proto::{self, Error, Prioritized};
use crate::SendStream;

use bytes::{Buf, Bytes, BytesMut};
use http::{uri, HeaderMap, Method, Request, Response, Version};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// A protocol event surfaced to the application by [`Connection::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// Response headers were received for a request the client sent.
    Response {
        /// The stream the response belongs to.
        stream_id: crate::StreamId,
        /// The response head.
        response: Response<()>,
        /// Whether this response also ends the stream (no body, no trailers).
        end_stream: bool,
    },
    /// A chunk of response body data was received.
    ///
    /// The library automatically releases flow-control capacity for delivered
    /// data, so the peer's window is replenished as data is surfaced.
    Data {
        /// The stream the data belongs to.
        stream_id: crate::StreamId,
        /// The body bytes.
        data: Bytes,
    },
    /// Trailers were received, ending the stream.
    Trailers {
        /// The stream the trailers belong to.
        stream_id: crate::StreamId,
        /// The trailer header map.
        trailers: HeaderMap,
    },
    /// The stream ended cleanly (body fully received, no trailers).
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

/// Tracks per-stream receive progress for event generation.
struct Tracked {
    recv: proto::OpaqueStreamRef,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// Awaiting the response head.
    Head,
    /// Streaming the response body.
    Body,
    /// Finished.
    Done,
}

/// Configures an HTTP/2 client connection before it is created.
#[derive(Clone, Debug)]
pub struct Builder {
    /// Time to keep locally reset streams around before reaping.
    reset_stream_duration: Duration,
    /// Initial maximum number of locally initiated (send) streams.
    initial_max_send_streams: usize,
    /// Initial target window size for new connections.
    initial_target_connection_window_size: Option<u32>,
    /// Maximum amount of bytes to "buffer" for writing per stream.
    max_send_buffer_size: usize,
    /// Maximum number of locally reset streams to keep at a time.
    reset_stream_max: usize,
    /// Maximum number of remotely reset streams to allow in the pending accept
    /// queue.
    pending_accept_reset_stream_max: usize,
    /// Initial `Settings` frame to send as part of the handshake.
    settings: Settings,
    /// The stream ID of the first (lowest) stream.
    stream_id: StreamId,
    /// Maximum number of locally reset streams due to protocol error across the
    /// lifetime of the connection.
    local_max_error_reset_streams: Option<usize>,
}

#[derive(Debug)]
pub(crate) struct Peer;

/// A sans-I/O HTTP/2 client connection.
///
/// See the [module documentation](self) for an overview.
pub struct Connection<B: Buf = Bytes> {
    inner: proto::Connection<Peer, B>,
    streams: proto::Streams<B, Peer>,
    tracked: HashMap<u32, Tracked>,
    events: VecDeque<Event>,
    closed: bool,
    close_err: Option<crate::Error>,
    waker: Waker,
    preface_sent: bool,
}

/// Performs the client connection handshake with default settings, returning a
/// connection ready to send requests.
///
/// The connection preface and initial `SETTINGS` frame are queued immediately;
/// call [`Connection::poll_transmit`] to obtain the bytes to write.
#[must_use]
pub fn handshake() -> Connection<Bytes> {
    Builder::new().handshake()
}

// ===== impl Builder =====

impl Builder {
    /// Returns a new client builder with default configuration values.
    #[must_use]
    pub fn new() -> Builder {
        Builder {
            max_send_buffer_size: proto::DEFAULT_MAX_SEND_BUFFER_SIZE,
            reset_stream_duration: Duration::from_secs(proto::DEFAULT_RESET_STREAM_SECS),
            reset_stream_max: proto::DEFAULT_RESET_STREAM_MAX,
            pending_accept_reset_stream_max: proto::DEFAULT_REMOTE_RESET_STREAM_MAX,
            initial_target_connection_window_size: None,
            initial_max_send_streams: usize::MAX,
            settings: Default::default(),
            stream_id: 1.into(),
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

    /// Sets the max frame size (in octets) this client is willing to receive.
    ///
    /// Must be between 16,384 and 16,777,215.
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

    /// Enables or disables server push.
    pub fn enable_push(&mut self, enabled: bool) -> &mut Self {
        self.settings.set_enable_push(enabled);
        self
    }

    /// Sets the header table size (in octets) for the HPACK encoder.
    pub fn header_table_size(&mut self, size: u32) -> &mut Self {
        self.settings.set_header_table_size(Some(size));
        self
    }

    /// Sets the first stream ID to use. Must be odd.
    pub fn initial_stream_id(&mut self, stream_id: u32) -> &mut Self {
        self.stream_id = stream_id.into();
        assert!(
            self.stream_id.is_client_initiated(),
            "stream id must be odd"
        );
        self
    }

    /// Sets the maximum send buffer size per stream (in octets).
    pub fn max_send_buffer_size(&mut self, max: usize) -> &mut Self {
        assert!(u32::try_from(max).is_ok());
        self.max_send_buffer_size = max;
        self
    }

    /// Creates a new configured client connection.
    ///
    /// The connection preface and initial `SETTINGS` frame are queued; call
    /// [`Connection::poll_transmit`] to obtain the bytes to write.
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
        // Create the codec and queue the initial SETTINGS frame, mirroring the
        // values the local endpoint advertises.
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
                next_stream_id: builder.stream_id,
                initial_max_send_streams: builder.initial_max_send_streams,
                max_send_buffer_size: builder.max_send_buffer_size,
                reset_stream_duration: builder.reset_stream_duration,
                reset_stream_max: builder.reset_stream_max,
                remote_reset_stream_max: builder.pending_accept_reset_stream_max,
                local_error_reset_streams_max: builder.local_max_error_reset_streams,
                settings: builder.settings.clone(),
            },
        );

        let streams = inner.streams().clone();
        let mut conn = Connection {
            inner,
            streams,
            tracked: HashMap::new(),
            events: VecDeque::new(),
            closed: false,
            close_err: None,
            waker: crate::noop_waker(),
            preface_sent: false,
        };

        if let Some(sz) = builder.initial_target_connection_window_size {
            conn.inner.set_target_window_size(sz);
        }

        conn
    }

    /// Initiates a new request, returning the stream ID and a [`SendStream`]
    /// for streaming the request body.
    ///
    /// If `end_stream` is `true`, the request has no body and the stream's send
    /// half is closed immediately.
    pub fn send_request(
        &mut self,
        request: Request<()>,
        end_stream: bool,
    ) -> Result<(crate::StreamId, SendStream<B>), crate::Error> {
        let (stream_ref, _is_full) = self.streams.send_request(request, end_stream, None)?;
        let id = stream_ref.stream_id();
        let opaque = stream_ref.clone_to_opaque();
        self.tracked.insert(
            id.into(),
            Tracked {
                recv: opaque,
                phase: Phase::Head,
            },
        );
        Ok((
            crate::StreamId::from_internal(id),
            SendStream::new(stream_ref),
        ))
    }

    /// Feeds bytes received from the peer into the connection.
    pub fn recv(&mut self, src: &[u8]) -> Result<(), crate::Error> {
        self.inner.recv_bytes(src);
        self.drive();
        self.take_closed_err()
    }

    /// Drains any bytes that need to be written to the peer into `dst`,
    /// returning the number of bytes written.
    pub fn poll_transmit(&mut self, dst: &mut BytesMut) -> usize {
        let mut n = 0;
        if !self.preface_sent {
            const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            dst.extend_from_slice(PREFACE);
            n += PREFACE.len();
            self.preface_sent = true;
        }
        self.drive();
        n + self.inner.poll_transmit(dst)
    }

    /// Returns the next available protocol [`Event`], if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        if self.events.is_empty() {
            self.pump();
        }
        self.events.pop_front()
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
    pub fn go_away(&mut self, reason: Reason) {
        self.inner.go_away_from_user(reason);
    }

    fn take_closed_err(&mut self) -> Result<(), crate::Error> {
        self.close_err.take().map_or(Ok(()), Err)
    }

    /// Advances the underlying protocol state machine.
    fn drive(&mut self) {
        if self.closed {
            return;
        }
        self.inner.maybe_close_connection_if_no_streams();
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

    /// Generates per-stream events from the current state.
    fn pump(&mut self) {
        self.drive();

        let waker = self.waker.clone();
        let cx = Context::from_waker(&waker);

        let ids: Vec<u32> = self.tracked.keys().copied().collect();
        for id in ids {
            loop {
                let Some(phase) = self.tracked.get(&id).map(|t| t.phase) else {
                    break;
                };
                match phase {
                    Phase::Head => {
                        let entry = self.tracked.get_mut(&id).unwrap();
                        match entry.recv.poll_response(&cx) {
                            Poll::Ready(Ok(response)) => {
                                let end = entry.recv.is_end_stream();
                                entry.phase = if end { Phase::Done } else { Phase::Body };
                                self.events.push_back(Event::Response {
                                    stream_id: crate::StreamId::from_u32(id),
                                    response,
                                    end_stream: end,
                                });
                                if end {
                                    break;
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                entry.phase = Phase::Done;
                                self.emit_stream_error(id, e);
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                    Phase::Body => {
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
                    Phase::Done => break,
                }
            }
        }

        // Drop finished streams so their state can be reclaimed.
        self.tracked.retain(|_, t| t.phase != Phase::Done);
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
        fmt.debug_struct("client::Connection")
            .finish_non_exhaustive()
    }
}

// ===== impl Peer =====

impl Peer {
    pub fn convert_send_message(
        id: StreamId,
        request: Request<()>,
        protocol: Option<Protocol>,
        end_of_stream: bool,
    ) -> Result<Headers, SendError> {
        use http::request::Parts;

        let (
            Parts {
                method,
                uri,
                headers,
                version,
                ..
            },
            (),
        ) = request.into_parts();

        let is_connect = method == Method::CONNECT;

        // Build the set pseudo header set. All requests will include `method`
        // and `path`.
        let mut pseudo = Pseudo::request(method, uri, protocol);

        if pseudo.scheme.is_none() {
            // If the scheme is not set, then there are a two options.
            //
            // 1) Authority is not set. In this case, a request was issued with
            //    a relative URI. This is permitted **only** when forwarding
            //    HTTP 1.x requests. If the HTTP version is set to 2.0, then
            //    this is an error.
            //
            // 2) Authority is set, then the HTTP method *must* be CONNECT.
            //
            // It is not possible to have a scheme but not an authority set (the
            // `http` crate does not allow it).
            //
            if pseudo.authority.is_none() {
                if version == Version::HTTP_2 {
                    return Err(UserError::MissingUriSchemeAndAuthority.into());
                }
                // This is acceptable as per the above comment. However,
                // HTTP/2 requires that a scheme is set. Since we are
                // forwarding an HTTP 1.1 request, the scheme is set to
                // "http".
                pseudo.set_scheme(uri::Scheme::HTTP);
            } else if !is_connect {
                // TODO: Error
            }
        }

        // Create the HEADERS frame
        let mut frame = Headers::new(id, pseudo, headers);

        if end_of_stream {
            frame.set_end_stream();
        }

        Ok(frame)
    }
}

impl proto::Peer for Peer {
    type Poll = Response<()>;

    const NAME: &'static str = "Client";

    fn r#dyn() -> proto::DynPeer {
        proto::DynPeer::Client
    }

    fn convert_poll_message(
        pseudo: Pseudo,
        fields: HeaderMap,
        stream_id: StreamId,
    ) -> Result<Self::Poll, Error> {
        let mut b = Response::builder();

        b = b.version(Version::HTTP_2);

        if let Some(status) = pseudo.status {
            b = b.status(status);
        }

        let mut response = match b.body(()) {
            Ok(response) => response,
            Err(_) => {
                // TODO: Should there be more specialized handling for different
                // kinds of errors
                return Err(Error::library_reset(stream_id, Reason::PROTOCOL_ERROR));
            }
        };

        *response.headers_mut() = fields;

        Ok(response)
    }
}
