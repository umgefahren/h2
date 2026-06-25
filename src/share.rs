use crate::frame::Reason;
use crate::proto::{self, WindowSize};

use bytes::Buf;
use http::HeaderMap;

/// Sends the body stream and trailers to the remote peer.
///
/// # Overview
///
/// A `SendStream` is returned by [`client::Connection::send_request`] once a
/// request has been initiated. It is used to stream the message body and send
/// the message trailers, and to manage outbound flow control. The server sends
/// response bodies through the connection directly (see
/// [`server::Connection::send_data`]).
///
/// If a `SendStream` is dropped without explicitly closing the send stream, a
/// `RST_STREAM` frame will be sent. This essentially cancels the request /
/// response exchange.
///
/// The ways to explicitly close the send stream are:
///
/// * Set `end_stream` to true when calling
///   [`send_request`][crate::client::Connection::send_request] or
///   [`send_data`](SendStream::send_data).
/// * Send trailers with [`send_trailers`](SendStream::send_trailers).
/// * Explicitly reset the stream with [`send_reset`](SendStream::send_reset).
///
/// # Flow control
///
/// In HTTP/2, data cannot be sent to the remote peer unless there is available
/// window capacity on both the stream and the connection. When a data frame is
/// sent, both the stream window and the connection window are decremented. When
/// the stream level window reaches zero, no further data can be sent on that
/// stream. When the connection level window reaches zero, no further data can
/// be sent on any stream for that connection.
///
/// When the remote peer is ready to receive more data, it sends `WINDOW_UPDATE`
/// frames. These frames increment the windows.
///
/// The caller can inspect the currently available capacity with
/// [`capacity`](SendStream::capacity) and express intent to send a given amount
/// with [`reserve_capacity`](SendStream::reserve_capacity). If the caller calls
/// [`send_data`](SendStream::send_data) with more data than there is capacity
/// for, the excess is buffered until capacity becomes available.
///
/// **NOTE**: There is no bound on the amount of data that the library will
/// buffer. If you are sending large amounts of data, you really should hook
/// into the flow control lifecycle. Otherwise, you risk using up significant
/// amounts of memory.
///
/// [`client::Connection::send_request`]: crate::client::Connection::send_request
/// [`server::Connection::send_data`]: crate::server::Connection::send_data
#[derive(Debug)]
pub struct SendStream<B> {
    inner: proto::StreamRef<B>,
}

/// A stream identifier, as described in [Section 5.1.1] of RFC 7540.
///
/// Streams are identified with an unsigned 31-bit integer. Streams
/// initiated by a client MUST use odd-numbered stream identifiers; those
/// initiated by the server MUST use even-numbered stream identifiers.  A
/// stream identifier of zero (0x0) is used for connection control
/// messages; the stream identifier of zero cannot be used to establish a
/// new stream.
///
/// [Section 5.1.1]: https://tools.ietf.org/html/rfc7540#section-5.1.1
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct StreamId(u32);

impl From<StreamId> for u32 {
    fn from(src: StreamId) -> Self {
        src.0
    }
}

// ===== impl SendStream =====

impl<B: Buf> SendStream<B> {
    pub(crate) fn new(inner: proto::StreamRef<B>) -> Self {
        SendStream { inner }
    }

    /// Requests capacity to send data.
    ///
    /// This function is used to express intent to send data. This requests
    /// connection level capacity. Once the capacity is available, it is
    /// assigned to the stream and not reused by other streams.
    ///
    /// The `capacity` argument is the **total** amount of requested capacity.
    /// Sequential calls to `reserve_capacity` are *not* additive; the last call
    /// wins. Calling with a lower value than is currently assigned returns the
    /// excess to the connection.
    ///
    /// See [Flow control](SendStream#flow-control) for an overview of how send
    /// flow control works.
    pub fn reserve_capacity(&mut self, capacity: usize) {
        // TODO: Check for overflow
        self.inner.reserve_capacity(capacity as WindowSize)
    }

    /// Returns the stream's current send capacity.
    ///
    /// This allows the caller to check the current amount of available capacity
    /// before sending data.
    pub fn capacity(&self) -> usize {
        self.inner.capacity() as usize
    }

    /// Sends a single data frame to the remote peer.
    ///
    /// This function may be called repeatedly as long as `end_stream` is set to
    /// `false`. Setting `end_stream` to `true` sets the end stream flag on the
    /// data frame. Any further calls to `send_data` or `send_trailers` will
    /// return an [`Error`](crate::Error).
    ///
    /// `send_data` can be called without reserving capacity. In this case, the
    /// data is buffered and the capacity is implicitly requested. Once the
    /// capacity becomes available, the data is flushed to the connection.
    /// However, this buffering is unbounded.
    pub fn send_data(&mut self, data: B, end_stream: bool) -> Result<(), crate::Error> {
        self.inner.send_data(data, end_stream).map_err(Into::into)
    }

    /// Sends trailers to the remote peer.
    ///
    /// Sending trailers implicitly closes the send stream. Once the send stream
    /// is closed, no more data can be sent.
    pub fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), crate::Error> {
        self.inner.send_trailers(trailers).map_err(Into::into)
    }

    /// Resets the stream.
    ///
    /// This cancels the request / response exchange. If the response has not
    /// yet been received, the peer is notified with a `RST_STREAM` frame.
    pub fn send_reset(&mut self, reason: Reason) {
        self.inner.send_reset(reason)
    }

    /// Returns the stream ID of this `SendStream`.
    ///
    /// # Panics
    ///
    /// If the lock on the stream store has been poisoned.
    pub fn stream_id(&self) -> StreamId {
        StreamId::from_internal(self.inner.stream_id())
    }
}

// ===== impl StreamId =====

impl StreamId {
    pub(crate) fn from_internal(id: crate::frame::StreamId) -> Self {
        StreamId(id.into())
    }

    pub(crate) fn from_u32(id: u32) -> Self {
        StreamId(id)
    }

    /// Returns the `u32` corresponding to this `StreamId`
    ///
    /// # Note
    ///
    /// This is the same as the `From<StreamId>` implementation, but
    /// included as an inherent method because that implementation doesn't
    /// appear in rustdocs, as well as a way to force the type instead of
    /// relying on inference.
    pub fn as_u32(&self) -> u32 {
        (*self).into()
    }
}
