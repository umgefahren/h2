mod error;
mod framed_read;
mod framed_write;

pub use self::error::{SendError, UserError};

use self::framed_read::FramedRead;
use self::framed_write::FramedWrite;

use crate::frame::{self, Data, Frame};
use crate::proto::Error;

use bytes::{Buf, BytesMut};
use std::task::Poll;

use std::io;

/// A sans-I/O HTTP/2 frame codec.
///
/// Bytes received from the peer are fed in with [`Codec::recv`] and decoded
/// frames are produced by [`Codec::next_frame`]. Frames to send are staged with
/// [`Codec::buffer`] and the resulting wire bytes are drained with
/// [`Codec::flush_into`]. The codec never performs I/O itself.
#[derive(Debug)]
pub struct Codec<B> {
    /// Inbound frame decoder.
    read: FramedRead,

    /// Outbound frame encoder.
    write: FramedWrite<B>,

    /// Encoded bytes ready to be written to the peer.
    out: BytesMut,
}

impl<B> Codec<B>
where
    B: Buf,
{
    /// Returns a new `Codec` with the default max frame size
    #[inline]
    pub fn new() -> Self {
        Self::with_max_recv_frame_size(frame::DEFAULT_MAX_FRAME_SIZE as usize)
    }

    /// Returns a new `Codec` with the given maximum frame size
    pub fn with_max_recv_frame_size(max_frame_size: usize) -> Self {
        let mut read = FramedRead::new();
        // Use FramedRead's method since it checks the value is within range.
        read.set_max_frame_size(max_frame_size);

        Codec {
            read,
            write: FramedWrite::new(),
            out: BytesMut::new(),
        }
    }
}

impl<B> Default for Codec<B>
where
    B: Buf,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B> Codec<B> {
    /// Updates the max received frame size.
    ///
    /// The change takes effect the next time a frame is decoded. In other
    /// words, if a frame is currently in process of being decoded with a frame
    /// size greater than `val` but less than the max frame size in effect
    /// before calling this function, then the frame will be allowed.
    #[inline]
    pub fn set_max_recv_frame_size(&mut self, val: usize) {
        self.read.set_max_frame_size(val);
    }

    /// Returns the current max received frame size setting.
    ///
    /// This is the largest size this codec will accept from the wire. Larger
    /// frames will be rejected.
    #[cfg(feature = "unstable")]
    #[inline]
    pub fn max_recv_frame_size(&self) -> usize {
        self.read.max_frame_size()
    }

    /// Returns the max frame size that can be sent to the peer.
    pub fn max_send_frame_size(&self) -> usize {
        self.write.max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_send_frame_size(&mut self, val: usize) {
        self.write.set_max_frame_size(val);
    }

    /// Set the peer's header table size size.
    pub fn set_send_header_table_size(&mut self, val: usize) {
        self.write.set_header_table_size(val);
    }

    /// Set the decoder header table size size.
    pub fn set_recv_header_table_size(&mut self, val: usize) {
        self.read.set_header_table_size(val);
    }

    /// Set the max header list size that can be received.
    pub fn set_max_recv_header_list_size(&mut self, val: usize) {
        self.read.set_max_header_list_size(val);
    }

    /// Takes the data payload value that was fully written to the socket
    pub(crate) fn take_last_data_frame(&mut self) -> Option<Data<B>> {
        self.write.take_last_data_frame()
    }
}

// ===== Sans-I/O read side =====

impl<B> Codec<B> {
    /// Append bytes received from the peer to the decode buffer.
    pub fn recv(&mut self, src: &[u8]) {
        self.read.recv(src);
    }

    /// Decode the next frame, if a complete one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        self.read.next_frame()
    }
}

// ===== Sans-I/O write side =====

impl<B> Codec<B>
where
    B: Buf,
{
    /// Returns `true` when the codec can buffer another frame.
    pub fn has_capacity(&self) -> bool {
        self.write.has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `has_capacity` (or `poll_ready`) must be checked first to ensure that a
    /// frame may be accepted.
    ///
    /// TODO: Rename this to avoid conflicts with `Sink::buffer`
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        self.write.buffer(item)
    }

    /// Drain any encoded frame bytes into the internal output buffer.
    fn drain_to_out(&mut self) {
        if self.write.has_pending() {
            self.write.flush_into(&mut self.out);
        }
    }

    /// Returns `true` when there are encoded bytes waiting to be transmitted.
    pub fn wants_transmit(&mut self) -> bool {
        self.drain_to_out();
        !self.out.is_empty()
    }

    /// Move all pending wire bytes into `dst`, returning the number of bytes
    /// written.
    pub fn flush_into(&mut self, dst: &mut BytesMut) -> usize {
        self.drain_to_out();
        let n = self.out.len();
        if n > 0 {
            dst.unsplit(std::mem::take(&mut self.out));
        }
        n
    }

    /// Take all pending wire bytes as a single buffer.
    pub fn take_transmit(&mut self) -> BytesMut {
        self.drain_to_out();
        std::mem::take(&mut self.out)
    }
}

// ===== Poll-shaped adapters =====
//
// These keep the internal protocol state machine (which is structured around
// `Poll`) unchanged. Because the codec only ever reads from and writes to
// in-memory buffers, write readiness is always satisfied immediately and the
// read side simply reports `Pending` when more bytes are required. No waker is
// ever registered.

impl<B> Codec<B>
where
    B: Buf,
{
    /// Always ready: buffering writes to memory. Flushes any pending frame data
    /// out first to restore encoder capacity.
    pub fn poll_ready(&mut self, _cx: &mut std::task::Context) -> Poll<io::Result<()>> {
        if !self.write.has_capacity() {
            self.drain_to_out();
        }
        Poll::Ready(Ok(()))
    }

    /// Drain buffered frame data into the output buffer. Always succeeds.
    pub fn flush(&mut self, _cx: &mut std::task::Context) -> Poll<io::Result<()>> {
        self.drain_to_out();
        Poll::Ready(Ok(()))
    }

    /// Nothing to shut down for an in-memory codec; just flush.
    pub fn shutdown(&mut self, _cx: &mut std::task::Context) -> Poll<io::Result<()>> {
        self.drain_to_out();
        Poll::Ready(Ok(()))
    }
}

impl<B> Codec<B> {
    /// Poll-shaped frame decoder: `Pending` means "need more bytes".
    pub fn poll_next(
        &mut self,
        _cx: &mut std::task::Context,
    ) -> Poll<Option<Result<Frame, Error>>> {
        match self.read.next_frame() {
            Ok(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Ok(None) => Poll::Pending,
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}
