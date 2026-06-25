//! A self-contained demonstration of the sans-I/O HTTP/2 API.
//!
//! A client and a server are driven entirely through in-memory byte buffers —
//! there is no socket, no TLS, and no async runtime. This is exactly how you
//! would wire the connections to a real (possibly kTLS) transport: read bytes
//! and call `recv`, then call `poll_transmit` and write the bytes back out.
//!
//! Run with: `cargo run --example sansio`

use bytes::{Bytes, BytesMut};
use h2::{client, server};
use http::{Request, Response};

/// Move all pending outbound bytes from one endpoint into the other.
fn pump<F>(label: &str, mut take: F, recv: &mut dyn FnMut(&[u8]))
where
    F: FnMut(&mut BytesMut),
{
    let mut buf = BytesMut::new();
    take(&mut buf);
    if !buf.is_empty() {
        println!("  {label}: {} bytes on the wire", buf.len());
        recv(&buf);
    }
}

fn main() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    // ---- Client initiates a request with a body --------------------------
    let request = Request::post("https://example.com/echo").body(()).unwrap();
    let (stream_id, mut body) = client.send_request(request, false).unwrap();
    body.send_data(Bytes::from_static(b"hello, server"), true)
        .unwrap();
    println!("client -> sent request on stream {}", stream_id.as_u32());

    // ---- Shuttle bytes back and forth ------------------------------------
    for _ in 0..8 {
        pump(
            "client->server",
            |b| {
                client.poll_transmit(b);
            },
            &mut |bytes| {
                server.recv(bytes).unwrap();
            },
        );
        pump(
            "server->client",
            |b| {
                server.poll_transmit(b);
            },
            &mut |bytes| {
                client.recv(bytes).unwrap();
            },
        );

        // ---- Server side: handle requests --------------------------------
        while let Some(event) = server.poll_event() {
            match event {
                server::Event::Request {
                    stream_id, request, ..
                } => {
                    println!("server <- request: {} {}", request.method(), request.uri());
                    let response = Response::builder().status(200).body(()).unwrap();
                    server.send_response(stream_id, response, false).unwrap();
                    server
                        .send_data(stream_id, Bytes::from_static(b"hello, client"), true)
                        .unwrap();
                }
                server::Event::Data { data, .. } => {
                    println!("server <- body: {:?}", String::from_utf8_lossy(&data));
                }
                _ => {}
            }
        }

        // ---- Client side: handle responses -------------------------------
        while let Some(event) = client.poll_event() {
            match event {
                client::Event::Response { response, .. } => {
                    println!("client <- response: {}", response.status());
                }
                client::Event::Data { data, .. } => {
                    println!("client <- body: {:?}", String::from_utf8_lossy(&data));
                }
                _ => {}
            }
        }
    }

    println!("done");
}
