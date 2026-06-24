//! End-to-end smoke tests for the sans-I/O client/server connections.
//!
//! These drive a client and a server purely through in-memory byte buffers,
//! exercising the `recv` / `poll_transmit` / `poll_event` API with no real I/O.

use bytes::{Bytes, BytesMut};
use h2::{client, server};
use http::{Request, Response};

/// Pump all currently-available bytes from `from` into `to`, returning the
/// number of bytes transferred.
macro_rules! pump {
    ($from:expr => $to:expr) => {{
        let mut buf = BytesMut::new();
        $from.poll_transmit(&mut buf);
        let n = buf.len();
        if n > 0 {
            $to.recv(&buf).expect("recv failed");
        }
        n
    }};
}

#[test]
fn get_request_no_body() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    // Client sends a simple GET with no body.
    let request = Request::get("https://example.com/")
        .body(())
        .unwrap();
    let (_id, _body) = client.send_request(request, true).unwrap();

    // Exchange bytes until both sides settle.
    for _ in 0..8 {
        pump!(client => server);
        pump!(server => client);
    }

    // Server should see the request.
    let mut saw_request = None;
    while let Some(ev) = server.poll_event() {
        if let server::Event::Request {
            stream_id,
            request,
            end_stream,
        } = ev
        {
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().path(), "/");
            assert!(end_stream);
            saw_request = Some(stream_id);
        }
    }
    let server_stream = saw_request.expect("server did not receive request");

    // Server responds 200, no body.
    let response = Response::builder().status(200).body(()).unwrap();
    server
        .send_response(server_stream, response, true)
        .unwrap();

    for _ in 0..8 {
        pump!(server => client);
        pump!(client => server);
    }

    // Client should see the response.
    let mut saw_response = false;
    while let Some(ev) = client.poll_event() {
        if let client::Event::Response {
            response,
            end_stream,
            ..
        } = ev
        {
            assert_eq!(response.status(), 200);
            assert!(end_stream);
            saw_response = true;
        }
    }
    assert!(saw_response, "client did not receive response");
}

#[test]
fn request_and_response_with_body() {
    let mut client = client::Builder::new().handshake::<Bytes>();
    let mut server = server::Builder::new().handshake::<Bytes>();

    let request = Request::post("https://example.com/echo")
        .body(())
        .unwrap();
    let (cid, mut send_body) = client.send_request(request, false).unwrap();
    send_body
        .send_data(Bytes::from_static(b"ping"), true)
        .unwrap();

    for _ in 0..8 {
        pump!(client => server);
        pump!(server => client);
    }

    // Collect server events: a request followed by body data.
    let mut server_stream = None;
    let mut server_body = Vec::new();
    let mut server_end = false;
    loop {
        let mut progressed = false;
        while let Some(ev) = server.poll_event() {
            progressed = true;
            match ev {
                server::Event::Request { stream_id, .. } => server_stream = Some(stream_id),
                server::Event::Data { data, .. } => server_body.extend_from_slice(&data),
                server::Event::StreamEnd { .. } => server_end = true,
                _ => {}
            }
        }
        pump!(client => server);
        if !progressed {
            break;
        }
    }

    assert_eq!(&server_body, b"ping");
    assert!(server_end);
    let server_stream = server_stream.expect("no request");

    // Server replies with a body.
    let response = Response::builder().status(200).body(()).unwrap();
    server.send_response(server_stream, response, false).unwrap();
    server
        .send_data(server_stream, Bytes::from_static(b"pong"), true)
        .unwrap();

    for _ in 0..8 {
        pump!(server => client);
        pump!(client => server);
    }

    let mut client_body = Vec::new();
    let mut client_status = None;
    while let Some(ev) = client.poll_event() {
        match ev {
            client::Event::Response { response, .. } => client_status = Some(response.status()),
            client::Event::Data { data, .. } => client_body.extend_from_slice(&data),
            _ => {}
        }
    }

    assert_eq!(client_status, Some(http::StatusCode::OK));
    assert_eq!(&client_body, b"pong");
    let _ = cid;
}
