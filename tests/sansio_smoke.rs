//! End-to-end smoke tests for the sans-I/O client/server connections.
//!
//! These drive a client and a server purely through in-memory byte buffers,
//! exercising the `recv` / `poll_transmit` / `poll_event` API with no real I/O.

use bytes::{Bytes, BytesMut};
use h2::{client, server};
use http::{HeaderMap, Request, Response};

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

/// Shuttle bytes between a client and server until neither has more to send.
fn settle(client: &mut client::Connection, server: &mut server::Connection) {
    for _ in 0..16 {
        let c = pump!(client => server);
        let s = pump!(server => client);
        if c == 0 && s == 0 {
            break;
        }
    }
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

#[test]
fn request_headers_round_trip() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    let request = Request::get("https://example.com/resource")
        .header("x-custom", "value-123")
        .header("accept", "text/plain")
        .body(())
        .unwrap();
    client.send_request(request, true).unwrap();

    settle(&mut client, &mut server);

    let mut got = None;
    while let Some(ev) = server.poll_event() {
        if let server::Event::Request { request, .. } = ev {
            got = Some(request);
        }
    }
    let request = got.expect("server did not receive request");
    assert_eq!(request.headers().get("x-custom").unwrap(), "value-123");
    assert_eq!(request.headers().get("accept").unwrap(), "text/plain");
    assert_eq!(request.uri().path(), "/resource");
}

#[test]
fn response_with_trailers() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    client
        .send_request(Request::get("https://example.com/").body(()).unwrap(), true)
        .unwrap();
    settle(&mut client, &mut server);

    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let server::Event::Request { stream_id, .. } = ev {
            server_stream = Some(stream_id);
        }
    }
    let server_stream = server_stream.unwrap();

    server
        .send_response(server_stream, Response::builder().status(200).body(()).unwrap(), false)
        .unwrap();
    server
        .send_data(server_stream, Bytes::from_static(b"chunk"), false)
        .unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    server.send_trailers(server_stream, trailers).unwrap();

    settle(&mut client, &mut server);

    let mut body = Vec::new();
    let mut got_trailers = None;
    while let Some(ev) = client.poll_event() {
        match ev {
            client::Event::Data { data, .. } => body.extend_from_slice(&data),
            client::Event::Trailers { trailers, .. } => got_trailers = Some(trailers),
            _ => {}
        }
    }
    assert_eq!(&body, b"chunk");
    let trailers = got_trailers.expect("client did not receive trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

#[test]
fn server_resets_stream() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    // Open a stream but leave it half-open (no end_stream) awaiting a response.
    client
        .send_request(Request::get("https://example.com/").body(()).unwrap(), false)
        .unwrap();
    settle(&mut client, &mut server);

    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let server::Event::Request { stream_id, .. } = ev {
            server_stream = Some(stream_id);
        }
    }
    let server_stream = server_stream.unwrap();

    // Server refuses the request.
    server.reset_stream(server_stream, h2::Reason::REFUSED_STREAM);
    settle(&mut client, &mut server);

    let mut reset_reason = None;
    while let Some(ev) = client.poll_event() {
        if let client::Event::Reset { reason, .. } = ev {
            reset_reason = Some(reason);
        }
    }
    assert_eq!(reset_reason, Some(h2::Reason::REFUSED_STREAM));
}

#[test]
fn multiple_concurrent_streams() {
    let mut client = client::handshake();
    let mut server = server::handshake();

    let (id_a, _) = client
        .send_request(Request::get("https://example.com/a").body(()).unwrap(), true)
        .unwrap();
    let (id_b, _) = client
        .send_request(Request::get("https://example.com/b").body(()).unwrap(), true)
        .unwrap();
    assert_ne!(id_a.as_u32(), id_b.as_u32());

    settle(&mut client, &mut server);

    // Server should observe two distinct requests; respond to each.
    let mut paths = Vec::new();
    let mut server_streams = Vec::new();
    while let Some(ev) = server.poll_event() {
        if let server::Event::Request {
            stream_id, request, ..
        } = ev
        {
            paths.push(request.uri().path().to_string());
            server_streams.push(stream_id);
        }
    }
    assert_eq!(server_streams.len(), 2);
    paths.sort();
    assert_eq!(paths, vec!["/a".to_string(), "/b".to_string()]);

    for s in server_streams {
        server
            .send_response(s, Response::builder().status(204).body(()).unwrap(), true)
            .unwrap();
    }

    settle(&mut client, &mut server);

    let mut responses = 0;
    while let Some(ev) = client.poll_event() {
        if let client::Event::Response { response, .. } = ev {
            assert_eq!(response.status(), 204);
            responses += 1;
        }
    }
    assert_eq!(responses, 2);
}
