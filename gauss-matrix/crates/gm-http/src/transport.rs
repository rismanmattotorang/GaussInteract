// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A std-only HTTP/1.1 transport for the ingress (spec §III.B).
//!
//! [`crate::ingress::Ingress`] is the synchronous request→response core; this
//! module is the wire layer that turns it into a process listening on a socket.
//! It parses an HTTP/1.1 request off a stream into an [`ingress::Request`], calls
//! [`Ingress::handle`], and writes the [`ingress::Response`] back — no
//! dependencies, so it compiles and runs anywhere `std` does.
//!
//! It is deliberately minimal (one request per connection, no keep-alive or TLS).
//! The production deployment swaps this for an async axum/hyper front that
//! terminates TLS and multiplexes connections across a thread pool over a
//! thread-safe store; the [`Ingress`] it drives, and the request/response
//! contract, are identical.

use crate::ingress::{Ingress, Request, Response};
use crate::Method;
use gm_api::{Homeserver, MatrixError};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

/// The cap on a request body we will buffer, to bound memory on a hostile
/// `Content-Length` (a real deployment makes this configurable).
const MAX_BODY: usize = 1 << 20; // 1 MiB

/// An owned, parsed HTTP request: enough for the ingress to handle it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRequest {
    method: Method,
    target: String,
    authorization: Option<String>,
    body: String,
}

/// The result of trying to read one request off a connection.
enum Incoming {
    /// A well-formed request.
    Request(ParsedRequest),
    /// The request line/headers were malformed (answered with `400`).
    Malformed,
    /// The peer closed the connection with nothing to read.
    Closed,
}

fn parse_method(token: &str) -> Option<Method> {
    match token {
        "GET" => Some(Method::Get),
        "POST" => Some(Method::Post),
        "PUT" => Some(Method::Put),
        "DELETE" => Some(Method::Delete),
        _ => None,
    }
}

fn method_str(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

/// The reason phrase for a status code (the subset the ingress emits).
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        501 => "Not Implemented",
        _ => "OK",
    }
}

/// Read one HTTP/1.1 request: the request line, headers (we keep `Authorization`
/// and `Content-Length`), and the body.
fn read_request<R: BufRead>(reader: &mut R) -> io::Result<Incoming> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(Incoming::Closed);
    }
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next().and_then(parse_method), parts.next()) else {
        return Ok(Incoming::Malformed);
    };
    let target = target.to_owned();

    let mut content_length = 0usize;
    let mut authorization = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = header.split_once(':') {
            let (name, value) = (name.trim(), value.trim());
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.to_owned());
            }
        }
    }
    if content_length > MAX_BODY {
        return Ok(Incoming::Malformed);
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body).into_owned();

    Ok(Incoming::Request(ParsedRequest {
        method,
        target,
        authorization,
        body,
    }))
}

/// Serialise a [`Response`] as an HTTP/1.1 response (adding `Content-Length`).
fn write_response<W: Write>(writer: &mut W, resp: &Response) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {} {}\r\n",
        resp.status,
        reason(resp.status)
    )?;
    let mut wrote_length = false;
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("content-length") {
            wrote_length = true;
        }
        write!(writer, "{name}: {value}\r\n")?;
    }
    if !wrote_length {
        write!(writer, "Content-Length: {}\r\n", resp.body.len())?;
    }
    write!(writer, "\r\n")?;
    writer.write_all(resp.body.as_bytes())
}

fn bad_request() -> Response {
    // Reuse the ingress's response shape via a minimal error response.
    Response {
        status: 400,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: MatrixError::new("M_NOT_JSON", "malformed HTTP request").to_json(),
    }
}

/// Read a request from `raw`, handle it, and return the serialised HTTP response
/// bytes. The wire core, testable without a socket.
pub fn respond<H: Homeserver>(ingress: &Ingress<H>, raw: &[u8]) -> Vec<u8> {
    let mut reader = BufReader::new(raw);
    let response = match read_request(&mut reader) {
        Ok(Incoming::Request(req)) => {
            let request = Request {
                method: req.method,
                target: &req.target,
                authorization: req.authorization.as_deref(),
                body: if req.body.is_empty() {
                    None
                } else {
                    Some(&req.body)
                },
            };
            ingress.handle(&request)
        }
        Ok(Incoming::Malformed) | Ok(Incoming::Closed) => bad_request(),
        Err(_) => bad_request(),
    };
    let mut out = Vec::new();
    // Writing to a Vec is infallible.
    let _ = write_response(&mut out, &response);
    out
}

/// Serve a single connection: read one request, handle it, write the response.
pub fn serve_connection<H: Homeserver>(stream: &TcpStream, ingress: &Ingress<H>) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let response = match read_request(&mut reader)? {
        Incoming::Request(req) => {
            let request = Request {
                method: req.method,
                target: &req.target,
                authorization: req.authorization.as_deref(),
                body: if req.body.is_empty() {
                    None
                } else {
                    Some(&req.body)
                },
            };
            ingress.handle(&request)
        }
        Incoming::Malformed | Incoming::Closed => bad_request(),
    };
    let mut writer = stream;
    write_response(&mut writer, &response)?;
    // Connection-per-request: signal end-of-response by closing the write half,
    // so the client's read completes even if the caller keeps the stream alive.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    Ok(())
}

/// Accept and serve connections on `listener` forever, one at a time.
///
/// Single-threaded by design (the scaffold store is not thread-safe); the
/// production transport multiplexes across a thread pool over a thread-safe
/// store. Per-connection errors are swallowed so one bad client cannot stop the
/// server.
pub fn serve<H: Homeserver>(listener: &TcpListener, ingress: &Ingress<H>) -> io::Result<()> {
    for connection in listener.incoming() {
        let stream = connection?;
        let _ = serve_connection(&stream, ingress);
    }
    Ok(())
}

/// Render a request as HTTP/1.1 wire bytes (a tiny client, for tests/tools).
pub fn encode_request(
    method: Method,
    target: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Vec<u8> {
    let body = body.unwrap_or("");
    let mut out = format!(
        "{} {target} HTTP/1.1\r\nHost: gaussian.tech\r\n",
        method_str(method)
    );
    if let Some(auth) = authorization {
        out.push_str(&format!("Authorization: {auth}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// The outbound HTTP client: connect to `addr`, send one request, and read the
/// response, returning `(status, body)`. This is the wire side of the
/// federation *sender* — delivering a transaction to a peer's `/send/{txnId}`.
/// Connection-per-request, matching [`serve`]; production pools connections.
pub fn send_request<A: ToSocketAddrs>(
    addr: A,
    method: Method,
    target: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(&encode_request(method, target, authorization, body))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_response(&raw)
}

/// Deliver a federation `transaction` (JSON) to `addr`'s `/send/{txn_id}` with
/// the given `X-Matrix` authorization header, returning `(status, body)`.
pub fn deliver_transaction<A: ToSocketAddrs>(
    addr: A,
    txn_id: &str,
    authorization: &str,
    transaction_json: &str,
) -> io::Result<(u16, String)> {
    let target = format!("/_matrix/federation/v1/send/{txn_id}");
    send_request(
        addr,
        Method::Put,
        &target,
        Some(authorization),
        Some(transaction_json),
    )
}

/// Parse an HTTP response's status code and body.
fn parse_response(raw: &[u8]) -> io::Result<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed status line"))?;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn status_line(resp: &[u8]) -> String {
        let text = String::from_utf8_lossy(resp);
        text.lines().next().unwrap_or("").to_owned()
    }

    fn body_of(resp: &[u8]) -> String {
        let text = String::from_utf8_lossy(resp);
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
    }

    #[test]
    fn respond_serves_a_get_over_the_wire_format() {
        let ingress = Ingress::new();
        let raw = encode_request(Method::Get, "/_matrix/client/versions", None, None);
        let resp = respond(&ingress, &raw);
        assert_eq!(status_line(&resp), "HTTP/1.1 200 OK");
        assert!(String::from_utf8_lossy(&resp).contains("Content-Length:"));
        assert!(body_of(&resp).contains("\"v1.11\""));
    }

    #[test]
    fn respond_parses_a_post_body_and_authorization_header() {
        // An unauthenticated POST /login with a (bad-credential) body reaches the
        // handler: NoServer rejects the login with 403, proving body parsing.
        let ingress = Ingress::new();
        let raw = encode_request(
            Method::Post,
            "/_matrix/client/v3/login",
            None,
            Some(r#"{"type":"m.login.password","identifier":{"user":"alice"},"password":"x"}"#),
        );
        let resp = respond(&ingress, &raw);
        assert_eq!(status_line(&resp), "HTTP/1.1 403 Forbidden");
    }

    #[test]
    fn respond_propagates_the_auth_gate_for_a_missing_token() {
        let ingress = Ingress::new();
        let raw = encode_request(Method::Get, "/_matrix/client/v3/sync", None, None);
        let resp = respond(&ingress, &raw);
        assert_eq!(status_line(&resp), "HTTP/1.1 401 Unauthorized");
        assert!(body_of(&resp).contains("M_MISSING_TOKEN"));
    }

    #[test]
    fn a_malformed_request_line_is_400() {
        let ingress = Ingress::new();
        let resp = respond(&ingress, b"GIBBERISH\r\n\r\n");
        assert_eq!(status_line(&resp), "HTTP/1.1 400 Bad Request");
    }

    #[test]
    fn serves_a_real_tcp_connection() {
        // Bind an ephemeral port, serve exactly one connection on a thread, and
        // drive it with a real TcpStream — proving the socket path works.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let ingress = Ingress::new();
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&stream, &ingress).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(&encode_request(
                Method::Get,
                "/_matrix/client/versions",
                None,
                None,
            ))
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();

        assert_eq!(status_line(&response), "HTTP/1.1 200 OK");
        assert!(body_of(&response).contains("\"v1.11\""));
    }

    #[test]
    fn send_request_client_round_trips_over_tcp() {
        // Server on a thread; the outbound client (send_request) drives it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let ingress = Ingress::new();
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&stream, &ingress).unwrap();
        });

        let (status, body) =
            send_request(addr, Method::Get, "/_matrix/client/versions", None, None).unwrap();
        server.join().unwrap();

        assert_eq!(status, 200);
        assert!(body.contains("\"v1.11\""));
    }
}
