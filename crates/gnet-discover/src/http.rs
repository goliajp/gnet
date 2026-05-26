//! Minimal HTTP/1.1 server over tokio, built on httparse.
//!
//! Replaces axum/hyper for the gnet-discover control plane to keep the dep
//! footprint inside the allow-list (see memory
//! `[[feedback-gnet-0dep-self-research]]` → "Control plane 边界").
//!
//! Limitations (intentional for now):
//! - Connection: close on every response (no keep-alive).
//! - Only `Content-Length`-framed request bodies; no `chunked`.
//! - Request header buffer caps at 64 KiB; body caps at 1 MiB.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HEADER_BUF_MAX: usize = 64 * 1024;
const BODY_MAX: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] httparse::Error),
    #[error("request header too large (> {HEADER_BUF_MAX} bytes)")]
    HeaderTooLarge,
    #[error("body too large (> {BODY_MAX} bytes)")]
    BodyTooLarge,
    #[error("malformed request")]
    Malformed,
}

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub status_text: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(status: u16, status_text: &'static str, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        Self {
            status,
            status_text,
            headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            body,
        }
    }

    pub fn json<S: serde::Serialize>(body: &S) -> Self {
        match serde_json::to_vec(body) {
            Ok(bytes) => Self {
                status: 200,
                status_text: "OK",
                headers: vec![("content-type".into(), "application/json".into())],
                body: bytes,
            },
            Err(_) => Self::text(500, "Internal Server Error", "json encode failed"),
        }
    }
}

pub type Handler<S> = Arc<
    dyn Fn(Request, Arc<S>) -> Pin<Box<dyn Future<Output = Response> + Send>>
        + Send
        + Sync,
>;

/// Serve forever — accept connections, dispatch to `handler`.
pub async fn serve<S>(listener: TcpListener, state: Arc<S>, handler: Handler<S>) -> std::io::Result<()>
where
    S: Send + Sync + 'static,
{
    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = state.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, state, handler).await {
                tracing::warn!(error = %e, "connection error");
            }
        });
    }
}

async fn handle_conn<S>(
    mut stream: TcpStream,
    state: Arc<S>,
    handler: Handler<S>,
) -> std::result::Result<(), HttpError>
where
    S: Send + Sync + 'static,
{
    let req = read_request(&mut stream).await?;
    let resp = handler(req, state).await;
    write_response(&mut stream, resp).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> std::result::Result<Request, HttpError> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    let (header_len, content_length) = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(HttpError::Malformed);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > HEADER_BUF_MAX {
            return Err(HttpError::HeaderTooLarge);
        }
        let mut headers_arr = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers_arr);
        match req.parse(&buf)? {
            httparse::Status::Partial => continue,
            httparse::Status::Complete(hl) => {
                let content_length = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if content_length > BODY_MAX {
                    return Err(HttpError::BodyTooLarge);
                }
                break (hl, content_length);
            }
        }
    };

    // header re-parse to own the strings outside the borrow of buf
    let mut headers_arr = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers_arr);
    let _ = req.parse(&buf)?;
    let method = req.method.unwrap_or("").to_string();
    let path = req.path.unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                std::str::from_utf8(h.value).unwrap_or("").to_string(),
            )
        })
        .collect();

    // read body up to content_length
    let mut body = if buf.len() > header_len {
        buf[header_len..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < content_length {
        let need = content_length - body.len();
        let cap = tmp.len();
        let n = stream.read(&mut tmp[..need.min(cap)]).await?;
        if n == 0 {
            return Err(HttpError::Malformed);
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

async fn write_response(stream: &mut TcpStream, resp: Response) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256 + resp.body.len());
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", resp.status, resp.status_text).as_bytes());
    let mut saw_cl = false;
    let mut saw_conn = false;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            saw_cl = true;
        }
        if k.eq_ignore_ascii_case("connection") {
            saw_conn = true;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !saw_cl {
        out.extend_from_slice(format!("content-length: {}\r\n", resp.body.len()).as_bytes());
    }
    if !saw_conn {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&resp.body);
    stream.write_all(&out).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    fn echo_handler<S: Send + Sync + 'static>() -> Handler<S> {
        Arc::new(|req, _state| {
            Box::pin(async move {
                let body = format!(
                    "{} {}\n{}",
                    req.method,
                    req.path,
                    String::from_utf8_lossy(&req.body)
                );
                Response::text(200, "OK", body)
            })
        })
    }

    async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(());
        let handle = tokio::spawn(async move {
            let _ = serve(listener, state, echo_handler::<()>()).await;
        });
        (addr, handle)
    }

    async fn raw_request(addr: std::net::SocketAddr, raw: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(raw).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn get_request_roundtrip() {
        let (addr, _h) = spawn_echo().await;
        let resp = raw_request(addr, b"GET /hello HTTP/1.1\r\nhost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("GET /hello"));
    }

    #[tokio::test]
    async fn post_with_body() {
        let (addr, _h) = spawn_echo().await;
        let resp = raw_request(
            addr,
            b"POST /x HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello",
        )
        .await;
        assert!(resp.contains("POST /x"));
        assert!(resp.ends_with("hello"));
    }

    #[tokio::test]
    async fn json_response_shape() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler: Handler<()> = Arc::new(|_req, _state| {
            Box::pin(async move {
                let v = serde_json::json!({"a": 1, "b": "two"});
                Response::json(&v)
            })
        });
        let _h = tokio::spawn(async move {
            let _ = serve(listener, Arc::new(()), handler).await;
        });
        let resp = raw_request(addr, b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await;
        assert!(resp.contains("content-type: application/json"));
        assert!(resp.contains("\"a\":1"));
    }
}
