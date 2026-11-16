//! Minimal HTTP/1.1 backend for benchmarks.
//!
//! Answers every request with a fixed 2-byte body and supports keep-alive, so
//! the backend is never the bottleneck when measuring strait.
//!
//! Usage: cargo run --release --example bench_backend -- 127.0.0.1:9301

use std::env;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9301".into());
    let listener = TcpListener::bind(&addr).await?;
    println!("bench backend listening on {addr}");

    loop {
        let (socket, _) = listener.accept().await?;
        socket.set_nodelay(true)?;
        tokio::spawn(serve(socket));
    }
}

/// Answers one response per request head (`\r\n\r\n`) until the client closes,
/// or until a request asks for `Connection: close`.
/// Requests carry no body in the benchmarks, so the head is the whole request.
async fn serve(mut socket: TcpStream) {
    let mut buf = vec![0u8; 8192];
    let mut pending = 0;

    loop {
        let Ok(n) = socket.read(&mut buf[pending..]).await else {
            return;
        };
        if n == 0 {
            return;
        }
        pending += n;

        let mut start = 0;
        while let Some(end) = find_head_end(&buf[start..pending]) {
            if socket.write_all(RESPONSE).await.is_err() {
                return;
            }
            if wants_close(&buf[start..start + end]) {
                return;
            }
            start += end;
        }

        buf.copy_within(start..pending, 0);
        pending -= start;
        if pending == buf.len() {
            return;
        }
    }
}

fn wants_close(head: &[u8]) -> bool {
    head.to_ascii_lowercase()
        .windows(17)
        .any(|window| window == b"connection: close")
}

fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}
