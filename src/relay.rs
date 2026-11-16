//! Bidirectional byte copy with an idle timeout.

use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep};

const BUFFER_SIZE: usize = 16 * 1024;

/// Bytes copied in each direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Transferred {
    pub sent: u64,
    pub received: u64,
}

/// Copies bytes between `client` and `upstream` until both directions are closed.
///
/// When one side stops sending, the write half of the other side is shut down
/// (TCP half-close) and the remaining direction keeps flowing. The connection is
/// dropped if no byte moves in either direction for `idle_timeout`.
pub async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
) -> Result<Transferred> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let mut to_upstream = vec![0u8; BUFFER_SIZE];
    let mut to_client = vec![0u8; BUFFER_SIZE];
    let mut client_open = true;
    let mut upstream_open = true;
    let mut transferred = Transferred::default();

    let idle = sleep(idle_timeout);
    tokio::pin!(idle);

    while client_open || upstream_open {
        // Reads are cancel safe, so losing a branch of `select!` never drops data.
        tokio::select! {
            read = client_read.read(&mut to_upstream), if client_open => {
                let n = read?;
                if n == 0 {
                    client_open = false;
                    let _ = upstream_write.shutdown().await;
                } else {
                    upstream_write.write_all(&to_upstream[..n]).await?;
                    transferred.sent += n as u64;
                }
            }
            read = upstream_read.read(&mut to_client), if upstream_open => {
                let n = read?;
                if n == 0 {
                    upstream_open = false;
                    let _ = client_write.shutdown().await;
                } else {
                    client_write.write_all(&to_client[..n]).await?;
                    transferred.received += n as u64;
                }
            }
            () = &mut idle => bail!("idle for {}", humantime::format_duration(idle_timeout)),
        }

        idle.as_mut().reset(Instant::now() + idle_timeout);
    }

    Ok(transferred)
}
