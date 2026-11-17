//! Bidirectional byte copy with an idle timeout.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use prometheus_client::metrics::counter::Counter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until};

use crate::metrics::TransferCounters;

const BUFFER_SIZE: usize = 16 * 1024;

/// Bytes copied in each direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Transferred {
    pub sent: u64,
    pub received: u64,
}

/// Copies bytes between `client` and `upstream` until both directions are closed.
///
/// Each direction runs on its own, so a peer that stops reading only stalls the
/// direction that writes to it. When one side stops sending, the write half of
/// the other side is shut down (TCP half-close) and the remaining direction keeps
/// flowing. The connection is dropped if no byte is read or written in either
/// direction for `idle_timeout`, including while a write is stuck on a full
/// socket buffer.
///
/// `counters` are bumped as bytes move, so long-lived connections show up in
/// metrics while they are still open.
pub async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
    counters: &TransferCounters,
) -> Result<Transferred> {
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let activity = Activity::new();

    let sent = copy(client_read, upstream_write, &counters.sent, &activity);
    let received = copy(upstream_read, client_write, &counters.received, &activity);

    tokio::select! {
        result = async { tokio::try_join!(sent, received) } => {
            let (sent, received) = result?;
            Ok(Transferred { sent, received })
        }
        () = activity.idle_for(idle_timeout) => {
            bail!("idle for {}", humantime::format_duration(idle_timeout))
        }
    }
}

/// Copies `reader` into `writer` until `reader` ends, then shuts `writer` down.
/// Returns the number of bytes copied.
async fn copy(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    counter: &Counter,
    activity: &Activity,
) -> io::Result<u64> {
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total = 0;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        activity.touch();

        // Partial writes count as activity, so a slow but live reader is not
        // mistaken for an idle one.
        let mut pending = &buf[..n];
        while !pending.is_empty() {
            let written = writer.write(pending).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            activity.touch();
            pending = &pending[written..];
            total += written as u64;
            counter.inc_by(written as u64);
        }
    }
}

/// When a byte last moved in either direction.
///
/// An atomic rather than a `Cell` because the relay future must be `Send`.
struct Activity {
    start: Instant,
    /// Nanoseconds after `start`.
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Relaxed);
    }

    /// Completes once nothing has moved for `limit`.
    async fn idle_for(&self, limit: Duration) {
        loop {
            let last = self.start + Duration::from_nanos(self.last.load(Ordering::Relaxed));
            let deadline = last + limit;
            if Instant::now() >= deadline {
                return;
            }
            sleep_until(deadline).await;
        }
    }
}
