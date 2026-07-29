//! Cross-worker connection hand-off for shared listening sockets.
//!
//! When every worker accepts from dups of one listening socket (kernels
//! without REUSEPORT load balancing such as OpenBSD, or inherited
//! socket-activation fds), the readiness-driven accept loop is edge-triggered
//! and drains the whole backlog without yielding, so a burst of connections
//! lands on whichever worker wakes first. With keep-alive traffic that skew is
//! permanent — monoio never migrates a connection off its runtime — and the
//! overloaded worker's queueing delay shows up directly as tail latency.
//!
//! To keep workers evenly loaded, each accepted connection is assigned
//! round-robin across all workers. A connection destined for a sibling is
//! deregistered from the accepting worker's driver and its raw fd sent over a
//! channel; the sibling re-registers it with its own driver before any I/O.

use std::{
    net::SocketAddr,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures::channel::mpsc;
use monoio::net::TcpStream;

/// An accepted connection in transit between workers. Owns the fd, so a
/// connection dropped in transit (e.g. worker shutdown) is closed, not leaked.
pub struct HandoffConn {
    fd: OwnedFd,
    peer: SocketAddr,
}

impl HandoffConn {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Register the connection with the current worker's driver.
    pub fn into_stream(self) -> std::io::Result<(TcpStream, SocketAddr)> {
        let stream = TcpStream::from_std(std::net::TcpStream::from(self.fd))?;
        Ok((stream, self.peer))
    }
}

/// The distributing half of a hand-off group, held by each worker's accept
/// loop. The round-robin counter is shared by all workers of the group, so the
/// assignment is globally balanced no matter which worker wins each accept.
pub struct ConnDistributor {
    worker_id: usize,
    next: Arc<AtomicUsize>,
    senders: Vec<mpsc::UnboundedSender<HandoffConn>>,
}

impl ConnDistributor {
    /// Assign a freshly accepted connection to a worker. Returns the
    /// connection back if this worker should serve it, or `None` after handing
    /// it to a sibling.
    ///
    /// Must be called before any I/O on `stream`: extracting the fd requires
    /// sole ownership of it.
    pub fn route(&self, stream: TcpStream, peer: SocketAddr) -> Option<(TcpStream, SocketAddr)> {
        let target = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        if target == self.worker_id {
            return Some((stream, peer));
        }
        // `into_raw_fd` deregisters the fd from this worker's driver and
        // yields ownership without closing it.
        // SAFETY: the fd returned by `into_raw_fd` is open and exclusively
        // ours to manage.
        let fd = unsafe { OwnedFd::from_raw_fd(stream.into_raw_fd()) };
        match self.senders[target].unbounded_send(HandoffConn { fd, peer }) {
            Ok(()) => None,
            // The sibling's receiver is gone (worker exited); serve the
            // connection locally rather than dropping it.
            Err(err) => match err.into_inner().into_stream() {
                Ok(pair) => Some(pair),
                Err(io_err) => {
                    eprintln!("failed to reclaim handed-off connection {peer}: {io_err}");
                    None
                }
            },
        }
    }
}

/// One worker's endpoints for a listener family (HTTP or TLS): the distributor
/// used by its accept loop and the receiver for connections its siblings
/// assigned to it.
pub struct HandoffGroup {
    pub distributor: ConnDistributor,
    pub receiver: mpsc::UnboundedReceiver<HandoffConn>,
}

/// Build hand-off endpoints connecting `workers` workers all-to-all.
///
/// The channels are unbounded: an accepted connection must never be dropped,
/// and the accept rate is already bounded by the shared listen queue.
pub fn handoff_groups(workers: usize) -> Vec<HandoffGroup> {
    let (senders, receivers): (Vec<_>, Vec<_>) = (0..workers).map(|_| mpsc::unbounded()).unzip();
    let next = Arc::new(AtomicUsize::new(0));
    receivers
        .into_iter()
        .enumerate()
        .map(|(worker_id, receiver)| HandoffGroup {
            distributor: ConnDistributor {
                worker_id,
                next: next.clone(),
                senders: senders.clone(),
            },
            receiver,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use futures::StreamExt;
    use monoio::io::{AsyncReadRentExt, AsyncWriteRentExt};

    use super::*;

    /// A connection accepted on one worker's runtime must stay usable after
    /// being routed to a sibling worker's runtime.
    #[test]
    fn routed_connection_serves_on_sibling_worker() {
        let mut groups = handoff_groups(2);
        let worker1 = groups.pop().unwrap();
        let worker0 = groups.pop().unwrap();

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();

        // Worker 0 accepts both connections. Round-robin keeps the first
        // (target 0) and hands the second (target 1) to its sibling.
        let acceptor = std::thread::spawn(move || {
            crate::rt::build_runtime(None).unwrap().block_on(async {
                let listener = monoio::net::TcpListener::bind("127.0.0.1:0").unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();

                let (stream, peer) = listener.accept().await.unwrap();
                assert!(worker0.distributor.route(stream, peer).is_some());

                let (stream, peer) = listener.accept().await.unwrap();
                assert!(worker0.distributor.route(stream, peer).is_none());
            });
        });

        // Worker 1 adopts the handed-off connection and echoes on it.
        let sibling = std::thread::spawn(move || {
            crate::rt::build_runtime(None).unwrap().block_on(async {
                let mut receiver = worker1.receiver;
                let conn = receiver.next().await.unwrap();
                let (mut stream, _peer) = conn.into_stream().unwrap();
                let (res, buf) = stream.read_exact(vec![0u8; 5]).await;
                res.unwrap();
                assert_eq!(&buf, b"hello");
                let (res, _) = stream.write_all(&b"world"[..]).await;
                res.unwrap();
            });
        });

        let addr = addr_rx.recv().unwrap();
        let _kept_local = std::net::TcpStream::connect(addr).unwrap();
        let mut handed_off = std::net::TcpStream::connect(addr).unwrap();
        handed_off.write_all(b"hello").unwrap();
        let mut reply = [0u8; 5];
        handed_off.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"world");

        acceptor.join().unwrap();
        sibling.join().unwrap();
    }
}
