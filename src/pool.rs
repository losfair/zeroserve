use std::{
    cell::RefCell,
    collections::HashMap,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};

use monoio::net::{TcpStream, UnixStream};

use crate::boringtls::BoringStream;
use crate::http::h1::H1Connection;

const MAX_POOL_PER_KEY: usize = 128;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    host: Arc<str>,
    port: u16,
    tls: bool,
}

impl PoolKey {
    pub fn new(host: String, port: u16, tls: bool) -> Self {
        Self {
            host: Arc::from(host.to_ascii_lowercase()),
            port,
            tls,
        }
    }

    pub fn unix(path: String) -> Self {
        Self {
            host: Arc::from(format!("unix:{path}")),
            port: 0,
            tls: false,
        }
    }
}

pub enum PooledConnection {
    Http(H1Connection<TcpStream>),
    Https(H1Connection<BoringStream<TcpStream>>),
    Unix(H1Connection<UnixStream>),
}

impl PooledConnection {
    fn raw_fd(&mut self) -> Option<RawFd> {
        match self {
            PooledConnection::Http(conn) => conn.io_mut().ok().map(|io| io.as_raw_fd()),
            PooledConnection::Https(conn) => conn.io_mut().ok().map(|io| io.as_raw_fd()),
            PooledConnection::Unix(conn) => conn.io_mut().ok().map(|io| io.as_raw_fd()),
        }
    }

    /// Unconsumed bytes sitting in the connection's userspace parse buffer.
    /// The idle poll below only sees the kernel receive queue, so this is the
    /// other half of the "connection is truly quiescent" check.
    fn buffered_len(&self) -> usize {
        match self {
            PooledConnection::Http(conn) => conn.buffered_len(),
            PooledConnection::Https(conn) => conn.buffered_len(),
            PooledConnection::Unix(conn) => conn.buffered_len(),
        }
    }
}

fn connection_still_idle(conn: &mut PooledConnection) -> bool {
    let Some(fd) = conn.raw_fd() else {
        return false;
    };
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    if ret < 0 {
        return false;
    }

    // A reusable backend connection is expected to be completely idle. Any
    // readable, hangup, or error event means the peer sent data or closed after
    // the connection was pooled, so reusing it would consume stale state or EOF.
    ret == 0 && pfd.revents == 0
}

struct PoolEntry {
    conn: PooledConnection,
}

pub struct ProxyPool {
    entries: HashMap<PoolKey, Vec<PoolEntry>>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn take(&mut self, key: &PoolKey) -> Option<PooledConnection> {
        let Some(entries) = self.entries.get_mut(key) else {
            return None;
        };

        let mut reusable = None;
        while let Some(mut entry) = entries.pop() {
            if connection_still_idle(&mut entry.conn) {
                reusable = Some(entry.conn);
                break;
            }
        }

        let is_empty = entries.is_empty();
        if is_empty {
            self.entries.remove(key);
        }
        reusable
    }

    pub fn put(&mut self, key: PoolKey, conn: PooledConnection) {
        if conn.buffered_len() > 0 {
            // Mid-exchange connection: reusing it would splice stale backend
            // bytes into the next request's response. Drop it instead.
            return;
        }
        let entries = self.entries.entry(key.clone()).or_default();
        if entries.len() >= MAX_POOL_PER_KEY {
            return;
        }
        entries.push(PoolEntry { conn });
    }
}

// Keep the pool thread-local since monoio sockets are !Send.
thread_local! {
    static PROXY_POOL: RefCell<ProxyPool> = RefCell::new(ProxyPool::new());
}

pub fn take_connection(key: &PoolKey) -> Option<PooledConnection> {
    PROXY_POOL.with(|pool| pool.borrow_mut().take(key))
}

pub fn return_connection(key: PoolKey, conn: PooledConnection) {
    PROXY_POOL.with(|pool| pool.borrow_mut().put(key, conn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    use monoio::net::TcpListener;

    // Explicit runtime instead of `#[monoio::test]` for the same reason as the
    // boringtls loopback test: the macro cfg-gates on a feature we don't define.
    fn run(fut: impl Future<Output = ()>) {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(fut);
    }

    async fn pooled_pair(listener: &TcpListener) -> (PoolKey, monoio::net::TcpStream) {
        let addr = listener.local_addr().unwrap();
        let client = monoio::net::TcpStream::connect(addr).await.unwrap();
        let (backend_side, _) = listener.accept().await.unwrap();
        let key = PoolKey::new("127.0.0.1".to_string(), addr.port(), false);
        return_connection(
            key.clone(),
            PooledConnection::Http(H1Connection::new(client)),
        );
        (key, backend_side)
    }

    #[test]
    fn pooled_connection_can_be_taken_once() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();

            let (key, _backend_side) = pooled_pair(&listener).await;

            assert!(take_connection(&key).is_some());
            assert!(take_connection(&key).is_none());
        });
    }

    #[test]
    fn pooled_connection_can_be_returned() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();

            let (key, _backend_side) = pooled_pair(&listener).await;

            let conn = take_connection(&key).expect("live connection should be reusable");
            return_connection(key.clone(), conn);

            assert!(take_connection(&key).is_some());
        });
    }

    #[test]
    fn closed_pooled_connection_is_not_reused() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();

            let (key, backend_side) = pooled_pair(&listener).await;
            unsafe {
                libc::shutdown(backend_side.as_raw_fd(), libc::SHUT_RDWR);
            }
            drop(backend_side);

            assert!(take_connection(&key).is_none());
        });
    }
}
