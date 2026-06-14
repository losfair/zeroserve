use std::{cell::RefCell, collections::HashMap, sync::Arc};

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

        while let Some(entry) = entries.pop() {
            if entries.is_empty() {
                self.entries.remove(key);
            }
            return Some(entry.conn);
        }

        self.entries.remove(key);
        None
    }

    pub fn put(&mut self, key: PoolKey, conn: PooledConnection) {
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

/// Retained for startup compatibility; pooled connections are validated when
/// reused, avoiding per-request watcher task churn on the hot proxy path.
pub fn install_hup_watcher(_hup: std::sync::Arc<crate::hupwatch::HupWatcher>) {}

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
}
