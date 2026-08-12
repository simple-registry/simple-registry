use std::{fmt::Debug, io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use angos_backoff::Backoff;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    command::server::{ServerContext, error::Error, serve_request},
    configuration::listeners::ListenerBaseConfig,
    identity::RequestScheme,
};

pub mod insecure;
pub mod tls;

pub struct HandshakeResult<S> {
    pub stream: S,
    pub peer_certificate: Option<Vec<u8>>,
}

/// The per-connection deadlines: how long the handshake may take, the
/// wall-clock request-processing timeout, and the grace period allowed for the
/// in-flight request to drain after it fires.
#[derive(Clone, Copy, Debug)]
pub struct RequestTimeouts {
    pub handshake: Duration,
    pub query: Duration,
    pub grace: Duration,
}

impl RequestTimeouts {
    pub fn from_config(base: &ListenerBaseConfig) -> Self {
        Self {
            handshake: Duration::from_secs(base.handshake_timeout.get()),
            query: Duration::from_secs(base.query_timeout.get()),
            grace: Duration::from_secs(base.query_timeout_grace_period.get()),
        }
    }
}

/// Paced by consecutive accept failures so a listener that cannot hand out
/// descriptors does not spin the loop at full speed until it recovers.
const ACCEPT_BACKOFF: Backoff =
    Backoff::exponential(Duration::from_millis(50), Duration::from_secs(1));

#[async_trait]
pub trait Connector: Send + Sync {
    type Stream: Unpin + AsyncWrite + AsyncRead + Send + Debug + 'static;

    async fn handshake(
        &self,
        tcp: TcpStream,
        remote_address: SocketAddr,
    ) -> Option<HandshakeResult<Self::Stream>>;

    fn label(&self) -> &'static str;

    fn scheme(&self) -> RequestScheme;
}

/// The shared listener shell: a bound address plus a hot-swappable context and
/// timeouts, driving connections through a [`Connector`] that supplies the
/// per-scheme handshake. TLS and non-TLS listeners are the same shell over a
/// different connector, so the shape lives here once.
pub struct Listener<C: Connector> {
    binding_address: SocketAddr,
    connector: Arc<C>,
    context: ArcSwap<ServerContext>,
    timeouts: ArcSwap<RequestTimeouts>,
}

impl<C: Connector + 'static> Listener<C> {
    /// Assemble the shell around `connector`, deriving the bind address and
    /// timeouts from `base`.
    pub fn build(base: &ListenerBaseConfig, connector: C, context: ServerContext) -> Self {
        Self {
            binding_address: SocketAddr::new(base.bind_address, base.port),
            connector: Arc::new(connector),
            context: ArcSwap::from_pointee(context),
            timeouts: ArcSwap::from_pointee(RequestTimeouts::from_config(base)),
        }
    }

    /// Swap in a freshly-built server context on a non-listener config reload.
    pub fn store_context(&self, context: ServerContext) {
        self.context.store(Arc::new(context));
    }

    /// Swap in the per-connection timeouts from an updated base config.
    pub fn store_timeouts(&self, base: &ListenerBaseConfig) {
        self.timeouts
            .store(Arc::new(RequestTimeouts::from_config(base)));
    }

    pub async fn shutdown(&self) {
        self.context.load().shutdown().await;
    }

    pub async fn serve(&self) -> Result<(), Error> {
        let listener = build_listener(self.binding_address).await?;
        accept_loop(listener, &self.connector, &self.context, &self.timeouts).await
    }

    #[cfg(test)]
    pub fn current_context(&self) -> arc_swap::Guard<Arc<ServerContext>> {
        self.context.load()
    }

    #[cfg(test)]
    pub fn current_timeouts(&self) -> arc_swap::Guard<Arc<RequestTimeouts>> {
        self.timeouts.load()
    }
}

pub async fn accept_loop<C: Connector + 'static>(
    listener: TcpListener,
    connector: &Arc<C>,
    context: &ArcSwap<ServerContext>,
    timeouts: &ArcSwap<RequestTimeouts>,
) -> Result<(), Error> {
    let binding_address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            return Err(Error::Initialization(format!(
                "Failed to read the address of a bound listener: {error}"
            )));
        }
    };
    info!("Listening on {} ({})", binding_address, connector.label());
    let mut consecutive_failures = 0;

    loop {
        debug!("Waiting for incoming connection");
        let (tcp, remote_address) = match listener.accept().await {
            Ok(accepted) => {
                consecutive_failures = 0;
                accepted
            }
            // A client gone between the SYN and the accept costs only its own
            // connection, so the next one is taken immediately.
            Err(error) if error.kind() == ErrorKind::ConnectionAborted => continue,
            // Everything else is transient too often to kill the server for:
            // an exhausted descriptor table clears once connections close.
            Err(error) => {
                warn!("Failed to accept a connection on {binding_address}: {error}");
                sleep(ACCEPT_BACKOFF.delay(consecutive_failures)).await;
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
        };

        let connector = Arc::clone(connector);
        let context = Arc::clone(&context.load());
        let timeouts = Arc::clone(&timeouts.load());

        // The handshake runs on its own task: awaiting it here would let one
        // stalled client hold up every other connection on this listener.
        tokio::spawn(async move {
            let handshake =
                match timeout(timeouts.handshake, connector.handshake(tcp, remote_address)).await {
                    Ok(Some(handshake)) => handshake,
                    Ok(None) => return,
                    Err(_) => {
                        debug!("Handshake from {remote_address} timed out");
                        return;
                    }
                };

            debug!("Accepted connection from {remote_address}");
            serve_request(
                TokioIo::new(handshake.stream),
                context,
                handshake.peer_certificate,
                timeouts,
                remote_address,
                connector.scheme(),
            )
            .await;
        });
    }
}

async fn build_listener(binding_address: SocketAddr) -> Result<TcpListener, Error> {
    match TcpListener::bind(binding_address).await {
        Ok(listener) => Ok(listener),
        Err(err) => {
            let msg = format!("Failed to bind to {binding_address}: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::command::server::server_context::tests::create_test_server_context;

    #[tokio::test]
    async fn test_build_listener_invalid_port_in_use() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let listener1 = build_listener(addr).await.unwrap();
        let actual_addr = listener1.local_addr().unwrap();

        let result = build_listener(actual_addr).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Initialization(msg) => {
                assert!(msg.contains("Failed to bind to"));
            }
            _ => panic!("Expected Initialization error"),
        }
    }

    /// A connector whose handshake never completes, counting the connections
    /// handed to it. Modelling the client that opens a socket and then stalls.
    struct StalledConnector {
        started: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Connector for StalledConnector {
        type Stream = TcpStream;

        async fn handshake(
            &self,
            _tcp: TcpStream,
            _remote_address: SocketAddr,
        ) -> Option<HandshakeResult<TcpStream>> {
            self.started.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
            None
        }

        fn label(&self) -> &'static str {
            "stalled"
        }

        fn scheme(&self) -> RequestScheme {
            RequestScheme::Http
        }
    }

    /// Bind a loopback listener and report where it landed. Binding before the
    /// loop is spawned means the backlog holds the connections the test opens,
    /// so it never races the task's start.
    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = build_listener("127.0.0.1:0".parse().unwrap())
            .await
            .expect("a loopback bind must succeed");
        let address = listener
            .local_addr()
            .expect("a bound listener has an address");
        (listener, address)
    }

    /// The regression: awaiting the handshake in the accept loop let one
    /// stalled client hold up every connection behind it.
    #[tokio::test]
    async fn a_stalled_handshake_does_not_block_the_next_connection() {
        let (listener, address) = bound_listener().await;
        let started = Arc::new(AtomicUsize::new(0));
        let connector = Arc::new(StalledConnector {
            started: Arc::clone(&started),
        });
        let context = ArcSwap::from_pointee(create_test_server_context().await);
        let timeouts =
            ArcSwap::from_pointee(RequestTimeouts::from_config(&ListenerBaseConfig::default()));

        let loop_handle =
            tokio::spawn(
                async move { accept_loop(listener, &connector, &context, &timeouts).await },
            );

        // Both clients connect; neither handshake will ever finish.
        let _first = TcpStream::connect(address).await.expect("first connect");
        let _second = TcpStream::connect(address).await.expect("second connect");

        for _ in 0..100 {
            if started.load(Ordering::SeqCst) >= 2 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            started.load(Ordering::SeqCst),
            2,
            "the second connection must reach the handshake while the first is stalled"
        );
        loop_handle.abort();
    }

    /// A handshake that outlives its deadline is dropped, and the loop keeps
    /// serving: the stalled task must not accumulate.
    #[tokio::test]
    async fn a_handshake_past_its_deadline_is_dropped() {
        let (listener, address) = bound_listener().await;
        let started = Arc::new(AtomicUsize::new(0));
        let connector = Arc::new(StalledConnector {
            started: Arc::clone(&started),
        });
        let context = ArcSwap::from_pointee(create_test_server_context().await);
        let timeouts = ArcSwap::from_pointee(RequestTimeouts {
            handshake: Duration::from_millis(20),
            query: Duration::from_secs(1),
            grace: Duration::from_secs(1),
        });

        let loop_handle =
            tokio::spawn(
                async move { accept_loop(listener, &connector, &context, &timeouts).await },
            );

        let client = TcpStream::connect(address).await.expect("connect");
        for _ in 0..100 {
            if started.load(Ordering::SeqCst) == 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        // The deadline fires and the connector's task is dropped, closing the
        // socket the client still holds.
        let mut buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(5), client.readable())
            .await
            .expect("the timed-out connection must be closed");
        assert!(read.is_ok());
        assert_eq!(
            client
                .try_read(&mut buffer)
                .expect("a closed peer reads EOF"),
            0
        );
        loop_handle.abort();
    }

    #[tokio::test]
    async fn test_build_listener_error_message_format() {
        let addr: SocketAddr = "240.0.0.1:8080".parse().unwrap();
        let result = build_listener(addr).await;

        assert!(result.is_err());
        if let Err(Error::Initialization(msg)) = result {
            assert!(msg.starts_with("Failed to bind to"));
            assert!(msg.contains("240.0.0.1:8080"));
        } else {
            panic!("Expected Initialization error with formatted message");
        }
    }
}
