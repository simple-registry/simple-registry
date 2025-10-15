use crate::command::server::error::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

pub mod insecure;
pub mod tls;

async fn build_listener(binding_address: SocketAddr) -> Result<TcpListener, Error> {
    match TcpListener::bind(binding_address).await {
        Ok(listener) => Ok(listener),
        Err(err) => {
            let msg = format!("Failed to bind to {binding_address}: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

async fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), Error> {
    match listener.accept().await {
        Ok((stream, remote_address)) => {
            debug!("Accepted connection from {remote_address}");
            Ok((stream, remote_address))
        }
        Err(err) => {
            let msg = format!("Failed to accept incoming connection: {err}");
            Err(Error::Execution(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_listener_success() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let result = build_listener(addr).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_build_listener_with_port_zero() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let result = build_listener(addr).await;

        assert!(result.is_ok());
        let listener = result.unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert_ne!(local_addr.port(), 0);
    }

    #[tokio::test]
    async fn test_build_listener_ipv6() {
        let addr = "[::1]:0".parse().unwrap();
        let result = build_listener(addr).await;

        assert!(result.is_ok());
    }

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

    #[tokio::test]
    async fn test_accept_with_connection() {
        use tokio::io::AsyncWriteExt;

        let addr = "127.0.0.1:0".parse().unwrap();
        let listener = build_listener(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let connect_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(local_addr).await.unwrap();
            stream.write_all(b"test").await.unwrap();
        });

        let result = accept(&listener).await;

        assert!(result.is_ok());
        let (_, remote_addr) = result.unwrap();
        assert!(remote_addr.port() > 0);

        connect_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_build_listener_preserves_address() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = build_listener(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        assert_eq!(local_addr.ip(), addr.ip());
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
