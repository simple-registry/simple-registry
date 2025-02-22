use crate::registry::api::body::Body;
use crate::registry::Error;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::{Response, StatusCode};
use serde::de::StdError;
use std::io;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

pub trait PaginatedResponseExt {
    fn paginated(content: Body, link: Option<&str>) -> Result<Self, Error>
    where
        Self: Sized;
}

impl PaginatedResponseExt for Response<Body> {
    fn paginated(body: Body, link: Option<&str>) -> Result<Response<Body>, Error> {
        let res = match link {
            Some(link) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("Link", format!("<{link}>; rel=\"next\""))
                .body(body)?,
            None => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(body)?,
        };

        Ok(res)
    }
}

pub trait IntoAsyncRead {
    fn into_async_read(self) -> impl AsyncRead;
}

impl<S> IntoAsyncRead for Response<S>
where
    S: BodyExt,
    S::Error: Sync + Send + StdError + 'static,
{
    fn into_async_read(self) -> impl AsyncRead {
        let stream = self
            .into_data_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        StreamReader::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_paginated() {
        let body = Body::Empty;
        let link = Some("http://example.com");
        let res = Response::paginated(body, link).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            res.headers().get("Link").unwrap(),
            "<http://example.com>; rel=\"next\""
        );

        let body = Body::Empty;
        let link = None;
        let res = Response::paginated(body, link).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(res.headers().get("Link"), None);
    }

    #[tokio::test]
    async fn test_into_async_read() {
        let mut reader = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(String::from("Hello World!"))
            .unwrap()
            .into_async_read();

        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"Hello World!");
    }
}
