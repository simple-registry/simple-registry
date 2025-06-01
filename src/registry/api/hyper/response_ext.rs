use crate::registry::Error;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::header::{AsHeaderName, CONTENT_TYPE, LINK};
use hyper::{Response, StatusCode};
use std::io;
use std::str::FromStr;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

pub trait ResponseExt<B> {
    fn get_header<K>(&self, header: K) -> Option<String>
    where
        K: AsHeaderName;

    fn parse_header<T, K>(&self, header: K) -> Result<T, Error>
    where
        T: FromStr,
        K: AsHeaderName;

    fn paginated(content: B, link: Option<&str>) -> Result<Self, Error>
    where
        Self: Sized;
}

impl<B> ResponseExt<B> for Response<B> {
    fn get_header<K>(&self, header: K) -> Option<String>
    where
        K: AsHeaderName,
    {
        self.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
            .map(ToString::to_string)
    }

    fn parse_header<T, K>(&self, header: K) -> Result<T, Error>
    where
        T: FromStr,
        K: AsHeaderName,
    {
        self.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.parse().ok())
            .ok_or(Error::Unsupported)
    }

    fn paginated(body: B, link: Option<&str>) -> Result<Response<B>, Error> {
        let res = match link {
            Some(link) => Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .header(LINK, format!("<{link}>; rel=\"next\""))
                .body(body)?,
            None => Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
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
    S::Error: Sync + Send + std::error::Error + 'static,
{
    fn into_async_read(self) -> impl AsyncRead {
        let stream = self.into_data_stream().map_err(io::Error::other);
        StreamReader::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::body::Body;
    use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, LINK};
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_get_header() {
        let res = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(
            res.get_header(CONTENT_TYPE),
            Some("application/json".to_string())
        );
        assert_eq!(res.get_header(CONTENT_LENGTH), None);
    }

    #[test]
    fn test_parse_header() {
        let res = Response::builder()
            .header(CONTENT_LENGTH, "42")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(res.parse_header::<u64, _>("Content-Length"), Ok(42));
        assert_eq!(
            res.parse_header::<u64, _>(CONTENT_TYPE),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn test_paginated() {
        let body = Body::Empty;
        let link = Some("http://example.com");
        let res = Response::paginated(body, link).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.get_header(CONTENT_TYPE),
            Some(String::from("application/json"))
        );
        assert_eq!(
            res.get_header(LINK),
            Some(String::from("<http://example.com>; rel=\"next\""))
        );

        let body = Body::Empty;
        let link = None;
        let res = Response::paginated(body, link).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.get_header(CONTENT_TYPE),
            Some(String::from("application/json"))
        );
        assert_eq!(res.get_header(LINK), None);
    }

    #[tokio::test]
    async fn test_into_async_read() {
        let mut reader = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(String::from("Hello World!"))
            .unwrap()
            .into_async_read();

        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"Hello World!");
    }
}
