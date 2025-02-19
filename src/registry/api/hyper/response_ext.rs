use crate::registry::api::body::Body;
use crate::registry::Error;
use hyper::{Response, StatusCode};

pub trait ResponseExt {
    fn paginated(content: Body, link: Option<&str>) -> Result<Self, Error>
    where
        Self: Sized;
}

impl ResponseExt for Response<Body> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
