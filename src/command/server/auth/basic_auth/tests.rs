use super::*;
use crate::command::server::response_body::ResponseBody;
use hyper::header::HeaderValue;
use hyper::Request;

#[test]
fn test_extract_basic_auth() {
    let request = Request::builder()
        .header(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
        )
        .body(ResponseBody::empty())
        .unwrap();
    let (parts, _) = request.into_parts();

    assert_eq!(
        extract_basic_auth(&parts),
        Some(("user".to_string(), "password".to_string()))
    );

    let request = Request::builder()
        .header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer dXNlcjpwYXNzd29yZA=="),
        )
        .body(ResponseBody::empty())
        .unwrap();
    let (parts, _) = request.into_parts();

    assert_eq!(extract_basic_auth(&parts), None);

    let request = Request::builder()
        .header(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpw YXNzd29yZA="),
        )
        .body(ResponseBody::empty())
        .unwrap();
    let (parts, _) = request.into_parts();

    assert_eq!(extract_basic_auth(&parts), None);

    let request = Request::builder()
        .header(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwY%%%%XNzd29yZA"),
        )
        .body(ResponseBody::empty())
        .unwrap();
    let (parts, _) = request.into_parts();

    assert_eq!(extract_basic_auth(&parts), None);

    let request = Request::builder()
        .header(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA==="),
        )
        .body(ResponseBody::empty())
        .unwrap();
    let (parts, _) = request.into_parts();

    assert_eq!(extract_basic_auth(&parts), None);

    let request = Request::builder().body(ResponseBody::empty()).unwrap();
    let (parts, _) = request.into_parts();
    assert_eq!(extract_basic_auth(&parts), None);
}
