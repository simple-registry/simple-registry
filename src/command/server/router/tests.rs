use angos_oci::client::referrers_path;
use angos_oci::request::GetReferrersRequest;

use super::*;

#[test]
fn test_parse_healthz() {
    let method = Method::GET;
    let uri: Uri = "/healthz".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(matches!(route, Some(Action::Healthz)));
}

#[test]
fn test_parse_metrics() {
    let method = Method::GET;
    let uri: Uri = "/metrics".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(matches!(route, Some(Action::Metrics)));
}

/// Without its own arm the token endpoint reaches the UI-asset arm and answers
/// `index.html` with a 200.
#[test]
fn test_parse_token() {
    let uri: Uri = "/token".parse().unwrap();
    assert!(matches!(parse(&Method::GET, &uri), Some(Action::Token)));
    assert!(parse(&Method::POST, &uri).is_none());
    assert!(parse(&Method::HEAD, &uri).is_none());
}

/// The UI's configuration endpoint is a module of the `ui` component, under the
/// same extension namespace as the rest of angos's own API.
#[test]
fn test_parse_ui_config() {
    let uri: Uri = "/v2/_angos/ui/config".parse().unwrap();
    assert!(matches!(parse(&Method::GET, &uri), Some(Action::UiConfig)));
    assert!(parse(&Method::POST, &uri).is_none());
    assert!(
        parse(&Method::GET, &"/_ui/config".parse().unwrap())
            .is_none_or(|action| !matches!(action, Action::UiConfig))
    );
}

#[test]
fn test_parse_api_version() {
    let method = Method::GET;
    let uri: Uri = "/v2/".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(matches!(route, Some(Action::ApiVersion)));
}

/// end-1 spells the trailing slash. Without one the path is not the version
/// endpoint, and must not reach the UI-asset arm and answer `index.html`.
#[test]
fn test_parse_api_version_without_trailing_slash_is_not_a_route() {
    for method in [Method::GET, Method::HEAD] {
        let uri: Uri = "/v2".parse().unwrap();
        assert!(
            parse(&method, &uri).is_none(),
            "{method} /v2 must not route anywhere"
        );
    }
}

/// The version check must resolve for HEAD too, or it reaches the UI-asset arm
/// and answers `index.html` with a 200.
#[test]
fn test_parse_api_version_head() {
    let method = Method::HEAD;
    let uri: Uri = "/v2/".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(
        matches!(route, Some(Action::ApiVersion)),
        "HEAD /v2/ must resolve to the API version check"
    );
}

/// A reference that parses as neither a tag nor a digest must not route, so the
/// dispatcher answers a `PUT` carrying one with `400`, as OCI conformance
/// requires.
#[test]
fn test_parse_put_manifest_with_unparseable_reference_is_rejected() {
    let uri: Uri = "/v2/myrepo/app/manifests/sha256:not-a-digest"
        .parse()
        .unwrap();
    let route = parse(&Method::PUT, &uri);
    assert!(
        route.is_none(),
        "a manifest reference that is neither tag nor digest must not route (PUT -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_list_catalog_no_params() {
    let method = Method::GET;
    let uri: Uri = "/v2/_catalog".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(matches!(
        route,
        Some(Action::ListCatalog {
            n: None,
            last: None
        })
    ));
}

#[test]
fn test_parse_list_catalog_with_pagination() {
    let method = Method::GET;
    let uri: Uri = "/v2/_catalog?n=10&last=myrepo".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListCatalog { n, last }) = route {
        assert_eq!(n, Some(10));
        assert_eq!(last, Some("myrepo".to_string()));
    } else {
        panic!("Expected ListCatalog route");
    }
}

/// A page size angos cannot read is a bad cursor, not an absent one: serving
/// an unpaginated listing instead would answer a different question.
#[test]
fn test_parse_list_catalog_unreadable_n_is_not_a_route() {
    let method = Method::GET;
    for query in ["n=abc", "n=65536"] {
        let uri: Uri = format!("/v2/_catalog?{query}").parse().unwrap();
        assert!(
            parse(&method, &uri).is_none(),
            "?{query} must not degrade into an unpaginated listing"
        );
    }

    // An empty value is form syntax for an absent one, which is a page size the
    // listing can answer.
    let uri: Uri = "/v2/_catalog?n=".parse().unwrap();
    assert!(matches!(
        parse(&method, &uri),
        Some(Action::ListCatalog { n: None, .. })
    ));
}

#[test]
fn test_parse_list_catalog_url_encoded_last() {
    let method = Method::GET;
    let uri: Uri = "/v2/_catalog?last=foo%2Fbar".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListCatalog { n, last }) = route {
        assert_eq!(n, None);
        assert_eq!(last, Some("foo/bar".to_string()));
    } else {
        panic!("Expected ListCatalog route");
    }
}

#[test]
fn test_parse_start_upload() {
    let method = Method::POST;
    let uri: Uri = "/v2/myrepo/app/blobs/uploads/".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::StartUpload {
        namespace, digest, ..
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert!(digest.is_none());
    } else {
        panic!("Expected StartUpload route");
    }
}

#[test]
fn test_parse_start_upload_without_trailing_slash_is_not_a_route() {
    let method = Method::POST;
    let uri: Uri = "/v2/myrepo/app/blobs/uploads".parse().unwrap();

    assert!(
        parse(&method, &uri).is_none(),
        "the uploads endpoint is spelled with its trailing slash (end-4a)"
    );
}

#[test]
fn test_parse_start_upload_with_digest() {
    let method = Method::POST;
    let uri: Uri = "/v2/myrepo/app/blobs/uploads/?digest=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::StartUpload {
        namespace, digest, ..
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert!(digest.is_some());
        assert_eq!(
            digest.unwrap().to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected StartUpload route");
    }
}

#[test]
fn test_parse_mount_blob_with_from() {
    let method = Method::POST;
    let mount_digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri =
        format!("/v2/myrepo/target/blobs/uploads/?mount={mount_digest}&from=myrepo/source")
            .parse()
            .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::MountBlob {
        namespace,
        digest,
        from,
    }) = route
    {
        assert_eq!(namespace, "myrepo/target");
        assert_eq!(digest.to_string(), mount_digest);
        assert_eq!(from.unwrap(), "myrepo/source");
    } else {
        panic!("Expected MountBlob route");
    }
}

#[test]
fn test_parse_mount_blob_without_from() {
    // An unset `from` makes the server attempt automatic content discovery.
    let method = Method::POST;
    let mount_digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/myrepo/target/blobs/uploads/?mount={mount_digest}")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::MountBlob { digest, from, .. }) = route {
        assert_eq!(digest.to_string(), mount_digest);
        assert!(from.is_none());
    } else {
        panic!("Expected MountBlob route");
    }
}

#[test]
fn test_parse_mount_blob_with_malformed_from_is_rejected() {
    let mount_digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/myrepo/target/blobs/uploads/?mount={mount_digest}&from=Invalid")
        .parse()
        .unwrap();
    let route = parse(&Method::POST, &uri);
    assert!(
        route.is_none(),
        "a malformed ?from= must not route (POST -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_malformed_from_without_mount_is_rejected() {
    let uri: Uri = "/v2/myrepo/target/blobs/uploads/?from=Invalid"
        .parse()
        .unwrap();
    let route = parse(&Method::POST, &uri);
    assert!(
        route.is_none(),
        "a malformed ?from= must not route even unused (POST -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_start_upload_with_malformed_digest_is_rejected() {
    let uri: Uri = "/v2/myrepo/app/blobs/uploads/?digest=not-a-digest"
        .parse()
        .unwrap();
    let route = parse(&Method::POST, &uri);
    assert!(
        route.is_none(),
        "a malformed ?digest= must not start a session (POST -> 400), got: {route:?}"
    );

    let uri: Uri = "/v2/myrepo/app/blobs/uploads/?digest=garbage"
        .parse()
        .unwrap();
    let route = parse(&Method::POST, &uri);
    assert!(
        route.is_none(),
        "a malformed ?digest= must not start a session (POST -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_malformed_mount_is_rejected() {
    // The OCI fall-back-to-session rule covers unsatisfiable mounts, not
    // syntactically invalid ones.
    let route = parse(
        &Method::POST,
        &"/v2/myrepo/target/blobs/uploads/?mount=not-a-digest"
            .parse()
            .unwrap(),
    );
    assert!(
        route.is_none(),
        "a malformed ?mount= must reject the route (POST -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_mount_with_malformed_digest_is_rejected() {
    // Real clients never combine `?mount=` with a monolithic `?digest=`;
    // rejecting the combination is by design.
    let mount_digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/myrepo/target/blobs/uploads/?mount={mount_digest}&digest=garbage")
        .parse()
        .unwrap();
    let route = parse(&Method::POST, &uri);
    assert!(
        route.is_none(),
        "a malformed ?digest= must poison the mount path too (POST -> 400), got: {route:?}"
    );
}

#[test]
fn test_parse_get_upload() {
    let method = Method::GET;
    let session_id = UploadSessionId::generate();
    let uri: Uri = format!("/v2/myrepo/app/blobs/uploads/{session_id}")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetUpload {
        namespace,
        session_id: parsed_session_id,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(parsed_session_id, session_id);
    } else {
        panic!("Expected GetUpload route");
    }
}

#[test]
fn test_parse_patch_upload() {
    let method = Method::PATCH;
    let session_id = UploadSessionId::generate();
    let uri: Uri = format!("/v2/myrepo/app/blobs/uploads/{session_id}")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::PatchUpload {
        namespace,
        session_id: parsed_session_id,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(parsed_session_id, session_id);
    } else {
        panic!("Expected PatchUpload route");
    }
}

#[test]
fn test_parse_put_upload() {
    let method = Method::PUT;
    let session_id = UploadSessionId::generate();
    let uri: Uri = format!("/v2/myrepo/app/blobs/uploads/{session_id}?digest=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::PutUpload {
        namespace,
        session_id: parsed_session_id,
        digest,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(parsed_session_id, session_id);
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected PutUpload route");
    }
}

#[test]
fn test_parse_put_upload_without_digest() {
    let method = Method::PUT;
    let session_id = UploadSessionId::generate();
    let uri: Uri = format!("/v2/myrepo/app/blobs/uploads/{session_id}")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_delete_upload() {
    let method = Method::DELETE;
    let session_id = UploadSessionId::generate();
    let uri: Uri = format!("/v2/myrepo/app/blobs/uploads/{session_id}")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::DeleteUpload {
        namespace,
        session_id: parsed_session_id,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(parsed_session_id, session_id);
    } else {
        panic!("Expected DeleteUpload route");
    }
}

#[test]
fn test_parse_get_blob() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetBlob { namespace, digest }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected GetBlob route");
    }
}

#[test]
fn test_parse_head_blob() {
    let method = Method::HEAD;
    let uri: Uri = "/v2/myrepo/app/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::HeadBlob { namespace, digest }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected HeadBlob route");
    }
}

#[test]
fn test_parse_delete_blob() {
    let method = Method::DELETE;
    let uri: Uri = "/v2/myrepo/app/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::DeleteBlob { namespace, digest }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected DeleteBlob route");
    }
}

#[test]
fn test_parse_get_manifest_by_tag() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/manifests/v1.0.0".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(reference.to_string(), "v1.0.0");
    } else {
        panic!("Expected GetManifest route");
    }
}

#[test]
fn test_parse_get_manifest_by_digest() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/manifests/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            reference.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected GetManifest route");
    }
}

#[test]
fn test_parse_head_manifest() {
    let method = Method::HEAD;
    let uri: Uri = "/v2/myrepo/app/manifests/v1.0.0".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::HeadManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(reference.to_string(), "v1.0.0");
    } else {
        panic!("Expected HeadManifest route");
    }
}

#[test]
fn test_parse_put_manifest() {
    let method = Method::PUT;
    let uri: Uri = "/v2/myrepo/app/manifests/v1.0.0".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::PutManifest { namespace, target }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert!(
            matches!(target, ManifestPutTarget::Tag(tag) if tag == *"v1.0.0"),
            "a by-tag PUT must produce a Tag target carrying no query tags"
        );
    } else {
        panic!("Expected PutManifest route");
    }
}

#[test]
fn test_parse_put_manifest_by_digest_with_tag_params() {
    let method = Method::PUT;
    let digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/foo/manifests/{digest}?tag=a&tag=b")
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::PutManifest { namespace, target }) = route {
        assert_eq!(namespace, "foo");
        let ManifestPutTarget::Digest { digest: d, tags } = target else {
            panic!("a by-digest PUT must produce a Digest target");
        };
        assert_eq!(d.to_string(), digest);
        assert_eq!(
            tags,
            vec![Tag::new("a").unwrap(), Tag::new("b").unwrap()],
            "valid `?tag=` values parse into Tags on the Digest target"
        );
    } else {
        panic!("Expected PutManifest route");
    }
}

#[test]
fn test_parse_put_manifest_by_digest_dedups_repeated_tag_params() {
    let method = Method::PUT;
    let digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/foo/manifests/{digest}?tag=a&tag=a&tag=b")
        .parse()
        .unwrap();
    let Some(Action::PutManifest {
        target: ManifestPutTarget::Digest { tags, .. },
        ..
    }) = parse(&method, &uri)
    else {
        panic!("a by-digest PUT must produce a Digest target");
    };
    assert_eq!(
        tags,
        vec![Tag::new("a").unwrap(), Tag::new("b").unwrap()],
        "a repeated `?tag=` value is de-duplicated"
    );
}

#[test]
fn test_parse_put_manifest_by_digest_invalid_tag_param_rejected() {
    let method = Method::PUT;
    let digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/foo/manifests/{digest}?tag=a&tag=bad!tag")
        .parse()
        .unwrap();
    // A single invalid `?tag=` value fails deserialization, so the route is
    // rejected (the router's generic 400) rather than dropping every tag.
    assert!(
        parse(&method, &uri).is_none(),
        "an invalid `?tag=` value must reject the by-digest PUT route"
    );
}

#[test]
fn test_parse_get_manifest_by_tag_ignores_tag_params() {
    let method = Method::GET;
    let uri: Uri = "/v2/foo/manifests/latest?tag=a".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(
        matches!(route, Some(Action::GetManifest { .. })),
        "GET by tag must not carry tag params"
    );
}

#[test]
fn test_parse_delete_manifest() {
    let method = Method::DELETE;
    let uri: Uri = "/v2/myrepo/app/manifests/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::DeleteManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            reference.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    } else {
        panic!("Expected DeleteManifest route");
    }
}

#[test]
fn test_parse_get_referrer() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/referrers/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetReferrer {
        namespace,
        digest,
        artifact_type,
        ..
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert!(artifact_type.is_none());
    } else {
        panic!("Expected GetReferrer route");
    }
}

#[test]
fn test_parse_get_referrer_with_artifact_type() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/referrers/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef?artifactType=application/vnd.oci.image.manifest.v1%2Bjson".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetReferrer {
        namespace,
        digest,
        artifact_type,
        ..
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(
            digest.to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(
            artifact_type,
            Some(MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap())
        );
    } else {
        panic!("Expected GetReferrer route");
    }
}

#[test]
fn test_parse_list_tags() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/tags/list".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListTags { namespace, n, last }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert!(n.is_none());
        assert!(last.is_none());
    } else {
        panic!("Expected ListTags route");
    }
}

#[test]
fn test_parse_list_tags_with_pagination() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/tags/list?n=50&last=v1.0.0".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListTags { namespace, n, last }) = route {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(n, Some(50));
        assert_eq!(last, Some("v1.0.0".to_string()));
    } else {
        panic!("Expected ListTags route");
    }
}

#[test]
fn test_parse_unknown_route_becomes_ui_asset() {
    let method = Method::GET;
    let uri: Uri = "/unknown/path".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::UiAsset { path }) = route {
        assert_eq!(path, "/unknown/path");
    } else {
        panic!("Expected UiAsset route for unknown GET path");
    }
}

#[test]
fn test_parse_unknown_post_route() {
    let method = Method::POST;
    let uri: Uri = "/unknown/path".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_unknown_method() {
    let method = Method::OPTIONS;
    let uri: Uri = "/v2/myrepo/app/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_invalid_digest_in_blob_path() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/blobs/invalid-digest".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_invalid_uuid_in_upload_path() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/blobs/uploads/invalid-uuid".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

/// The proxy `ns` parameter selects no upstream, so it must not change or
/// reject the route it rides on. Angos resolves its upstream from the namespace
/// prefix alone.
#[test]
fn ns_parameter_is_accepted_and_ignored() {
    let digest = format!("sha256:{}", "a".repeat(64));
    for (method, path) in [
        (Method::GET, "/v2/lib/nginx/manifests/latest".to_string()),
        (Method::HEAD, "/v2/lib/nginx/manifests/latest".to_string()),
        (Method::GET, format!("/v2/lib/nginx/blobs/{digest}")),
        (Method::GET, "/v2/lib/nginx/tags/list".to_string()),
        (Method::GET, format!("/v2/lib/nginx/referrers/{digest}")),
        (Method::POST, "/v2/lib/nginx/blobs/uploads/".to_string()),
        (Method::GET, "/v2/_catalog".to_string()),
    ] {
        let plain = parse(&method, &path.parse::<Uri>().unwrap());
        let with_ns = parse(
            &method,
            &format!("{path}?ns=docker.io").parse::<Uri>().unwrap(),
        );
        assert!(plain.is_some(), "{method} {path} must route");
        assert_eq!(
            format!("{with_ns:?}"),
            format!("{plain:?}"),
            "?ns= must not change the {method} {path} route"
        );
    }
}

/// The `?digest-algorithm=` hint reaches the session so it hashes under one
/// algorithm; an unsupported value is a malformed request, not an absent hint.
#[test]
fn upload_digest_algorithm_hint_is_parsed() {
    let uri: Uri = "/v2/myrepo/app/blobs/uploads/?digest-algorithm=sha512"
        .parse()
        .unwrap();
    match parse(&Method::POST, &uri) {
        Some(Action::StartUpload {
            digest_algorithm, ..
        }) => assert_eq!(digest_algorithm, Some(Algorithm::Sha512)),
        other => panic!("a hinted upload must start a session, got {other:?}"),
    }

    let uri: Uri = "/v2/myrepo/app/blobs/uploads/".parse().unwrap();
    match parse(&Method::POST, &uri) {
        Some(Action::StartUpload {
            digest_algorithm, ..
        }) => assert!(digest_algorithm.is_none()),
        other => panic!("an unhinted upload must start a session, got {other:?}"),
    }

    let uri: Uri = "/v2/myrepo/app/blobs/uploads/?digest-algorithm=md5"
        .parse()
        .unwrap();
    assert!(
        parse(&Method::POST, &uri).is_none(),
        "an unsupported algorithm must not start a session (POST -> 400)"
    );
}

#[test]
fn test_try_parse_upload_start_post_method() {
    let method = Method::POST;
    let path = "myrepo/app/blobs/uploads/";
    let route = try_parse_upload(&method, path, None);
    assert!(route.is_some());
    if let Some(Action::StartUpload {
        namespace, digest, ..
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert!(digest.is_none());
    } else {
        panic!("Expected StartUpload route");
    }
}

#[test]
fn test_try_parse_upload_start_wrong_method() {
    let method = Method::GET;
    let path = "myrepo/app/blobs/uploads/";
    let route = try_parse_upload(&method, path, None);
    assert!(route.is_none());
}

#[test]
fn test_try_parse_upload_start_requires_the_trailing_slash() {
    let method = Method::POST;

    // The spec's endpoint (end-4a) carries the trailing slash.
    let route = try_parse_upload(&method, "foo/blobs/uploads/", None);
    assert!(
        matches!(route, Some(Action::StartUpload { ref namespace, digest: None, .. }) if namespace == "foo"),
        "the spec's spelling must yield StartUpload with the right namespace"
    );

    // Without it the path is not that endpoint, so it does not route.
    let route = try_parse_upload(&method, "foo/blobs/uploads", None);
    assert!(
        route.is_none(),
        "a path missing the trailing slash is not the uploads endpoint"
    );

    // Nested namespace.
    let route = try_parse_upload(&method, "org/team/blobs/uploads/", None);
    assert!(
        matches!(route, Some(Action::StartUpload { ref namespace, .. }) if namespace == "org/team"),
        "nested namespace must parse correctly"
    );

    // Invalid namespace: empty string before the suffix.
    let route = try_parse_upload(&method, "blobs/uploads/", None);
    assert!(route.is_none(), "empty namespace must not yield a route");

    // Invalid namespace: contains uppercase letter.
    let route = try_parse_upload(&method, "MyRepo/blobs/uploads/", None);
    assert!(
        route.is_none(),
        "uppercase namespace must not yield a route"
    );

    // Invalid namespace: contains a space (invalid character).
    let route = try_parse_upload(&method, "bad ns/blobs/uploads/", None);
    assert!(
        route.is_none(),
        "namespace with space must not yield a route"
    );
}

#[test]
fn test_try_parse_upload_invalid_uuid() {
    let method = Method::GET;
    let path = "myrepo/app/blobs/uploads/not-a-uuid";
    let route = try_parse_upload(&method, path, None);
    assert!(route.is_none());
}

#[test]
fn test_try_find_blobs_invalid_digest() {
    let method = Method::GET;
    let path = "myrepo/app/blobs/not-a-digest";
    let route = try_find_blobs(&method, path);
    assert!(route.is_none());
}

#[test]
fn test_try_find_manifests_valid_tag() {
    let method = Method::GET;
    let path = "myrepo/app/manifests/latest";
    let route = try_find_manifests(&method, path, None);
    assert!(route.is_some());
    if let Some(Action::GetManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(reference.to_string(), "latest");
    } else {
        panic!("Expected GetManifest route");
    }
}

#[test]
fn test_try_find_referrers_invalid_digest() {
    let method = Method::GET;
    let path = "myrepo/app/referrers/not-a-digest";
    let route = try_find_referrers(&method, path, None);
    assert!(route.is_none());
}

#[test]
fn test_try_find_tags_wrong_method() {
    let method = Method::POST;
    let path = "myrepo/app/tags/list";
    let route = try_find_tags(&method, path, None);
    assert!(route.is_none());
}

#[test]
fn test_parse_nested_namespace() {
    let method = Method::GET;
    let uri: Uri = "/v2/org/team/project/app/manifests/v1.0.0".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "org/team/project/app");
        assert_eq!(reference.to_string(), "v1.0.0");
    } else {
        panic!("Expected GetManifest route");
    }
}

#[test]
fn test_parse_get_blob_sha512() {
    let method = Method::GET;
    let digest = "sha512:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let uri: Uri = format!("/v2/myrepo/app/blobs/{digest}").parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetBlob {
        namespace,
        digest: parsed,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(parsed.to_string(), digest);
    } else {
        panic!("Expected GetBlob route for a sha512 digest");
    }
}

#[test]
fn test_parse_tag_name_with_hyphen_and_dot() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/manifests/v1.0.0-alpha.1".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::GetManifest {
        namespace,
        reference,
    }) = route
    {
        assert_eq!(namespace, "myrepo/app");
        assert_eq!(reference.to_string(), "v1.0.0-alpha.1");
    } else {
        panic!("Expected GetManifest route");
    }
}

#[test]
fn test_parse_invalid_tag_with_plus_sign() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/manifests/v1.0.0+build.123".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_ui_asset_root() {
    let method = Method::GET;
    let uri: Uri = "/".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::UiAsset { path }) = route {
        assert_eq!(path, "/");
    } else {
        panic!("Expected UiAsset route");
    }
}

#[test]
fn test_parse_ui_asset_with_path() {
    let method = Method::GET;
    let uri: Uri = "/index.html".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::UiAsset { path }) = route {
        assert_eq!(path, "/index.html");
    } else {
        panic!("Expected UiAsset route");
    }
}

#[test]
fn test_parse_ui_asset_head_method() {
    let method = Method::HEAD;
    let uri: Uri = "/style.css".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::UiAsset { path }) = route {
        assert_eq!(path, "/style.css");
    } else {
        panic!("Expected UiAsset route");
    }
}

#[test]
fn test_parse_ui_asset_post_not_allowed() {
    let method = Method::POST;
    let uri: Uri = "/index.html".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_list_revisions() {
    let method = Method::GET;
    let uri: Uri = "/v2/myrepo/app/_angos/revisions/list".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListRevisions { namespace }) = route {
        assert_eq!(namespace, "myrepo/app");
    } else {
        panic!("Expected ListRevisions route");
    }
}

#[test]
fn test_parse_list_revisions_simple_namespace() {
    let method = Method::GET;
    let uri: Uri = "/v2/library/_angos/revisions/list".parse().unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListRevisions { namespace }) = route {
        assert_eq!(namespace, "library");
    } else {
        panic!("Expected ListRevisions route");
    }
}

#[test]
fn test_parse_list_revisions_nested_namespace() {
    let method = Method::GET;
    let uri: Uri = "/v2/org/team/project/_angos/revisions/list"
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListRevisions { namespace }) = route {
        assert_eq!(namespace, "org/team/project");
    } else {
        panic!("Expected ListRevisions route");
    }
}

#[test]
fn test_parse_list_revisions_post_not_allowed() {
    let method = Method::POST;
    let uri: Uri = "/v2/myrepo/_angos/revisions/list".parse().unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_list_namespaces() {
    let method = Method::GET;
    let uri: Uri = "/v2/_angos/namespaces/list?repository=myrepo"
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListNamespaces { repository }) = route {
        assert_eq!(repository, "myrepo");
    } else {
        panic!("Expected ListNamespaces route");
    }
}

#[test]
fn test_parse_list_namespaces_nested() {
    let method = Method::GET;
    let uri: Uri = "/v2/_angos/namespaces/list?repository=org/team"
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    if let Some(Action::ListNamespaces { repository }) = route {
        assert_eq!(repository, "org/team");
    } else {
        panic!("Expected ListNamespaces route");
    }
}

#[test]
fn test_parse_list_namespaces_invalid_repository_returns_none() {
    let method = Method::GET;
    let uri: Uri = "/v2/_angos/namespaces/list?repository=INVALID"
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

#[test]
fn test_parse_list_namespaces_post_not_allowed() {
    let method = Method::POST;
    let uri: Uri = "/v2/_angos/namespaces/list?repository=myrepo"
        .parse()
        .unwrap();
    let route = parse(&method, &uri);
    assert!(route.is_none());
}

// Durable job-queue administration routes

#[test]
fn test_parse_list_jobs() {
    let route = parse(&Method::GET, &"/v2/_angos/jobs/list".parse().unwrap());
    match route {
        Some(Action::ListJobs { queue, n, after }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(n, None);
            assert_eq!(after, None);
        }
        other => panic!("expected ListJobs, got {other:?}"),
    }
}

#[test]
fn test_parse_list_jobs_with_pagination() {
    let route = parse(
        &Method::GET,
        &"/v2/_angos/jobs/list?n=10&after=abc".parse().unwrap(),
    );
    match route {
        Some(Action::ListJobs { queue, n, after }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(n, Some(10));
            assert_eq!(after.as_deref(), Some("abc"));
        }
        other => panic!("expected ListJobs, got {other:?}"),
    }
}

#[test]
fn test_parse_list_failed_jobs() {
    let route = parse(&Method::GET, &"/v2/_angos/jobs/failed".parse().unwrap());
    match route {
        Some(Action::ListFailedJobs { queue, n, after }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(n, None);
            assert_eq!(after, None);
        }
        other => panic!("expected ListFailedJobs, got {other:?}"),
    }
}

#[test]
fn test_parse_retry_job() {
    let route = parse(
        &Method::POST,
        &"/v2/_angos/jobs/failed?key=0000018b-abc".parse().unwrap(),
    );
    match route {
        Some(Action::RetryJob { queue, storage_key }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(storage_key, "0000018b-abc");
        }
        other => panic!("expected RetryJob, got {other:?}"),
    }
}

#[test]
fn test_parse_delete_failed_job() {
    let route = parse(
        &Method::DELETE,
        &"/v2/_angos/jobs/failed?key=0000018b-abc".parse().unwrap(),
    );
    match route {
        Some(Action::DeleteJob {
            queue,
            state,
            storage_key,
        }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(state, JobState::Failed);
            assert_eq!(storage_key, "0000018b-abc");
        }
        other => panic!("expected DeleteJob(Failed), got {other:?}"),
    }
}

#[test]
fn test_parse_delete_pending_job() {
    let route = parse(
        &Method::DELETE,
        &"/v2/_angos/jobs/pending?key=0000018b-abc".parse().unwrap(),
    );
    match route {
        Some(Action::DeleteJob {
            queue,
            state,
            storage_key,
        }) => {
            assert_eq!(queue, Queue::Cache);
            assert_eq!(state, JobState::Pending);
            assert_eq!(storage_key, "0000018b-abc");
        }
        other => panic!("expected DeleteJob(Pending), got {other:?}"),
    }
}

#[test]
fn test_parse_jobs_rejects_post_on_listing() {
    let route = parse(&Method::POST, &"/v2/_angos/jobs/list".parse().unwrap());
    assert!(route.is_none());
}

#[test]
fn test_parse_jobs_rejects_key_with_slash() {
    // A storage key is a single path segment; a nested path must not match.
    let route = parse(
        &Method::DELETE,
        &"/v2/_angos/jobs/failed?key=a/b".parse().unwrap(),
    );
    assert!(route.is_none());
}

/// A retry names its job in `?key=`, since an extension path ends at its
/// module. Without one there is nothing to retry.
#[test]
fn test_parse_retry_without_a_key_is_not_a_route() {
    let route = parse(&Method::POST, &"/v2/_angos/jobs/failed".parse().unwrap());
    assert!(route.is_none());
}

#[test]
fn test_parse_list_jobs_selects_replication_queue() {
    let route = parse(
        &Method::GET,
        &"/v2/_angos/jobs/list?queue=replication".parse().unwrap(),
    );
    match route {
        Some(Action::ListJobs { queue, .. }) => assert_eq!(queue, Queue::Replication),
        other => panic!("expected ListJobs, got {other:?}"),
    }
}

#[test]
fn test_parse_delete_failed_job_selects_replication_queue() {
    let route = parse(
        &Method::DELETE,
        &"/v2/_angos/jobs/failed?queue=replication&key=0000018b-abc"
            .parse()
            .unwrap(),
    );
    match route {
        Some(Action::DeleteJob { queue, state, .. }) => {
            assert_eq!(queue, Queue::Replication);
            assert_eq!(state, JobState::Failed);
        }
        other => panic!("expected DeleteJob, got {other:?}"),
    }
}

#[test]
fn test_parse_jobs_rejects_unknown_queue() {
    assert!(
        parse(
            &Method::GET,
            &"/v2/_angos/jobs/list?queue=bogus".parse().unwrap()
        )
        .is_none()
    );
    assert!(
        parse(
            &Method::DELETE,
            &"/v2/_angos/jobs/failed?queue=bogus&key=0000018b-abc"
                .parse()
                .unwrap(),
        )
        .is_none()
    );
}

#[test]
fn test_parse_jobs_rejects_malformed_query_instead_of_defaulting_queue() {
    // A lenient parse would reset the whole query and administer the default
    // cache queue instead of the requested one.
    assert!(
        parse(
            &Method::GET,
            &"/v2/_angos/jobs/list?queue=replication&n=abc"
                .parse()
                .unwrap(),
        )
        .is_none()
    );
    assert!(
        parse(
            &Method::GET,
            &"/v2/_angos/jobs/list?queue=replication&n=99999999"
                .parse()
                .unwrap(),
        )
        .is_none()
    );
    assert!(
        parse(
            &Method::DELETE,
            &"/v2/_angos/jobs/failed?queue=replication&key=0000018b-abc&n=abc"
                .parse()
                .unwrap(),
        )
        .is_none()
    );
}

/// The filter is a media type, so its `+json` style suffix must survive the
/// query decoding, in either spelling a client percent-encodes it as.
#[test]
fn artifact_type_filter_keeps_an_encoded_media_type_suffix() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let expected = MediaType::new("application/vnd.in-toto+json").unwrap();

    for query in [
        "artifactType=application%2Fvnd.in-toto%2Bjson",
        "artifactType=application/vnd.in-toto%2Bjson",
    ] {
        let uri: Uri = format!("/v2/lib/nginx/referrers/{digest}?{query}")
            .parse()
            .unwrap();
        match parse(&Method::GET, &uri) {
            Some(Action::GetReferrer { artifact_type, .. }) => assert_eq!(
                artifact_type.as_ref(),
                Some(&expected),
                "filter must survive {query}"
            ),
            other => panic!("{query} must route to a referrers listing, got {other:?}"),
        }
    }
}

/// A value that is not a media type is a bad filter, not an absent one: it must
/// never degrade into an unfiltered listing of every referrer. A parameter
/// section is not a media type either: only a header may carry one, so a filter
/// naming parameters is refused rather than quietly reduced to the type ahead
/// of them.
#[test]
fn artifact_type_filter_rejects_a_malformed_value() {
    let digest = format!("sha256:{}", "a".repeat(64));
    for filter in ["not-a-media-type", "application/json;charset=utf-8"] {
        let uri: Uri = format!("/v2/lib/nginx/referrers/{digest}?artifactType={filter}")
            .parse()
            .unwrap();
        assert!(
            parse(&Method::GET, &uri).is_none(),
            "'{filter}' must not resolve to a listing"
        );
    }
}

/// The referrers endpoint must never answer a `404` while it serves the API, so
/// every way of malforming the request owes a `400`.
#[test]
fn every_malformed_referrers_request_is_a_bad_request() {
    let digest = format!("sha256:{}", "a".repeat(64));

    for bad in [
        format!("/v2/lib/nginx/referrers/{digest}?artifactType=not-a-media-type"),
        "/v2/lib/nginx/referrers/not-a-digest".to_string(),
    ] {
        let uri: Uri = bad.parse().unwrap();
        assert!(
            parse(&Method::GET, &uri).is_none(),
            "{bad} must not resolve to a listing"
        );
        assert!(
            is_invalid_referrers_request(&Method::GET, &uri),
            "{bad} must be a bad request, not the miss an unserved path gets"
        );
    }
}

/// The spec defines no page size for this endpoint, so `?n=` is not part of it
/// and is ignored like any other unknown parameter rather than rejected.
#[test]
fn a_referrers_page_size_is_not_a_parameter() {
    let digest = format!("sha256:{}", "a".repeat(64));

    for query in ["n=abc", "n=65536", "n=10"] {
        let uri: Uri = format!("/v2/lib/nginx/referrers/{digest}?{query}")
            .parse()
            .unwrap();
        assert!(
            matches!(parse(&Method::GET, &uri), Some(Action::GetReferrer { .. })),
            "?{query} must be ignored, not refused"
        );
    }
}

/// The `Link` a filtered listing advertises is composed by the serving side and
/// parsed back by this one, so the filter has to survive the round trip. A raw
/// `+` would come back as a space and fail the media-type grammar.
#[test]
fn a_rendered_referrers_link_parses_back_into_the_same_filter() {
    let digest: Digest = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
    let filter = MediaType::new("application/vnd.example.sbom.v1+json").unwrap();
    let link = referrers_path(
        "",
        &GetReferrersRequest {
            namespace: Namespace::new("lib/nginx").unwrap(),
            digest: digest.clone(),
            artifact_type: Some(filter.clone()),
            last: Some(digest.to_string()),
        },
    );

    match parse(&Method::GET, &link.parse().unwrap()) {
        Some(Action::GetReferrer {
            artifact_type,
            last,
            ..
        }) => {
            assert_eq!(artifact_type.as_ref(), Some(&filter));
            assert_eq!(last.as_deref(), Some(digest.to_string().as_str()));
        }
        other => panic!("the advertised next page must route, got {other:?}"),
    }
}

/// No filter at all still lists every referrer.
#[test]
fn artifact_type_filter_is_optional() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let uri: Uri = format!("/v2/lib/nginx/referrers/{digest}").parse().unwrap();
    match parse(&Method::GET, &uri) {
        Some(Action::GetReferrer { artifact_type, .. }) => assert!(artifact_type.is_none()),
        other => panic!("an unfiltered referrers listing must route, got {other:?}"),
    }
}
