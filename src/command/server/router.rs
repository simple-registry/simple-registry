use super::route::Route;
use crate::oci::{Digest, Reference};
use hyper::{Method, Uri};
use serde::Deserialize;
use std::str::FromStr;
use uuid::Uuid;

pub fn parse<'a>(method: &Method, uri: &'a Uri) -> Route<'a> {
    let path = uri.path();
    let params = uri.query();

    match path {
        "/healthz" if method == Method::GET => return Route::Healthz,
        "/metrics" if method == Method::GET => return Route::Metrics,
        "/v2" | "/v2/" if method == Method::GET => return Route::ApiVersion,
        "/v2/_catalog" if method == Method::GET => {
            let (n, last) = if let Some(p) = params.map(PaginationQuery::from_params) {
                (p.n, p.last)
            } else {
                (None, None)
            };

            return Route::ListCatalog { n, last };
        }
        _ => {}
    }

    let Some(path) = path.strip_prefix("/v2/") else {
        return Route::Unknown;
    };

    if let Some(route) = try_parse_uploads(method, path, params) {
        return route;
    }

    if let Some(route) = try_parse_upload(method, path, params) {
        return route;
    }

    if let Some(route) = try_find_blobs(method, path) {
        return route;
    }

    if let Some(route) = try_find_manifests(method, path) {
        return route;
    }

    if let Some(route) = try_find_referrers(method, path, params) {
        return route;
    }

    if let Some(route) = try_find_tags(method, path, params) {
        return route;
    }

    Route::Unknown
}

#[derive(Deserialize, Default)]
struct DigestQuery {
    digest: Option<String>,
}

impl DigestQuery {
    fn from_params(params: &str) -> Self {
        serde_urlencoded::from_str(params).ok().unwrap_or_default()
    }

    fn to_digest(&self) -> Option<Digest> {
        self.digest.as_ref().and_then(|d| d.parse().ok())
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ArtifactTypeQuery {
    pub artifact_type: Option<String>,
}

impl ArtifactTypeQuery {
    fn from_params(params: &str) -> Self {
        serde_urlencoded::from_str(params).ok().unwrap_or_default()
    }
}

#[derive(Deserialize, Default)]
struct PaginationQuery {
    pub n: Option<u16>,
    pub last: Option<String>,
}

impl PaginationQuery {
    fn from_params(params: &str) -> Self {
        serde_urlencoded::from_str(params).ok().unwrap_or_default()
    }
}

fn try_parse_uploads<'a>(
    method: &Method,
    path: &'a str,
    params: Option<&'a str>,
) -> Option<Route<'a>> {
    let suffixes = ["/blobs/uploads", "/blobs/uploads/"];

    for suffix in suffixes {
        if let Some(namespace) = path.strip_suffix(suffix) {
            if method == Method::POST {
                let digest = params
                    .map(DigestQuery::from_params)
                    .and_then(|r| r.to_digest());

                return Some(Route::StartUpload { namespace, digest });
            }
        }
    }

    None
}

fn try_parse_upload<'a>(
    method: &Method,
    path: &'a str,
    params: Option<&'a str>,
) -> Option<Route<'a>> {
    if let Some(upload_position) = path.rfind("/blobs/uploads/") {
        let namespace = &path[..upload_position];

        let uuid = &path[upload_position + "/blobs/uploads/".len()..];
        let uuid = Uuid::from_str(uuid).ok()?;

        match *method {
            Method::GET => return Some(Route::GetUpload { namespace, uuid }),
            Method::PATCH => return Some(Route::PatchUpload { namespace, uuid }),
            Method::PUT => {
                if let Some(digest) = params
                    .map(DigestQuery::from_params)
                    .and_then(|r| r.to_digest())
                {
                    return Some(Route::PutUpload {
                        namespace,
                        uuid,
                        digest,
                    });
                }
            }
            Method::DELETE => return Some(Route::DeleteUpload { namespace, uuid }),
            _ => {}
        }
    }

    None
}

fn try_find_blobs<'a>(method: &Method, path: &'a str) -> Option<Route<'a>> {
    if let Some(blob_position) = path.rfind("/blobs/") {
        let namespace = &path[..blob_position];

        let digest = &path[blob_position + "/blobs/".len()..];
        let digest = Digest::from_str(digest).ok()?;

        match *method {
            Method::GET => return Some(Route::GetBlob { namespace, digest }),
            Method::HEAD => return Some(Route::HeadBlob { namespace, digest }),
            Method::DELETE => return Some(Route::DeleteBlob { namespace, digest }),
            _ => {}
        }
    }

    None
}

fn try_find_manifests<'a>(method: &Method, path: &'a str) -> Option<Route<'a>> {
    if let Some(manifest_position) = path.rfind("/manifests/") {
        let namespace = &path[..manifest_position];

        let reference = &path[manifest_position + "/manifests/".len()..];
        let reference = Reference::from_str(reference).ok()?;

        match *method {
            Method::GET => {
                return Some(Route::GetManifest {
                    namespace,
                    reference,
                })
            }
            Method::HEAD => {
                return Some(Route::HeadManifest {
                    namespace,
                    reference,
                })
            }
            Method::PUT => {
                return Some(Route::PutManifest {
                    namespace,
                    reference,
                })
            }
            Method::DELETE => {
                return Some(Route::DeleteManifest {
                    namespace,
                    reference,
                })
            }
            _ => {}
        }
    }

    None
}

fn try_find_referrers<'a>(
    method: &Method,
    path: &'a str,
    params: Option<&'a str>,
) -> Option<Route<'a>> {
    if let Some(referrers_position) = path.rfind("/referrers/") {
        let namespace = &path[..referrers_position];

        let digest = &path[referrers_position + "/referrers/".len()..];
        let digest = Digest::from_str(digest).ok()?;

        let artifact_type = params
            .map(ArtifactTypeQuery::from_params)
            .and_then(|f| f.artifact_type);

        if *method == Method::GET {
            return Some(Route::GetReferrer {
                namespace,
                digest,
                artifact_type,
            });
        }
    }

    None
}

fn try_find_tags<'a>(method: &Method, path: &'a str, params: Option<&'a str>) -> Option<Route<'a>> {
    if let Some(namespace) = path.strip_suffix("/tags/list") {
        if *method == Method::GET {
            let (n, last) = if let Some(p) = params.map(PaginationQuery::from_params) {
                (p.n, p.last)
            } else {
                (None, None)
            };

            return Some(Route::ListTags { namespace, n, last });
        }
    }

    None
}
