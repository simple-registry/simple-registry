use crate::cmd::server::{
    BlobParameters, ManifestParameters, NewUploadParameters, ReferrerParameters, TagsParameters,
    UploadParameters, RANGE_RE,
};
use crate::error::RegistryError;
use crate::oci::{Digest, ReferrerList};
use crate::policy::{ClientAction, ClientIdentity};
use crate::registry::{BlobData, NewUpload, Registry, RegistryResponseBody};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tracing::{instrument, warn};

pub fn parse_range_header(range_header: &HeaderValue) -> Result<(u64, u64), RegistryError> {
    let range_str = range_header.to_str().map_err(|e| {
        warn!("Error parsing Range header as string: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    let captures = RANGE_RE.captures(range_str).ok_or_else(|| {
        warn!("Invalid Range header format: {}", range_str);
        RegistryError::RangeNotSatisfiable
    })?;

    let (Some(start), Some(end)) = (captures.name("start"), captures.name("end")) else {
        return Err(RegistryError::RangeNotSatisfiable);
    };

    let start = start.as_str().parse::<u64>().map_err(|e| {
        warn!("Error parsing 'start' in Range header: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    let end = end.as_str().parse::<u64>().map_err(|e| {
        warn!("Error parsing 'end' in Range header: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    if start > end {
        warn!(
            "Range start ({}) is greater than range end ({})",
            start, end
        );
        return Err(RegistryError::RangeNotSatisfiable);
    }

    Ok((start, end))
}

pub fn parse_query_parameters<T: DeserializeOwned + Default>(
    query: Option<&str>,
) -> Result<T, RegistryError> {
    let Some(query) = query else {
        return Ok(Default::default());
    };

    serde_urlencoded::from_str(query).map_err(|e| {
        warn!("Failed to parse query parameters: {}", e);
        RegistryError::Unsupported
    })
}

pub fn paginated_response(
    body: String,
    link: Option<String>,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let res = match link {
        Some(link) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Link", format!("<{}>; rel=\"next\"", link))
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
        None => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
    };

    Ok(res)
}

#[instrument]
pub async fn handle_get_api_version(
    registry: &Registry,
    identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::GetApiVersion)?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_get_manifest(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::GetManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let manifest = registry
        .get_manifest(&parameters.name, parameters.reference)
        .await?;

    let res = if let Some(content_type) = manifest.media_type {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(RegistryResponseBody::fixed(manifest.content))?
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(RegistryResponseBody::fixed(manifest.content))?
    };

    Ok(res)
}

#[instrument]
pub async fn handle_head_manifest(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::GetManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let manifest = registry
        .head_manifest(&parameters.name, parameters.reference)
        .await?;

    let res = if let Some(media_type) = manifest.media_type {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", media_type)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("Content-Length", manifest.size)
            .body(RegistryResponseBody::empty())?
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("Content-Length", manifest.size)
            .body(RegistryResponseBody::empty())?
    };

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_get_blob(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::GetBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    let range = request
        .headers()
        .get("range")
        .map(parse_range_header)
        .transpose()?;

    let res = match registry
        .get_blob(&parameters.name, &parameters.digest, range)
        .await?
    {
        BlobData::RangedReader(reader, (start, end), total_length) => {
            let length = end - start + 1;
            let stream = reader.take(length);
            let range = format!("bytes {}-{}/{}", start, end, total_length);

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("Docker-Content-Digest", parameters.digest.to_string())
                .header("Accept-Ranges", "bytes")
                .header("Content-Length", length.to_string())
                .header("Content-Range", range)
                .body(RegistryResponseBody::streaming(stream))?
        }
        BlobData::Reader(stream, total_length) => Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", parameters.digest.to_string())
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", total_length.to_string())
            .body(RegistryResponseBody::streaming(stream))?,
        BlobData::Empty => Response::builder()
            .status(StatusCode::OK)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", "0")
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

#[instrument]
pub async fn handle_head_blob(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::GetBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    let blob = registry
        .head_blob(&parameters.name, parameters.digest)
        .await?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", blob.digest.to_string())
        .header("Content-Length", blob.size.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_start_upload(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: NewUploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::PutBlob(parameters.name.clone()))?;

    #[derive(Deserialize, Default)]
    struct UploadQuery {
        digest: Option<String>,
    }

    let query: UploadQuery = parse_query_parameters(request.uri().query())?;
    let digest = query
        .digest
        .map(|s| Digest::try_from(s.as_str()))
        .transpose()?;

    let res = match registry.start_upload(&parameters.name, digest).await? {
        NewUpload::ExistingBlob(digest) => Response::builder()
            .status(StatusCode::CREATED)
            .header(
                "Location",
                format!("/v2/{}/blobs/{}", parameters.name, digest),
            )
            .header("Docker-Content-Digest", digest.to_string())
            .body(RegistryResponseBody::empty())?,
        NewUpload::Session(location, session_uuid) => Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Location", location)
            .header("Range", "0-0")
            .header("Docker-Upload-UUID", session_uuid.to_string())
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_patch_upload(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::PutBlob(parameters.name.clone()))?;

    let range = request
        .headers()
        .get("content-range")
        .map(parse_range_header)
        .transpose()?;

    let start_offset = range.map(|(start, _)| start);

    let body = request.into_data_stream();
    let location = format!("/v2/{}/blobs/uploads/{}", &parameters.name, parameters.uuid);

    let range_max = registry
        .patch_upload(&parameters.name, parameters.uuid, start_offset, body)
        .await?;
    let range_max = format!("0-{}", range_max);

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", location)
        .header("Range", range_max)
        .header("Content-Length", "0")
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_put_upload(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::PutBlob(parameters.name.clone()))?;

    #[derive(Deserialize, Default)]
    struct CompleteUploadQuery {
        digest: String,
    }

    let query: CompleteUploadQuery = parse_query_parameters(request.uri().query())?;
    let digest = Digest::try_from(query.digest.as_str())?;

    let body = request.into_data_stream();
    registry
        .complete_upload(&parameters.name, parameters.uuid, digest.clone(), body)
        .await?;

    let location = format!("/v2/{}/blobs/{}", &parameters.name, digest);

    let res = Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", location)
        .header("Docker-Content-Digest", digest.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_delete_upload(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::PutBlob(parameters.name.clone()))?;

    registry
        .delete_upload(&parameters.name, parameters.uuid)
        .await?;

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_get_upload_progress(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: UploadParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::PutBlob(parameters.name.clone()))?;

    let location = format!("/v2/{}/blobs/uploads/{}", parameters.name, parameters.uuid);

    let range_max = registry
        .get_upload_range_max(&parameters.name, parameters.uuid)
        .await?;
    let range_max = format!("0-{}", range_max);

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Location", location)
        .header("Range", range_max)
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_delete_blob(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: BlobParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::DeleteBlob(parameters.name.clone(), parameters.digest.clone()),
    )?;

    registry
        .delete_blob(&parameters.name, parameters.digest)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_put_manifest(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::PutManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    let content_type = request
        .headers()
        .get("Content-Type")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| {
            RegistryError::ManifestInvalid(Some(
                "Unable to parse provided Content-Type header".to_string(),
            ))
        })?
        .ok_or(RegistryError::ManifestInvalid(Some(
            "No Content-Type header provided".to_string(),
        )))?
        .to_string();

    let request_body = request.into_body().collect().await.map_err(|_| {
        RegistryError::ManifestInvalid(Some(
            "Unable to retrieve manifest from client query".to_string(),
        ))
    })?;
    let body = request_body.to_bytes();

    let manifest = registry
        .put_manifest(
            &parameters.name,
            parameters.reference.clone(),
            content_type,
            &body,
        )
        .await?;
    let location = format!("/v2/{}/manifests/{}", parameters.name, parameters.reference);

    let res = match manifest.subject {
        Some(subject) => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("OCI-Subject", subject.to_string())
            .body(RegistryResponseBody::empty())?,
        None => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(RegistryResponseBody::empty())?,
    };

    Ok(res)
}

#[instrument]
pub async fn handle_delete_manifest(
    registry: &Registry,
    identity: ClientIdentity,
    parameters: ManifestParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::DeleteManifest(parameters.name.clone(), parameters.reference.clone()),
    )?;

    registry
        .delete_manifest(&parameters.name, parameters.reference)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(RegistryResponseBody::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_get_referrers(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: ReferrerParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(
        registry,
        ClientAction::GetReferrers(parameters.name.clone(), parameters.digest.clone()),
    )?;

    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct GetReferrersQuery {
        artifact_type: Option<String>,
    }

    let query: GetReferrersQuery = parse_query_parameters(request.uri().query())?;

    let manifests = registry
        .get_referrers(
            &parameters.name,
            parameters.digest,
            query.artifact_type.clone(),
        )
        .await?;

    let referrer_list = ReferrerList {
        manifests,
        ..ReferrerList::default()
    };
    let referrer_list = serde_json::to_string(&referrer_list)?.into_bytes();

    let res = match query.artifact_type {
        Some(_) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .header("OCI-Filters-Applied", "artifactType")
            .body(RegistryResponseBody::fixed(referrer_list))?,
        None => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .body(RegistryResponseBody::fixed(referrer_list))?,
    };

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_list_catalog(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::ListCatalog)?;

    #[derive(Debug, Deserialize, Default)]
    struct CatalogQuery {
        n: Option<u32>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct CatalogResponse {
        repositories: Vec<String>,
    }

    let query: CatalogQuery = parse_query_parameters(request.uri().query())?;

    let (repositories, link) = registry.list_catalog(query.n, query.last).await?;

    let catalog = CatalogResponse { repositories };
    let catalog = serde_json::to_string(&catalog)?;

    paginated_response(catalog, link)
}

#[instrument(skip(request))]
pub async fn handle_list_tags(
    registry: &Registry,
    request: Request<Incoming>,
    identity: ClientIdentity,
    parameters: TagsParameters,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    identity.can_do(registry, ClientAction::ListTags(parameters.name.clone()))?;

    #[derive(Deserialize, Debug, Default)]
    struct TagsQuery {
        n: Option<u32>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct TagsResponse {
        name: String,
        tags: Vec<String>,
    }

    let query: TagsQuery = parse_query_parameters(request.uri().query())?;

    let (tags, link) = registry
        .list_tags(&parameters.name, query.n, query.last)
        .await?;

    let tag_list = TagsResponse {
        name: parameters.name.to_string(),
        tags,
    };
    let tag_list = serde_json::to_string(&tag_list)?;
    paginated_response(tag_list, link)
}
