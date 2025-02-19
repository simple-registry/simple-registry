use crate::command::server::{
    BlobParameters, ManifestParameters, NewUploadParameters, ReferrerParameters, TagsParameters,
    UploadParameters,
};
use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::response_ext::ResponseExt;
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::{Digest, ReferrerList};
use crate::registry::{Error, GetBlobResponse, Registry, Repository, StartUploadResponse};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONTENT_RANGE, RANGE};
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tracing::instrument;

#[instrument]
pub async fn handle_get_api_version() -> Result<Response<Body>, Error> {
    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(Body::empty())?;

    Ok(res)
}

#[instrument(skip(registry, repository))]
pub async fn handle_get_manifest<D: DataStore>(
    registry: &Registry<D>,
    repository: &Repository,
    accepted_mime_types: &[String],
    parameters: ManifestParameters,
) -> Result<Response<Body>, Error> {
    let manifest = registry
        .get_manifest(
            repository,
            accepted_mime_types,
            &parameters.name,
            parameters.reference,
        )
        .await?;

    let res = if let Some(content_type) = manifest.media_type {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(Body::fixed(manifest.content))?
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(Body::fixed(manifest.content))?
    };

    Ok(res)
}

#[instrument(skip(registry, repository))]
pub async fn handle_head_manifest<D: DataStore>(
    registry: &Registry<D>,
    repository: &Repository,
    accepted_mime_types: &[String],
    parameters: ManifestParameters,
) -> Result<Response<Body>, Error> {
    let manifest = registry
        .head_manifest(
            repository,
            accepted_mime_types,
            &parameters.name,
            parameters.reference,
        )
        .await?;

    let res = if let Some(media_type) = manifest.media_type {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", media_type)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("Content-Length", manifest.size)
            .body(Body::empty())?
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("Content-Length", manifest.size)
            .body(Body::empty())?
    };

    Ok(res)
}

#[instrument(skip(registry, repository, request))]
pub async fn handle_get_blob<D: DataStore + 'static>(
    registry: &Registry<D>,
    repository: &Repository,
    request: Request<Incoming>,
    accepted_mime_types: &[String],
    parameters: BlobParameters,
) -> Result<Response<Body>, Error> {
    let res = match registry
        .get_blob(
            repository,
            accepted_mime_types,
            &parameters.name,
            &parameters.digest,
            request.range(RANGE)?,
        )
        .await?
    {
        GetBlobResponse::RangedReader(reader, (start, end), total_length) => {
            let length = end - start + 1;
            let stream = reader.take(length);
            let range = format!("bytes {start}-{end}/{total_length}");

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("Docker-Content-Digest", parameters.digest.to_string())
                .header("Accept-Ranges", "bytes")
                .header("Content-Length", length.to_string())
                .header("Content-Range", range)
                .body(Body::streaming(stream))?
        }
        GetBlobResponse::Reader(stream, total_length) => Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", parameters.digest.to_string())
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", total_length.to_string())
            .body(Body::streaming(stream))?,
        GetBlobResponse::Empty => Response::builder()
            .status(StatusCode::OK)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", "0")
            .body(Body::empty())?,
    };

    Ok(res)
}

pub async fn handle_head_blob<D: DataStore + 'static>(
    registry: &Registry<D>,
    repository: &Repository,
    accepted_mime_types: &[String],
    parameters: BlobParameters,
) -> Result<Response<Body>, Error> {
    let blob = registry
        .head_blob(
            repository,
            accepted_mime_types,
            &parameters.name,
            parameters.digest,
        )
        .await?;

    let res = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", blob.digest.to_string())
        .header("Content-Length", blob.size.to_string())
        .body(Body::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_start_upload<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: NewUploadParameters,
) -> Result<Response<Body>, Error> {
    #[derive(Deserialize, Default)]
    struct UploadQuery {
        digest: Option<String>,
    }

    let query: UploadQuery = request.query_parameters()?;
    let digest = query
        .digest
        .map(|s| Digest::try_from(s.as_str()))
        .transpose()?;

    let res = match registry.start_upload(&parameters.name, digest).await? {
        StartUploadResponse::ExistingBlob(digest) => Response::builder()
            .status(StatusCode::CREATED)
            .header(
                "Location",
                format!("/v2/{}/blobs/{}", parameters.name, digest),
            )
            .header("Docker-Content-Digest", digest.to_string())
            .body(Body::empty())?,
        StartUploadResponse::Session(location, session_uuid) => Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Location", location)
            .header("Range", "0-0")
            .header("Docker-Upload-UUID", session_uuid.to_string())
            .body(Body::empty())?,
    };

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_patch_upload<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: UploadParameters,
) -> Result<Response<Body>, Error> {
    let start_offset = request.range(CONTENT_RANGE)?.map(|(start, _)| start);

    let body = request.into_data_stream();
    let location = format!("/v2/{}/blobs/uploads/{}", &parameters.name, parameters.uuid);

    let range_max = registry
        .patch_upload(&parameters.name, parameters.uuid, start_offset, body)
        .await?;
    let range_max = format!("0-{range_max}");

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", location)
        .header("Range", range_max)
        .header("Content-Length", "0")
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(Body::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_put_upload<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: UploadParameters,
) -> Result<Response<Body>, Error> {
    #[derive(Deserialize, Default)]
    struct CompleteUploadQuery {
        digest: String,
    }

    let query: CompleteUploadQuery = request.query_parameters()?;
    let digest = Digest::try_from(query.digest.as_str())?;

    let body = request.into_data_stream();
    registry
        .complete_upload(&parameters.name, parameters.uuid, digest, body)
        .await?;

    let location = format!("/v2/{}/blobs/{}", &parameters.name, query.digest);

    let res = Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", location)
        .header("Docker-Content-Digest", query.digest)
        .body(Body::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_delete_upload<D: DataStore>(
    registry: &Registry<D>,
    parameters: UploadParameters,
) -> Result<Response<Body>, Error> {
    registry
        .delete_upload(&parameters.name, parameters.uuid)
        .await?;

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_get_upload_progress<D: DataStore>(
    registry: &Registry<D>,
    parameters: UploadParameters,
) -> Result<Response<Body>, Error> {
    let location = format!("/v2/{}/blobs/uploads/{}", parameters.name, parameters.uuid);

    let range_max = registry
        .get_upload_range_max(&parameters.name, parameters.uuid)
        .await?;
    let range_max = format!("0-{range_max}");

    let res = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Location", location)
        .header("Range", range_max)
        .header("Docker-Upload-UUID", parameters.uuid.to_string())
        .body(Body::empty())?;

    Ok(res)
}

#[instrument]
pub async fn handle_delete_blob<D: DataStore + 'static>(
    registry: &Registry<D>,
    parameters: BlobParameters,
) -> Result<Response<Body>, Error> {
    registry
        .delete_blob(&parameters.name, parameters.digest)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Body::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_put_manifest<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: ManifestParameters,
) -> Result<Response<Body>, Error> {
    let content_type = request
        .headers()
        .get("Content-Type")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| {
            Error::ManifestInvalid("Unable to parse provided Content-Type header".to_string())
        })?
        .ok_or(Error::ManifestInvalid(
            "No Content-Type header provided".to_string(),
        ))?
        .to_string();

    let request_body = request.into_body().collect().await.map_err(|_| {
        Error::ManifestInvalid("Unable to retrieve manifest from client query".to_string())
    })?;
    let body = request_body.to_bytes();

    let location = format!("/v2/{}/manifests/{}", parameters.name, parameters.reference);

    let manifest = registry
        .put_manifest(
            &parameters.name,
            parameters.reference,
            Some(&content_type),
            &body,
        )
        .await?;

    let res = match manifest.subject {
        Some(subject) => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .header("OCI-Subject", subject.to_string())
            .body(Body::empty())?,
        None => Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", location)
            .header("Docker-Content-Digest", manifest.digest.to_string())
            .body(Body::empty())?,
    };

    Ok(res)
}

#[instrument]
pub async fn handle_delete_manifest<D: DataStore>(
    registry: &Registry<D>,
    parameters: ManifestParameters,
) -> Result<Response<Body>, Error> {
    registry
        .delete_manifest(&parameters.name, parameters.reference)
        .await?;

    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Body::empty())?;

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_get_referrers<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: ReferrerParameters,
) -> Result<Response<Body>, Error> {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct GetReferrersQuery {
        artifact_type: Option<String>,
    }

    let query: GetReferrersQuery = request.query_parameters()?;
    let query_supplied_artifact_type = query.artifact_type.is_some();

    let manifests = registry
        .get_referrers(&parameters.name, parameters.digest, query.artifact_type)
        .await?;

    let referrer_list = ReferrerList {
        manifests,
        ..ReferrerList::default()
    };
    let referrer_list = serde_json::to_string(&referrer_list)?.into_bytes();

    let res = if query_supplied_artifact_type {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .header("OCI-Filters-Applied", "artifactType")
            .body(Body::fixed(referrer_list))?
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/vnd.oci.image.index.v1+json")
            .body(Body::fixed(referrer_list))?
    };

    Ok(res)
}

#[instrument(skip(request))]
pub async fn handle_list_catalog<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
) -> Result<Response<Body>, Error> {
    #[derive(Debug, Deserialize, Default)]
    struct CatalogQuery {
        n: Option<u16>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct CatalogResponse {
        repositories: Vec<String>,
    }

    let query: CatalogQuery = request.query_parameters()?;

    let (repositories, link) = registry.list_catalog(query.n, query.last).await?;

    let catalog = CatalogResponse { repositories };
    let catalog = serde_json::to_string(&catalog)?;

    Response::paginated(Body::fixed(catalog.into_bytes()), link.as_deref())
}

#[instrument(skip(request))]
pub async fn handle_list_tags<D: DataStore>(
    registry: &Registry<D>,
    request: Request<Incoming>,
    parameters: TagsParameters,
) -> Result<Response<Body>, Error> {
    #[derive(Deserialize, Debug, Default)]
    struct TagsQuery {
        n: Option<u16>,
        last: Option<String>,
    }

    #[derive(Serialize, Debug)]
    struct TagsResponse {
        name: String,
        tags: Vec<String>,
    }

    let query: TagsQuery = request.query_parameters()?;

    let (tags, link) = registry
        .list_tags(&parameters.name, query.n, query.last)
        .await?;

    let tag_list = TagsResponse {
        name: parameters.name.to_string(),
        tags,
    };
    let tag_list = serde_json::to_string(&tag_list)?;
    Response::paginated(Body::fixed(tag_list.into_bytes()), link.as_deref())
}
