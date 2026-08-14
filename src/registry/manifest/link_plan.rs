//! Link-operation planners for manifest push and delete.
//!
//! These functions map a parsed `Manifest` plus its reference and media-type
//! context to a `Vec<LinkOperation>` ready to be passed directly to
//! `MetadataStore::update_links`. They perform no I/O. `push` consumes the
//! manifest's `annotations` via `Manifest::take_descriptor` when emitting a
//! referrer back-link.
//!
//! Using these planners in both the runtime write path and the scrub executor
//! ensures that both sides apply the same decisions about which links to create
//! or delete for a given manifest, eliminating divergence between them.

use angos_oci::{Content, Digest, Manifest, MediaType, Reference, Tag};

use crate::registry::metadata_store::{LinkKind, LinkOperation};

/// Produces the `LinkOperation::Create` set needed to store a manifest
/// identified by `digest` under `reference`.
///
/// Emits in order: digest self-link, tag link (only for `Reference::Tag`),
/// subject referrer back-link (only when the manifest has a `subject`; carries
/// the full `Descriptor` when `media_type` is set), config link, layer links
/// in manifest order, child-manifest links in manifest order. Every config /
/// layer / child link records the parent `digest` as referrer.
///
/// `effective_media_type` is the caller-resolved
/// `content_type.or(manifest.media_type)`. `manifest.annotations` is moved
/// out when a referrer back-link is emitted.
///
/// `created_tags` carries the tags requested via `?tag=` query parameters on a
/// by-digest push; one extra tag link is emitted per entry. The caller must
/// have validated each value as a well-formed tag.
pub fn push(
    manifest: &mut Manifest,
    digest: &Digest,
    reference: &Reference,
    effective_media_type: Option<&MediaType>,
    body_len: u64,
    created_tags: &[Tag],
) -> Vec<LinkOperation> {
    let mut ops = Vec::new();

    ops.push(LinkOperation::create_with_media_type(
        LinkKind::Digest(digest.clone()),
        digest.clone(),
        effective_media_type.cloned(),
    ));

    if let Some(tag) = reference.as_tag() {
        ops.push(LinkOperation::create_with_media_type(
            LinkKind::Tag(tag.clone()),
            digest.clone(),
            effective_media_type.cloned(),
        ));
    }

    for tag in created_tags {
        ops.push(LinkOperation::create_with_media_type(
            LinkKind::Tag(tag.clone()),
            digest.clone(),
            effective_media_type.cloned(),
        ));
    }

    if let Some(subject) = &manifest.subject {
        let referrer_link = LinkKind::Referrer {
            subject: subject.digest.clone(),
            referrer: digest.clone(),
        };
        ops.push(LinkOperation::create_with_descriptor(
            referrer_link,
            digest.clone(),
            Box::new(manifest.take_descriptor(digest.clone(), body_len)),
        ));
    }

    for (link, target) in referenced_links(manifest, digest) {
        ops.push(LinkOperation::create_with_referrer(
            link,
            target,
            digest.clone(),
        ));
    }

    ops
}

/// Produces the set of `LinkOperation::Delete` operations needed to remove a
/// manifest identified by `reference` from the metadata store.
///
/// - `Reference::Tag` → one tag delete.
/// - `Reference::Digest` → digest self-link delete + one delete per tag in
///   `tags_pointing_at_digest` + (when `manifest` is `Some`) the subject
///   referrer back-link + `delete_with_referrer` for each config / layer /
///   child manifest using the parent's digest as referrer.
///
/// `tags_pointing_at_digest` should contain the `LinkKind::Tag(...)` entries
/// already pointing at the digest. Passing an empty slice is safe and correct
/// when the caller has confirmed no tags point at the digest.
pub fn delete(
    reference: &Reference,
    manifest: Option<&Manifest>,
    tags_pointing_at_digest: &[LinkKind],
) -> Vec<LinkOperation> {
    match reference {
        Reference::Tag(tag) => vec![LinkOperation::delete(LinkKind::Tag(tag.clone()))],
        Reference::Digest(digest) => {
            let mut ops = Vec::new();

            ops.push(LinkOperation::delete(LinkKind::Digest(digest.clone())));

            for tag_link in tags_pointing_at_digest {
                ops.push(LinkOperation::delete(tag_link.clone()));
            }

            if let Some(m) = manifest {
                if let Some(subject) = &m.subject {
                    ops.push(LinkOperation::delete(LinkKind::Referrer {
                        subject: subject.digest.clone(),
                        referrer: digest.clone(),
                    }));
                }

                for (link, _) in referenced_links(m, digest) {
                    ops.push(LinkOperation::delete_with_referrer(link, digest.clone()));
                }
            }

            ops
        }
    }
}

/// The links a stored revision implies, each paired with the digest it targets:
/// the manifest's referenced links plus, for a subject-bearing manifest, the
/// referrer back-link pointing at the revision itself.
pub fn revision_links(manifest: &Manifest, revision: &Digest) -> Vec<(LinkKind, Digest)> {
    let mut links = referenced_links(manifest, revision);

    if let Some(subject) = &manifest.subject {
        links.push((
            LinkKind::Referrer {
                subject: subject.digest.clone(),
                referrer: revision.clone(),
            },
            revision.clone(),
        ));
    }

    links
}

/// The config / layer / child-manifest links `manifest` implies under
/// `revision`, each paired with the digest it targets. Config and layers come
/// in manifest order, and an index yields its children instead.
pub fn referenced_links(manifest: &Manifest, revision: &Digest) -> Vec<(LinkKind, Digest)> {
    match &manifest.content {
        Content::Image { config, layers } => {
            let config = config.iter().map(|config| {
                (
                    LinkKind::Config(config.digest.clone()),
                    config.digest.clone(),
                )
            });
            let layers = layers
                .iter()
                .map(|layer| (LinkKind::Layer(layer.digest.clone()), layer.digest.clone()));
            config.chain(layers).collect()
        }
        Content::Index { manifests } => manifests
            .iter()
            .map(|child| {
                (
                    LinkKind::Manifest {
                        index: revision.clone(),
                        child: child.digest.clone(),
                    },
                    child.digest.clone(),
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use angos_oci::{Descriptor, Manifest, Tag};

    use crate::registry::manifest::link_plan::*;
    use crate::registry::test_utils::media_type;

    fn d(byte: u8) -> Digest {
        let hex = format!("{byte:02x}").repeat(32);
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    fn descriptor(digest: Digest) -> Descriptor {
        Descriptor {
            media_type: media_type("application/vnd.oci.image.layer.v1.tar+gzip"),
            digest,
            size: 0,
            annotations: HashMap::new(),
            artifact_type: None,
            platform: None,
        }
    }

    fn minimal_manifest() -> Manifest {
        Manifest::default()
    }

    fn manifest_with_config_and_layer(config: Digest, layer: Digest) -> Manifest {
        Manifest::image(Some(descriptor(config)), vec![descriptor(layer)])
    }

    fn manifest_with_subject(subject: Digest) -> Manifest {
        Manifest {
            media_type: Some(media_type("application/vnd.oci.image.manifest.v1+json")),
            subject: Some(descriptor(subject)),
            ..Manifest::default()
        }
    }

    fn manifest_with_child(child: Digest) -> Manifest {
        Manifest::index(vec![descriptor(child)])
    }

    // push

    #[test]
    fn push_digest_self_link_always_present() {
        let digest = d(0xaa);
        let mut m = minimal_manifest();
        let ops = push(
            &mut m,
            &digest,
            &Reference::Digest(digest.clone()),
            None,
            0,
            &[],
        );

        let has_self = ops.iter().any(|op| {
            matches!(op, LinkOperation::Create { link: LinkKind::Digest(d), .. } if d == &digest)
        });
        assert!(has_self, "digest self-link must always be present");
    }

    #[test]
    fn push_tag_link_only_for_tag_reference() {
        let digest = d(0x01);
        let mut m_tag = minimal_manifest();
        let ops_tag = push(
            &mut m_tag,
            &digest,
            &Reference::Tag(Tag::new("latest").unwrap()),
            None,
            0,
            &[],
        );
        let tag_count = ops_tag
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    LinkOperation::Create {
                        link: LinkKind::Tag(_),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(tag_count, 1, "exactly one tag link for a Tag reference");

        let mut m_dig = minimal_manifest();
        let ops_dig = push(
            &mut m_dig,
            &digest,
            &Reference::Digest(digest.clone()),
            None,
            0,
            &[],
        );
        let tag_count_dig = ops_dig
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    LinkOperation::Create {
                        link: LinkKind::Tag(_),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(tag_count_dig, 0, "no tag link for a Digest reference");
    }

    #[test]
    fn push_created_tags_emit_one_tag_link_each() {
        let digest = d(0x02);
        let mut m = minimal_manifest();
        let extra = vec![
            Tag::new("1.2.3").unwrap(),
            Tag::new("1.2").unwrap(),
            Tag::new("latest").unwrap(),
        ];
        let ops = push(
            &mut m,
            &digest,
            &Reference::Digest(digest.clone()),
            None,
            0,
            &extra,
        );

        let tag_links: Vec<&Tag> = ops
            .iter()
            .filter_map(|op| match op {
                LinkOperation::Create {
                    link: LinkKind::Tag(t),
                    ..
                } => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(tag_links.len(), 3, "one tag link per additional tag");
        assert!(tag_links.iter().all(|t| extra.contains(t)));
    }

    #[test]
    fn push_empty_created_tags_emit_no_tag_links() {
        let digest = d(0x03);
        let mut m = minimal_manifest();
        let ops = push(
            &mut m,
            &digest,
            &Reference::Digest(digest.clone()),
            None,
            0,
            &[],
        );
        let tag_count = ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    LinkOperation::Create {
                        link: LinkKind::Tag(_),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(tag_count, 0, "empty additional tags emit no tag links");
    }

    #[test]
    fn push_config_and_layer_ops_carry_parent_referrer() {
        let parent = d(0x10);
        let config = d(0x11);
        let layer = d(0x12);
        let mut m = manifest_with_config_and_layer(config.clone(), layer.clone());
        let ops = push(
            &mut m,
            &parent,
            &Reference::Digest(parent.clone()),
            None,
            0,
            &[],
        );

        let Some(LinkOperation::Create { referrer, .. }) = ops.iter().find(|op| {
            matches!(
                op,
                LinkOperation::Create {
                    link: LinkKind::Config(_),
                    ..
                }
            )
        }) else {
            panic!("config Create op must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));

        let Some(LinkOperation::Create { referrer, .. }) = ops.iter().find(|op| {
            matches!(
                op,
                LinkOperation::Create {
                    link: LinkKind::Layer(_),
                    ..
                }
            )
        }) else {
            panic!("layer Create op must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));
    }

    #[test]
    fn push_child_manifest_op_carries_parent_referrer() {
        let parent = d(0x20);
        let child = d(0x21);
        let mut m = manifest_with_child(child.clone());
        let ops = push(
            &mut m,
            &parent,
            &Reference::Digest(parent.clone()),
            None,
            0,
            &[],
        );

        let Some(LinkOperation::Create { referrer, .. }) = ops.iter().find(|op| {
            matches!(op, LinkOperation::Create { link: LinkKind::Manifest { index: p, child: c }, .. } if p == &parent && c == &child)
        }) else {
            panic!("child manifest Create op must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));
    }

    #[test]
    fn push_total_op_count_for_simple_manifest_with_media_type() {
        // manifest with media_type + config + layer → no subject, no children
        let digest = d(0x30);
        let config = d(0x31);
        let layer = d(0x32);
        let media_type = media_type("application/vnd.oci.image.manifest.v1+json");
        let mut m = Manifest {
            media_type: Some(media_type.clone()),
            ..Manifest::image(Some(descriptor(config)), vec![descriptor(layer)])
        };

        let ops = push(
            &mut m,
            &digest,
            &Reference::Tag(Tag::new("v1").unwrap()),
            Some(&media_type),
            42,
            &[],
        );
        // Expected: digest-link + tag-link + config + layer = 4
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn push_subject_referrer_uses_descriptor_when_media_type_set() {
        let parent = d(0x40);
        let subject = d(0x41);
        let media_type = media_type("application/vnd.oci.image.manifest.v1+json");
        let mut m = manifest_with_subject(subject.clone());
        let ops = push(
            &mut m,
            &parent,
            &Reference::Digest(parent.clone()),
            Some(&media_type),
            100,
            &[],
        );

        let Some(LinkOperation::Create { descriptor, .. }) = ops.iter().find(|op| {
            matches!(op, LinkOperation::Create { link: LinkKind::Referrer { subject: s, referrer: r }, .. } if s == &subject && r == &parent)
        }) else {
            panic!("referrer Create op must be present");
        };
        assert!(
            descriptor.is_some(),
            "descriptor must be set when media_type is present"
        );
    }

    // delete

    #[test]
    fn delete_tag_reference_emits_single_tag_delete() {
        let ops = delete(&Reference::Tag(Tag::new("latest").unwrap()), None, &[]);
        assert_eq!(ops.len(), 1);
        assert!(
            matches!(&ops[0], LinkOperation::Delete { link: LinkKind::Tag(t), referrer: None } if t == "latest")
        );
    }

    #[test]
    fn delete_digest_with_no_manifest_and_no_tags_emits_single_delete() {
        let digest = d(0x50);
        let ops = delete(&Reference::Digest(digest.clone()), None, &[]);
        assert_eq!(ops.len(), 1);
        assert!(
            matches!(&ops[0], LinkOperation::Delete { link: LinkKind::Digest(d), .. } if d == &digest)
        );
    }

    #[test]
    fn delete_digest_with_tags_removes_them_all() {
        let digest = d(0x60);
        let tags = vec![
            LinkKind::Tag(Tag::new("v1").unwrap()),
            LinkKind::Tag(Tag::new("latest").unwrap()),
        ];
        let ops = delete(&Reference::Digest(digest.clone()), None, &tags);

        let tag_deletes: Vec<_> = ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    LinkOperation::Delete {
                        link: LinkKind::Tag(_),
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(tag_deletes.len(), 2);
    }

    #[test]
    fn delete_digest_with_manifest_removes_config_and_layers_with_referrer() {
        let parent = d(0x70);
        let config = d(0x71);
        let layer = d(0x72);
        let m = manifest_with_config_and_layer(config.clone(), layer.clone());

        let ops = delete(&Reference::Digest(parent.clone()), Some(&m), &[]);

        let Some(LinkOperation::Delete { referrer, .. }) = ops.iter().find(|op| {
            matches!(
                op,
                LinkOperation::Delete {
                    link: LinkKind::Config(_),
                    referrer: Some(_)
                }
            )
        }) else {
            panic!("config Delete op with referrer must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));

        let Some(LinkOperation::Delete { referrer, .. }) = ops.iter().find(|op| {
            matches!(
                op,
                LinkOperation::Delete {
                    link: LinkKind::Layer(_),
                    referrer: Some(_)
                }
            )
        }) else {
            panic!("layer Delete op with referrer must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));
    }

    #[test]
    fn delete_digest_with_subject_removes_referrer_link() {
        let parent = d(0x80);
        let subject = d(0x81);
        let m = manifest_with_subject(subject.clone());

        let ops = delete(&Reference::Digest(parent.clone()), Some(&m), &[]);

        let referrer_op = ops.iter().find(|op| {
            matches!(op, LinkOperation::Delete { link: LinkKind::Referrer { subject: s, referrer: r }, .. } if s == &subject && r == &parent)
        });
        assert!(
            referrer_op.is_some(),
            "referrer delete must be present for manifest with subject"
        );
    }

    #[test]
    fn delete_digest_with_children_removes_child_manifest_links() {
        let parent = d(0x90);
        let child = d(0x91);
        let m = manifest_with_child(child.clone());

        let ops = delete(&Reference::Digest(parent.clone()), Some(&m), &[]);

        let Some(LinkOperation::Delete { referrer, .. }) = ops.iter().find(|op| {
            matches!(op, LinkOperation::Delete { link: LinkKind::Manifest { index: p, child: c }, referrer: Some(_) } if p == &parent && c == &child)
        }) else {
            panic!("child manifest Delete op with referrer must be present");
        };
        assert_eq!(referrer.as_ref(), Some(&parent));
    }
}
