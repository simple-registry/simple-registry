//! Construction shortcuts for [`Manifest`]: nothing in the serving paths builds
//! one, they only parse, so these exist purely for the fixtures.

use crate::oci::{Content, Descriptor, Manifest};

impl Manifest {
    /// An image manifest carrying `config` and `layers`, every other field left
    /// at its default.
    pub fn image(config: Option<Descriptor>, layers: Vec<Descriptor>) -> Self {
        Self {
            content: Content::Image {
                config: config.map(Box::new),
                layers,
            },
            ..Self::default()
        }
    }

    /// An index listing `manifests`, every other field left at its default.
    pub fn index(manifests: Vec<Descriptor>) -> Self {
        Self {
            content: Content::Index { manifests },
            ..Self::default()
        }
    }
}
