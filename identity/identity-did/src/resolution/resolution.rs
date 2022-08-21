// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use crate::document::CoreDocument;
use crate::resolution::DocumentMetadata;
use crate::resolution::ResolutionMetadata;

/// The output returned from [DID resolution][SPEC].
///
/// [SPEC]: https://www.w3.org/TR/did-core/#dfn-did-resolution
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Resolution {
  /// Resolution-specific metadata.
  #[serde(rename = "didResolutionMetadata")]
  pub metadata: ResolutionMetadata,
  /// The DID Document of a successful resolution.
  #[serde(rename = "didDocument", skip_serializing_if = "Option::is_none")]
  pub document: Option<CoreDocument>,
  /// Document-specific metadata.
  #[serde(rename = "didDocumentMetadata", skip_serializing_if = "Option::is_none")]
  pub document_metadata: Option<DocumentMetadata>,
}

impl Resolution {
  /// Creates a new [`Resolution`].
  pub fn new() -> Self {
    Self {
      metadata: ResolutionMetadata::new(),
      document: None,
      document_metadata: None,
    }
  }
}
