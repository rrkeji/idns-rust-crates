// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use crate::resolution::DocumentMetadata;
use crate::resolution::ResolutionMetadata;
use crate::resolution::Resource;

/// The output returned from [DID URL dereferencing][SPEC].
///
/// [SPEC]: https://www.w3.org/TR/did-core/#dfn-did-url-dereferencing
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Dereference {
  /// Metadata regarding the base resolution process.
  #[serde(rename = "dereferencingMetadata")]
  pub metadata: ResolutionMetadata,
  /// The output resource of a successful dereference.
  #[serde(rename = "contentStream", skip_serializing_if = "Option::is_none")]
  pub content: Option<Resource>,
  /// Content-specific metadata.
  #[serde(rename = "contentMetadata", skip_serializing_if = "Option::is_none")]
  pub content_metadata: Option<DocumentMetadata>,
}

impl Dereference {
  /// Creates a new `Dereference`.
  pub fn new() -> Self {
    Self {
      metadata: ResolutionMetadata::new(),
      content: None,
      content_metadata: None,
    }
  }
}
