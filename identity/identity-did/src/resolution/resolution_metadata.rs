// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use identity_core::common::Object;

use crate::did::CoreDID;
use crate::resolution::ErrorKind;

/// Metadata associated with a [DID resolution][SPEC] process.
///
/// [SPEC]: https://www.w3.org/TR/did-core/#dfn-did-resolution
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct ResolutionMetadata {
  /// The error code from the resolution process, if an error occurred.
  ///
  /// [More Info](https://www.w3.org/TR/did-spec-registries/#error)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<ErrorKind>,
  /// The MIME type of the returned document stream.
  ///
  /// Note: This is only relevant when using stream-based resolution.
  ///
  /// [More Info](https://www.w3.org/TR/did-spec-registries/#content-type)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub content_type: Option<String>,
  /// The elapsed time of the resolution operation.
  pub duration: Duration,
  /// The parsed DID that was used for resolution.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub resolved: Option<CoreDID>,
  /// Additional resolution metadata properties.
  #[serde(flatten)]
  pub properties: Object,
}

impl ResolutionMetadata {
  /// Creates a new [`ResolutionMetadata`].
  pub fn new() -> Self {
    Self {
      error: None,
      content_type: None,
      duration: Duration::from_secs(0),
      resolved: None,
      properties: Object::new(),
    }
  }
}
