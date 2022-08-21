// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;

use crate::did::CoreDID;
use crate::document::CoreDocument;
use crate::error::Result;
use crate::resolution::DocumentMetadata;
use crate::resolution::InputMetadata;

/// A resolved [`Document`] and associated [`DocumentMetadata`].
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct MetaDocument {
  /// A resolved DID Document.
  pub data: CoreDocument,
  /// Information regarding the associated Documents resolution process.
  pub meta: DocumentMetadata,
}

/// A trait for generic DID Resolvers.
#[async_trait(?Send)]
pub trait ResolverMethod {
  /// Returns `true` if the given `did` is supported by this DID Resolver.
  fn is_supported(&self, did: &CoreDID) -> bool;

  /// Performs the "Read" operation of the DID method.
  async fn read(&self, did: &CoreDID, input: InputMetadata) -> Result<Option<MetaDocument>>;
}

#[async_trait(?Send)]
impl<T> ResolverMethod for &'_ T
where
  T: ResolverMethod + Send + Sync,
{
  fn is_supported(&self, did: &CoreDID) -> bool {
    (**self).is_supported(did)
  }

  async fn read(&self, did: &CoreDID, input: InputMetadata) -> Result<Option<MetaDocument>> {
    (**self).read(did, input).await
  }
}
