// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub type ClientError =  identity_did::Error;
pub type InvalidMessage =  identity_did::Error;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Error {
  #[error("{0}")]
  CoreError(#[from] identity_core::Error),
  #[error("{0}")]
  DiffError(#[from] identity_core::diff::Error),
  #[error("{0}")]
  CredError(#[from] identity_credential::Error),
  #[error("{0}")]
  InvalidDID(#[from] identity_did::did::DIDError),
  #[error("{0}")]
  InvalidDoc(#[from] identity_did::Error),
  // #[error("{0}")]
  // ClientError(#[from] ClientError),
  // #[error("Invalid Message: {0}")]
  // InvalidMessage(#[from] InvalidMessage),

  #[error("{0}")]
  DIDNotFound(String),
  #[error("Invalid Document - Missing Message Id")]
  InvalidDocumentMessageId,
  #[error("Invalid Document - Signing Verification Method Type Not Supported")]
  InvalidDocumentSigningMethodType,
  #[error("Invalid Verification Method - Missing Fragment")]
  InvalidMethodMissingFragment,
  #[error("Invalid Root Document")]
  InvalidRootDocument,
  #[error("Invalid Network Name")]
  InvalidNetworkName,
  #[error("Invalid Presentation Holder")]
  InvalidPresentationHolder,
  #[error("Chain Error: {error}")]
  ChainError { error: &'static str },
  #[error("Missing Signing Key")]
  MissingSigningKey,
  #[error("Cannot Revoke Verification Method")]
  CannotRevokeMethod,
  #[error("no client nodes provided for network")]
  NoClientNodesProvided,
  #[error("No Explorer URL Set")]
  NoExplorerURLSet,
  #[error("Invalid Explorer Url")]
  InvalidExplorerURL,
  #[error("compression error")]
  CompressionError,
  #[error("invalid message flags")]
  InvalidMessageFlags,
}
