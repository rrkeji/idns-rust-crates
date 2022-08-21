// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use identity_core::diff::Diff;
use identity_core::diff::DiffObject;
use identity_core::diff::DiffString;
use identity_core::diff::Result;

use crate::verification::MethodData;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum DiffMethodData {
  PublicKeyMultibase(#[serde(skip_serializing_if = "Option::is_none")] Option<DiffString>),
  PublicKeyBase58(#[serde(skip_serializing_if = "Option::is_none")] Option<DiffString>),
  PublicKeyJwk(#[serde(skip_serializing_if = "Option::is_none")] Option<DiffObject>),
}

impl Diff for MethodData {
  type Type = DiffMethodData;

  fn diff(&self, other: &Self) -> Result<Self::Type> {
    match (self, other) {
      (Self::PublicKeyMultibase(a), Self::PublicKeyMultibase(b)) if a == b => {
        Ok(DiffMethodData::PublicKeyMultibase(None))
      }
      (Self::PublicKeyMultibase(a), Self::PublicKeyMultibase(b)) => {
        a.diff(b).map(Some).map(DiffMethodData::PublicKeyMultibase)
      }
      (Self::PublicKeyBase58(a), Self::PublicKeyBase58(b)) if a == b => Ok(DiffMethodData::PublicKeyBase58(None)),
      (Self::PublicKeyBase58(a), Self::PublicKeyBase58(b)) => a.diff(b).map(Some).map(DiffMethodData::PublicKeyBase58),
      (Self::PublicKeyJwk(a), Self::PublicKeyJwk(b)) if a == b => Ok(DiffMethodData::PublicKeyJwk(None)),
      (Self::PublicKeyJwk(a), Self::PublicKeyJwk(b)) => a.diff(b).map(Some).map(DiffMethodData::PublicKeyJwk),
      (_, _) => other.clone().into_diff(),
    }
  }

  fn merge(&self, diff: Self::Type) -> Result<Self> {
    match (self, diff) {
      (Self::PublicKeyMultibase(a), DiffMethodData::PublicKeyMultibase(Some(b))) => {
        a.merge(b).map(Self::PublicKeyMultibase)
      }
      (Self::PublicKeyMultibase(a), DiffMethodData::PublicKeyMultibase(None)) => {
        Ok(Self::PublicKeyMultibase(a.clone()))
      }
      (Self::PublicKeyBase58(a), DiffMethodData::PublicKeyBase58(Some(b))) => a.merge(b).map(Self::PublicKeyBase58),
      (Self::PublicKeyBase58(a), DiffMethodData::PublicKeyBase58(None)) => Ok(Self::PublicKeyBase58(a.clone())),
      (Self::PublicKeyJwk(a), DiffMethodData::PublicKeyJwk(Some(b))) => a.merge(b).map(Self::PublicKeyJwk),
      (Self::PublicKeyJwk(a), DiffMethodData::PublicKeyJwk(None)) => Ok(Self::PublicKeyJwk(a.clone())),
      (_, diff) => Self::from_diff(diff),
    }
  }

  fn from_diff(diff: Self::Type) -> Result<Self> {
    match diff {
      DiffMethodData::PublicKeyMultibase(Some(value)) => Diff::from_diff(value).map(Self::PublicKeyMultibase),
      DiffMethodData::PublicKeyMultibase(None) => Ok(Self::PublicKeyMultibase(Default::default())),
      DiffMethodData::PublicKeyBase58(Some(value)) => Diff::from_diff(value).map(Self::PublicKeyBase58),
      DiffMethodData::PublicKeyBase58(None) => Ok(Self::PublicKeyBase58(Default::default())),
      DiffMethodData::PublicKeyJwk(Some(value)) => Diff::from_diff(value).map(Self::PublicKeyJwk),
      DiffMethodData::PublicKeyJwk(None) => Ok(Self::PublicKeyJwk(Default::default())),
    }
  }

  fn into_diff(self) -> Result<Self::Type> {
    match self {
      Self::PublicKeyMultibase(value) => value.into_diff().map(Some).map(DiffMethodData::PublicKeyMultibase),
      Self::PublicKeyBase58(value) => value.into_diff().map(Some).map(DiffMethodData::PublicKeyBase58),
      Self::PublicKeyJwk(value) => value.into_diff().map(Some).map(DiffMethodData::PublicKeyJwk),
    }
  }
}
