// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;

use serde::Serialize;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::FmtJson;
use identity_core::crypto::SetSignature;
use identity_core::crypto::Signature;
use identity_core::crypto::TrySignature;
use identity_core::crypto::TrySignatureMut;
use identity_did::verification::MethodUriType;
use identity_did::verification::TryMethod;

use crate::credential::CredentialBuilder;
use crate::credential::Evidence;
use crate::credential::Issuer;
use crate::credential::Policy;
use crate::credential::Refresh;
use crate::credential::Schema;
use crate::credential::Status;
use crate::credential::Subject;
use crate::error::Error;
use crate::error::Result;

lazy_static! {
  static ref BASE_CONTEXT: Context = Context::Url(Url::parse("https://www.w3.org/2018/credentials/v1").unwrap());
}

/// Represents a set of claims describing an entity.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Credential<T = Object> {
  /// The JSON-LD context(s) applicable to the `Credential`.
  #[serde(rename = "@context")]
  pub context: OneOrMany<Context>,
  /// A unique `URI` referencing the subject of the `Credential`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<Url>,
  /// One or more URIs defining the type of the `Credential`.
  #[serde(rename = "type")]
  pub types: OneOrMany<String>,
  /// One or more `Object`s representing the `Credential` subject(s).
  #[serde(rename = "credentialSubject")]
  pub credential_subject: OneOrMany<Subject>,
  /// A reference to the issuer of the `Credential`.
  pub issuer: Issuer,
  /// A timestamp of when the `Credential` becomes valid.
  #[serde(rename = "issuanceDate")]
  pub issuance_date: Timestamp,
  /// A timestamp of when the `Credential` should no longer be considered valid.
  #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
  pub expiration_date: Option<Timestamp>,
  /// Information used to determine the current status of the `Credential`.
  #[serde(default, rename = "credentialStatus", skip_serializing_if = "OneOrMany::is_empty")]
  pub credential_status: OneOrMany<Status>,
  /// Information used to assist in the enforcement of a specific `Credential` structure.
  #[serde(default, rename = "credentialSchema", skip_serializing_if = "OneOrMany::is_empty")]
  pub credential_schema: OneOrMany<Schema>,
  /// Service(s) used to refresh an expired `Credential`.
  #[serde(default, rename = "refreshService", skip_serializing_if = "OneOrMany::is_empty")]
  pub refresh_service: OneOrMany<Refresh>,
  /// Terms-of-use specified by the `Credential` issuer.
  #[serde(default, rename = "termsOfUse", skip_serializing_if = "OneOrMany::is_empty")]
  pub terms_of_use: OneOrMany<Policy>,
  /// Human-readable evidence used to support the claims within the `Credential`.
  #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
  pub evidence: OneOrMany<Evidence>,
  /// Indicates that the `Credential` must only be contained within a
  /// [`Presentation`][crate::presentation::Presentation] with a proof issued from the `Credential` subject.
  #[serde(rename = "nonTransferable", skip_serializing_if = "Option::is_none")]
  pub non_transferable: Option<bool>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  pub properties: T,
  /// Proof(s) used to verify a `Credential`
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<Signature>,
}

impl<T> Credential<T> {
  /// Returns the base JSON-LD context.
  pub fn base_context() -> &'static Context {
    &*BASE_CONTEXT
  }

  /// Returns the base type.
  pub const fn base_type() -> &'static str {
    "VerifiableCredential"
  }

  /// Creates a new `CredentialBuilder` to configure a `Credential`.
  ///
  /// This is the same as [CredentialBuilder::new].
  pub fn builder(properties: T) -> CredentialBuilder<T> {
    CredentialBuilder::new(properties)
  }

  /// Returns a new `Credential` based on the `CredentialBuilder` configuration.
  pub fn from_builder(builder: CredentialBuilder<T>) -> Result<Self> {
    let this: Self = Self {
      context: builder.context.into(),
      id: builder.id,
      types: builder.types.into(),
      credential_subject: builder.subject.into(),
      issuer: builder.issuer.ok_or(Error::MissingIssuer)?,
      issuance_date: builder.issuance_date.unwrap_or_default(),
      expiration_date: builder.expiration_date,
      credential_status: builder.status.into(),
      credential_schema: builder.schema.into(),
      refresh_service: builder.refresh.into(),
      terms_of_use: builder.policy.into(),
      evidence: builder.evidence.into(),
      non_transferable: builder.non_transferable,
      properties: builder.properties,
      proof: None,
    };

    this.check_structure()?;

    Ok(this)
  }

  /// Validates the semantic structure of the `Credential`.
  pub fn check_structure(&self) -> Result<()> {
    // Ensure the base context is present and in the correct location
    match self.context.get(0) {
      Some(context) if context == Self::base_context() => {}
      Some(_) | None => return Err(Error::MissingBaseContext),
    }

    // The set of types MUST contain the base type
    if !self.types.iter().any(|type_| type_ == Self::base_type()) {
      return Err(Error::MissingBaseType);
    }

    // Credentials MUST have at least one subject
    if self.credential_subject.is_empty() {
      return Err(Error::MissingSubject);
    }

    // Each subject is defined as one or more properties - no empty objects
    for subject in self.credential_subject.iter() {
      if subject.id.is_none() && subject.properties.is_empty() {
        return Err(Error::InvalidSubject);
      }
    }

    Ok(())
  }

  /// Returns a reference to the proof.
  pub fn proof(&self) -> Option<&Signature> {
    self.proof.as_ref()
  }

  /// Returns a mutable reference to the proof.
  pub fn proof_mut(&mut self) -> Option<&mut Signature> {
    self.proof.as_mut()
  }
}

impl<T> Display for Credential<T>
where
  T: Serialize,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.fmt_json(f)
  }
}

impl<T> TrySignature for Credential<T> {
  fn signature(&self) -> Option<&Signature> {
    self.proof.as_ref()
  }
}

impl<T> TrySignatureMut for Credential<T> {
  fn signature_mut(&mut self) -> Option<&mut Signature> {
    self.proof.as_mut()
  }
}

impl<T> SetSignature for Credential<T> {
  fn set_signature(&mut self, value: Signature) {
    self.proof.replace(value);
  }
}

impl<T> TryMethod for Credential<T> {
  const TYPE: MethodUriType = MethodUriType::Absolute;
}
