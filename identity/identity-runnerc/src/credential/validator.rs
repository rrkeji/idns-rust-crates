// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Serialize;

use identity_core::common::Object;
use identity_core::convert::FromJson;
use identity_credential::credential::Credential;
use identity_credential::presentation::Presentation;

use crate::did::RunnercDID;
use crate::document::RunnercDocument;
use crate::error::Error;
use crate::error::Result;
use crate::runnerc::ClientMap;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CredentialValidation<T = Object> {
    pub credential: Credential<T>,
    pub issuer: DocumentValidation,
    pub subjects: BTreeMap<String, DocumentValidation>,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PresentationValidation<T = Object, U = Object> {
    pub presentation: Presentation<T, U>,
    pub holder: DocumentValidation,
    pub credentials: Vec<CredentialValidation<U>>,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DocumentValidation {
    pub did: RunnercDID,
    pub document: RunnercDocument,
    pub metadata: Object,
    pub verified: bool,
}

unsafe impl std::marker::Send for DocumentValidation {}

#[derive()]
pub struct CredentialValidator {}

impl CredentialValidator {
    /// Deserializes the given JSON-encoded `Credential` and validates
    /// all associated DID documents.
    pub async fn check<T>(&self, data: &str, client: &ClientMap) -> Result<CredentialValidation<T>>
    where
        T: DeserializeOwned + Serialize,
    {
        self.validate_credential(Credential::from_json(data)?, client)
            .await
    }

    /// Deserializes the given JSON-encoded `Presentation` and
    /// validates all associated DID documents/`Credential`s.
    pub async fn check_presentation<T, U>(
        &self,
        data: &str,
        client: &ClientMap,
    ) -> Result<PresentationValidation<T, U>>
    where
        T: Clone + DeserializeOwned + Serialize,
        U: Clone + DeserializeOwned + Serialize,
    {
        self.validate_presentation(Presentation::from_json(data)?, client)
            .await
    }

    /// Validates the `Credential` proof and all relevant DID documents.
    ///
    /// Note: The credential is expected to have a proof created by the issuing party.
    /// Note: The credential issuer URL is expected to be a valid DID.
    /// Note: Credential subject IDs are expected to be valid DIDs (if present).
    pub async fn validate_credential<T>(
        &self,
        credential: Credential<T>,
        client: &ClientMap,
    ) -> Result<CredentialValidation<T>>
    where
        T: Serialize,
    {
        // Resolve the issuer DID Document and validate the digital signature.
        let issuer_url: &str = credential.issuer.url().as_str();

        tracing::debug!("validate_credential issuer_url:{}", issuer_url);

        let issuer_doc: DocumentValidation = self.validate_document(issuer_url, client).await?;

        tracing::debug!("validate_credential issuer_doc:{:?}", issuer_doc);

        let mut subjects: BTreeMap<String, DocumentValidation> = BTreeMap::new();

        // Resolve all credential subjects with `id`s - we assume all ids are DIDs.
        for id in credential
            .credential_subject
            .iter()
            .filter_map(|subject| subject.id.as_ref())
        {
            subjects.insert(
                id.to_string(),
                self.validate_document(id.as_str(), client).await?,
            );
        }

        // Verify the credential signature using the issuers DID Document
        let credential_verified: bool = issuer_doc.document.verify_data(&credential).is_ok();

        // Check if all subjects have valid signatures
        let subjects_verified: bool = subjects.values().all(|subject| subject.verified);

        // The credential is truly verified if all associated documents are verified
        let verified: bool = issuer_doc.verified && credential_verified && subjects_verified;

        Ok(CredentialValidation {
            credential,
            issuer: issuer_doc,
            subjects,
            verified,
        })
    }

    /// Validates the `Presentation` proof and all relevant DID documents.
    ///
    /// Note: The presentation holder is expected to be a valid DID.
    /// Note: The presentation is expected to have a proof created by the holder.
    pub async fn validate_presentation<T, U>(
        &self,
        presentation: Presentation<T, U>,
        client: &ClientMap,
    ) -> Result<PresentationValidation<T, U>>
    where
        T: Clone + Serialize,
        U: Clone + Serialize,
    {
        let holder_url: &str = presentation
            .holder
            .as_ref()
            .map(|holder| holder.as_str())
            .ok_or(Error::InvalidPresentationHolder)?;

        // Resolve the holder DID Document and validate the digital signature.
        let holder_doc: DocumentValidation = self.validate_document(holder_url, client).await?;

        let mut credentials: Vec<CredentialValidation<U>> = Vec::new();

        // Resolve and validate all associated credentials.
        for credential in presentation.verifiable_credential.iter() {
            credentials.push(self.validate_credential(credential.clone(), client).await?);
        }

        // Verify the presentation signature using the holders DID Document
        let presentation_verified: bool = holder_doc.document.verify_data(&presentation).is_ok();

        // Check if all credentials are verified
        let credentials_verified: bool = credentials.iter().all(|credential| credential.verified);

        // The presentation is truly verified if all associated documents are verified
        let verified: bool = holder_doc.verified && presentation_verified && credentials_verified;

        Ok(PresentationValidation {
            presentation,
            holder: holder_doc,
            credentials,
            verified,
        })
    }

    /// Resolves the document from the Tangle, which performs checks on all signatures etc.
    async fn validate_document(
        &self,
        did: impl AsRef<str>,
        client: &ClientMap,
    ) -> Result<DocumentValidation> {
        let did: RunnercDID = did.as_ref().parse()?;

        let document: RunnercDocument = client.read_document(&did).await?;
        // // TODO: check if document is deactivated, does that matter?

        Ok(DocumentValidation {
            did,
            document,
            metadata: Object::new(),
            verified: true,
        })
    }
}
