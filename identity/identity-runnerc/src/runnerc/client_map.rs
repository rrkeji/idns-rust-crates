// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use dashmap::DashMap;

use crate::did::RunnercDID;
use crate::document::DiffMessage;
use crate::document::RunnercDocument;
use crate::error::Result;
use crate::runnerc::Client;
use crate::runnerc::MessageId;
use crate::runnerc::Network;
use crate::runnerc::NetworkName;
use crate::runnerc::Receipt;
use crate::runnerc::TangleResolve;

type State = DashMap<NetworkName, Arc<Client>>;

// #[derive(Debug)]
pub struct ClientMap {
    data: State,
}

impl ClientMap {
    pub fn new() -> Self {
        Self { data: State::new() }
    }

    pub fn from_client(client: Client) -> Self {
        let data: State = State::new();

        data.insert(client.network.name(), Arc::new(client));

        Self { data }
    }

    pub async fn from_network(network: Network) -> Result<Self> {
        Client::from_network(network).await.map(Self::from_client)
    }

    pub fn insert(&self, client: Client) {
        self.data.insert(client.network.name(), Arc::new(client));
    }

    pub async fn publish_document(&self, document: &RunnercDocument) -> Result<Receipt> {
        let network: Network = document.id().network()?;
        let client: Arc<Client> = self.client(network).await?;

        client.publish_document(document).await
    }

    pub async fn publish_diff(
        &self,
        message_id: &MessageId,
        diff: &DiffMessage,
    ) -> Result<Receipt> {
        let network: Network = diff.id().network()?;
        let client: Arc<Client> = self.client(network).await?;

        client.publish_diff(message_id, diff).await
    }

    pub async fn read_document(&self, did: &RunnercDID) -> Result<RunnercDocument> {
        let network: Network = did.network()?;
        let client: Arc<Client> = self.client(network).await?;

        client.read_document(did).await
        // Err(DIDNotFound(String::from("")))
    }

    pub async fn client(&self, network: Network) -> Result<Arc<Client>> {
        let network_name = network.name();
        if let Some(client) = self.data.get(&network_name) {
            return Ok(Arc::clone(&client));
        }

        let client: Arc<Client> = Client::from_network(network.clone()).await.map(Arc::new)?;

        self.data.insert(network_name, Arc::clone(&client));

        Ok(client)
    }
}

impl Default for ClientMap {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait(?Send)]
impl TangleResolve for ClientMap {
    async fn resolve(&self, did: &RunnercDID) -> Result<RunnercDocument> {
        self.read_document(did).await
    }
}
