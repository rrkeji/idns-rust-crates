// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
// use bee_rest_api::types::dtos::LedgerInclusionStateDto;
use crate::ipfs_api::IpfsApi;
use crate::{
    did::RunnercDID,
    document::{DiffMessage, RunnercDocument},
    error::{Error::DIDNotFound, Result},
    runnerc::{Message, MessageId, Network, Receipt, TangleResolve},
};
use bytes::{BufMut, BytesMut};
use futures::stream::StreamExt;
use identity_core::convert::{FromJson, ToJson};
use std::io::Cursor;
use tokio::runtime::Handle;

/// Client for performing IOTA Identity operations on the Tangle.
pub struct Client {
    pub(crate) network: Network,
}

impl Client {
    /// Creates a new [`Client`] with default settings.
    pub async fn new() -> Result<Self> {
        Self::from_network(Network::Mainnet).await
    }

    /// Creates a new [`Client`] with default settings for the given [`Network`].
    pub async fn from_network(network: Network) -> Result<Self> {
        Ok(Self { network })
    }

    /// Returns the IOTA [`Network`] that the [`Client`] is configured to use.
    pub fn network(&self) -> Network {
        self.network.clone()
    }

    /// 存储值，并返回内容ID
    pub async fn set_value(&self, value: &String) -> Option<String> {
        //
        //保存到到IPFS
        let data = Cursor::new(value.clone());
        tracing::debug!("保存文档到IPFS:{}", value);

        let client = crate::utils::get_ipfs_client();

        if let res_result = client.add(data).await {
            match res_result {
                Ok(res) => {
                    tracing::debug!("保存到IPFS:{:#?}", res);
                    Some(res.hash)
                }
                Err(e) => {
                    tracing::error!("保存到IPFS失败:{:#?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    pub async fn get_value(&self, cid: &String) -> Option<String> {
        //
        let cid_copy = cid.clone();
        let client = crate::utils::get_ipfs_client();
        //读取数据
        let mut stream = client.cat(cid_copy.as_str());
        let mut buf = BytesMut::with_capacity(40960);
        while let Some(parts) = stream.next().await {
            // bytes.
            if let Ok(bs) = parts {
                buf.put(bs);
            }
        }
        Some(String::from_utf8(buf.to_vec()).unwrap())
    }

    /// Publishes an [`RunnercDocument`] to the Tangle.
    /// This method calls `publish_json_with_retry` with its default `interval` and `max_attempts`
    /// values for increasing the probability that the message will be referenced by a milestone.
    pub async fn publish_document(&self, document: &RunnercDocument) -> Result<Receipt> {
        self.publish_json_with_retry(
            format!("{:#?}", document.id()).as_str(),
            document,
            None,
            None,
        )
        .await
    }

    /// Publishes a [`DiffMessage`] to the Tangle to form part of the diff chain for the
    /// integration. chain message specified by the given [`MessageId`].
    /// This method calls `publish_json_with_retry` with its default `interval` and `max_attempts`
    /// values for increasing the probability that the message will be referenced by a milestone.
    pub async fn publish_diff(
        &self,
        message_id: &MessageId,
        diff: &DiffMessage,
    ) -> Result<Receipt> {
        self.publish_json_with_retry(&RunnercDocument::diff_index(message_id)?, diff, None, None)
            .await
    }

    /// Compresses and publishes arbitrary JSON data to the specified index on the Tangle.
    pub async fn publish_json<T: ToJson>(&self, index: &str, data: &T) -> Result<Receipt> {
        println!("index:{},data:{:#?}", index, data.to_json());
        //保存
        let cid_option = self.set_value(&data.to_json().unwrap()).await;
        match cid_option {
            Some(cid) => Ok(Receipt::new(
                self.network.clone(),
                Message {
                    network_id: 0,
                    message_id: cid.clone(),
                    payload: Some(cid.clone()),
                    nonce: 0,
                },
            )),
            None => Err(DIDNotFound(String::from(""))),
        }
        // Err(DIDNotFound(String::from("")))
    }

    /// Publishes arbitrary JSON data to the specified index on the Tangle.
    /// Retries (promotes or reattaches) the message until it’s included (referenced by a
    /// milestone). Default interval is 5 seconds and max attempts is 40.
    pub async fn publish_json_with_retry<T: ToJson>(
        &self,
        index: &str,
        data: &T,
        interval: Option<u64>,
        max_attempts: Option<u64>,
    ) -> Result<Receipt> {
        let receipt: Receipt = self.publish_json(index, data).await?;
        Ok(receipt)
    }

    /// Fetch the [`RunnercDocument`] specified by the given [`RunnercDID`].
    pub async fn read_document(&self, did: &RunnercDID) -> Result<RunnercDocument> {
        //
        let did_string = format!("{}", did);

        tracing::debug!("read_document > {}", did_string);
        //根据DID获取CID
        // TODO cid
        let cid = String::from("");
        tracing::debug!("read_document CID string > |{}|", cid);
        if let Some(msg) = self.get_value(&cid).await {
            tracing::debug!("read_document string > |{}|", msg);
            //反序列化
            let core_document_result = RunnercDocument::from_json_slice(msg.as_str());
            match core_document_result {
                Ok(core_document) => {
                    tracing::debug!("read_document value > {:#}", core_document);
                    return Ok(core_document);
                }
                Err(err) => {
                    tracing::error!("Json解析失败 > {:#}", err);
                    return Err(DIDNotFound(String::from("Json解析失败！")));
                }
            }
        } else {
            Err(DIDNotFound(String::from("")))
        }
    }

    /// Fetch all [`Messages`][Message] from the given index on the IOTA Tangle.
    pub(crate) async fn read_messages(&self, index: &str) -> Result<Vec<Message>> {
        // let message_ids: Box<[MessageId]> = Self::read_message_index(&self.client, index).await?;
        // let messages: Vec<Message> = Self::read_message_data(&self.client, &message_ids).await?;

        if let Some(msg) = self.get_value(&String::from(index)).await {
            Ok(vec![Message {
                network_id: 0,
                message_id: String::from(index),
                payload: Some(String::from(msg)),
                nonce: 0,
            }])
        } else {
            Err(DIDNotFound(String::from("")))
        }
    }
}

#[async_trait::async_trait(?Send)]
impl TangleResolve for Client {
    async fn resolve(&self, did: &RunnercDID) -> Result<RunnercDocument> {
        self.read_document(did).await
    }
}
