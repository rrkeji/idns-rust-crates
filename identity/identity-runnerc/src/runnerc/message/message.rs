// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use super::message_id::MessageId;

/// The minimum number of bytes in a message.
pub const MESSAGE_LENGTH_MIN: usize = 53;

/// The maximum number of bytes in a message.
pub const MESSAGE_LENGTH_MAX: usize = 32768;

const DEFAULT_POW_SCORE: f64 = 4000f64;
const DEFAULT_NONCE: u64 = 0;

/// Represent the object that nodes gossip around the network.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    /// Specifies which network this message is meant for.
    pub network_id: u64,
    /// The [`MessageId`]s that this message directly approves.
    pub message_id: String,
    /// The optional [Payload] of the message.
    pub payload: Option<String>,
    /// The result of the Proof of Work in order for the message to be accepted into the runnerc.
    pub nonce: u64,
}

impl Message {
    /// Creates a new `MessageBuilder` to construct an instance of a `Message`.
    // pub fn builder() -> MessageBuilder {
    //     MessageBuilder::new()
    // }

    /// Computes the identifier of the message.
    pub fn id(&self) -> (MessageId, Vec<u8>) {
        (MessageId::new(self.message_id.clone()), vec![])
    }

    /// Returns the network id of a `Message`.
    pub fn network_id(&self) -> u64 {
        self.network_id
    }

    // // Returns the parents of a `Message`.
    // pub fn parents(&self) -> &Parents {
    //     &self.parents
    // }

    // // Returns the optional payload of a `Message`.
    pub fn payload(&self) -> &Option<String> {
        &self.payload
    }

    /// Returns the nonce of a `Message`.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    // // Consumes the [`Message`], and returns ownership over its [`Parents`].
    // pub fn into_parents(self) -> Parents {
    //     self.parents
    // }
}
