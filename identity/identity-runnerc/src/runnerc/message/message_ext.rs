// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::Message;
use super::MessageId;
use super::MESSAGE_ID_LENGTH;

use identity_core::convert::FromJson;
use identity_did::did::DID;

use crate::did::RunnercDID;
use crate::document::DiffMessage;
use crate::document::RunnercDocument;
use crate::error::Result;
use crate::runnerc::TangleRef;

/// Magic bytes used to mark DID messages.
const DID_MESSAGE_MARKER: &[u8] = b"DID";

// TODO: Use MessageId when it has a const ctor
static NULL: &[u8; MESSAGE_ID_LENGTH] = &[0; MESSAGE_ID_LENGTH];

fn parse_message<T: FromJson + TangleRef>(message: &Message, did: &RunnercDID) -> Option<T> {
    let message_id: MessageId = message.id().0;
    let payload: Option<&String> = message.payload().as_ref();
    let resource: T = parse_payload(message_id, payload)?;

    if did.authority() != resource.did().authority() {
        return None;
    }

    Some(resource)
}

fn parse_payload<T: FromJson + TangleRef>(
    message_id: MessageId,
    payload: Option<&String>,
) -> Option<T> {
    match payload {
        Some(payload_str) => {
            if let Ok(t) = T::from_json_slice(payload_str) {
                Some(t)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub trait MessageIdExt: Sized {
    fn is_null(&self) -> bool;

    fn encode_hex(&self) -> String;

    fn decode_hex(hex: &str) -> Result<Self>;
}

impl MessageIdExt for MessageId {
    fn is_null(&self) -> bool {
        self.as_ref() == NULL
    }

    fn encode_hex(&self) -> String {
        self.to_string()
    }

    fn decode_hex(hex: &str) -> Result<Self> {
        hex.parse().map_err(Into::into)
    }
}

pub trait MessageExt {
    fn try_extract_document(&self, did: &RunnercDID) -> Option<RunnercDocument>;

    fn try_extract_diff(&self, did: &RunnercDID) -> Option<DiffMessage>;
}

impl MessageExt for Message {
    fn try_extract_document(&self, did: &RunnercDID) -> Option<RunnercDocument> {
        RunnercDocument::try_from_message(self, did)
    }

    fn try_extract_diff(&self, did: &RunnercDID) -> Option<DiffMessage> {
        DiffMessage::try_from_message(self, did)
    }
}

pub trait TryFromMessage: Sized {
    fn try_from_message(message: &Message, did: &RunnercDID) -> Option<Self>;
}

impl TryFromMessage for RunnercDocument {
    fn try_from_message(message: &Message, did: &RunnercDID) -> Option<Self> {
        parse_message(message, did)
    }
}

impl TryFromMessage for DiffMessage {
    fn try_from_message(message: &Message, did: &RunnercDID) -> Option<Self> {
        parse_message(message, did)
    }
}
