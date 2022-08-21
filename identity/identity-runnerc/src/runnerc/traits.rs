// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::did::RunnercDID;
use crate::document::RunnercDocument;
use crate::error::Result;
use crate::runnerc::MessageId;

pub trait TangleRef {
    fn did(&self) -> &RunnercDID;

    fn message_id(&self) -> &MessageId;

    fn set_message_id(&mut self, message_id: MessageId);

    fn previous_message_id(&self) -> &MessageId;

    fn set_previous_message_id(&mut self, message_id: MessageId);
}

#[async_trait::async_trait(?Send)]
pub trait TangleResolve {
    async fn resolve(&self, did: &RunnercDID) -> Result<RunnercDocument>;
}
