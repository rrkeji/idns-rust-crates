use futures::stream::FuturesUnordered;
use futures::stream::TryStreamExt;
// use iota_client::Client as IotaClient;
// use iota_client::Error as IotaClientError;
use mongodb::bson::{doc, Document};
use mongodb::options::FindOptions;
use mongodb::{options::ClientOptions, Client as MongoClient};
use serde_json;

use identity_core::convert::FromJson;
use identity_core::convert::ToJson;
use identity_did::document::CoreDocument;

use identity_did::did::DID;
use identity_runnerc::did::RunnercDID;
use identity_runnerc::document::DiffMessage;
use identity_runnerc::document::RunnercDocument;
use identity_runnerc::error::Error::DIDNotFound;
use identity_runnerc::error::Result;
use identity_runnerc::runnerc::Message;
use identity_runnerc::runnerc::MessageId;
use identity_runnerc::runnerc::Network;
use identity_runnerc::runnerc::Receipt;
use identity_runnerc::runnerc::TangleResolve;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    println!("=========================================");

    //反序列化
    let core_document_result = RunnercDocument::from_json_slice("{\"id\":\"did:runnerc:GyKt5qSVKTPGQjXoFgmqagBwj2Xm98Hfyy3BBnqezCo8\",\"capabilityInvocation\":[{\"id\":\"did:runnerc:GyKt5qSVKTPGQjXoFgmqagBwj2Xm98Hfyy3BBnqezCo8#sign-0\",\"controller\":\"did:runnerc:GyKt5qSVKTPGQjXoFgmqagBwj2Xm98Hfyy3BBnqezCo8\",\"type\":\"Ed25519VerificationKey2018\",\"publicKeyMultibase\":\"z7BmtKSViZXH2yDj6XuyPEM2X1XmSt6W9SQp1murtM4c1\"}],\"created\":\"2021-12-28T06:47:45Z\",\"updated\":\"2021-12-28T06:47:45Z\",\"proof\":{\"type\":\"JcsEd25519Signature2020\",\"verificationMethod\":\"#sign-0\",\"signatureValue\":\"3pQExQotStonBW69jCvfE3Luh1Qv28hKkEVGDW9R4FFgLuWF8GZmwYMSwKyz6qWLaiZuyBTEft1eGXVCG2psTdas\"}}");
    match core_document_result {
        Ok(core_document) => {
            tracing::debug!("read_document value > {:#}", core_document);
        }
        Err(err) => {
            tracing::error!("Json解析失败 > {:#}", err);
        }
    }

    Ok(())
}
