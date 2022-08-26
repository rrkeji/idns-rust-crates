use crate::ipfs_api::IpfsClient;
use anyhow::{anyhow, Result};
use hyper::{service::Service, Body, Client, Request};

//
pub fn get_ipfs_client() -> IpfsClient {
    //
    IpfsClient::default()
}

const KVSTORE_URL: &'static str = "http://localhost:35091";

/// 内部请求的方法
pub(crate) async fn _ciddb_get_request(path: &str) -> Result<String> {
    tracing::debug!("请求路径:{}", path);
    //请求地址
    let uri = format!("{}{}", KVSTORE_URL, path).parse::<http::Uri>()?;
    let mut client = Client::new();
    let body = Body::empty();
    let request = Request::get(uri).body(body)?;
    //发送请求
    let resp = client.call(request).await?;
    //
    let result = hyper::body::to_bytes(resp).await;
    match result {
        Ok(plain) => {
            tracing::debug!("response plain: {:?}", plain);
            Ok(String::from_utf8(plain[..].to_vec())?)
        }
        Err(err) => Err(anyhow!("Fail request {}!", err)),
    }
}
