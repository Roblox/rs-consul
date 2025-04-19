use std::time::Duration;

use http::Method;
use http_body_util::combinators::BoxBody;
use http_body_util::Empty;
use hyper::body::Bytes;

use crate::errors::ConsulError;
use crate::types::ACLToken;
use crate::Consul;
use crate::Result;
use hyper::body::Buf;

impl Consul {
    ///list_acl_tokens
    pub async fn list_acl_tokens(&self) -> Result<Vec<ACLToken>> {
        let uri = format!("{}/v1/acl/tokens", self.config.address);
        let request = hyper::Request::builder().method(Method::GET).uri(uri);
        let (response_body, _index) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::GetAclTokens,
            )
            .await?;
        serde_json::from_reader(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
    }
}
