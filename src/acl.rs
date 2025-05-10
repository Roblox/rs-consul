use std::time::Duration;

use http::Method;
use http_body_util::combinators::BoxBody;
use http_body_util::Empty;
use http_body_util::Full;
use hyper::body::Bytes;

use crate::errors::ConsulError;
use crate::types::ACLPolicy;
use crate::types::ACLToken;
use crate::types::CreateACLPolicyRequest;
use crate::Consul;
use crate::Function;
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

    /// list acl policies
    pub async fn list_acl_policies(&self) -> Result<Vec<ACLPolicy>> {
        let uri = format!("{}/v1/acl/policies", self.config.address);
        let request = hyper::Request::builder().method(Method::GET).uri(uri);
        let (response_body, _index) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::ListACLPolicies,
            )
            .await?;
        serde_json::from_reader(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Create an ACL policy
    /// https://developer.hashicorp.com/consul/api-docs/acl/policies
    pub async fn create_acl_policy(&self, payload: &CreateACLPolicyRequest) -> Result<()> {
        let uri = format!("{}/v1/acl/policy", self.config.address);
        let request = hyper::Request::builder().method(Method::PUT).uri(uri);
        let payload = serde_json::to_string(payload).map_err(ConsulError::InvalidRequest)?;
        self.execute_request(
            request,
            BoxBody::new(Full::<Bytes>::new(Bytes::from(payload.into_bytes()))),
            Some(Duration::from_secs(5)),
            Function::CreateACLPolicy,
        )
        .await?;
        Ok(())
    }
}
