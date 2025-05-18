use std::time::Duration;

use crate::errors::ConsulError;
use crate::ACLPolicy;
use crate::ACLToken;
use crate::Consul;
use crate::CreateACLPolicyRequest;
use crate::CreateACLTokenPayload;
use crate::Function;
use crate::Result;

use http::Method;
use http_body_util::combinators::BoxBody;
use http_body_util::Empty;
use http_body_util::Full;

use hyper::body::Buf;
use hyper::body::Bytes;

impl Consul {
    /// Returns all ACL tokens.
    ///
    /// Fetches the list of ACL tokens from Consul’s `/v1/acl/tokens` endpoint.
    /// Users can use these tokens to manage access control for Consul resources.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/tokens#list-tokens) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.
    ///
    /// # Errors:
    /// - [`ConsulError::ResponseDeserializationFailed`] if the response JSON can’t be parsed.
    pub async fn get_acl_tokens(&self) -> Result<Vec<ACLToken>> {
        let uri = format!("{}/v1/acl/tokens", self.config.address);
        let request = hyper::Request::builder().method(Method::GET).uri(uri);
        let (body, _) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::GetAclTokens,
            )
            .await?;
        serde_json::from_reader(body.reader()).map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Returns all ACL policies.
    ///
    /// Retrieves the list of ACL policies defined in Consul via the `/v1/acl/policies` endpoint.
    /// ACL policies define sets of rules for tokens to grant or restrict permissions.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/policies#list-policies) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.
    ///
    /// # Errors:
    /// - [`ConsulError::ResponseDeserializationFailed`] if the response JSON can’t be parsed.
    pub async fn get_acl_policies(&self) -> Result<Vec<ACLPolicy>> {
        let uri = format!("{}/v1/acl/policies", self.config.address);
        let request = hyper::Request::builder().method(Method::GET).uri(uri);
        let (body, _) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::GetACLPolicies,
            )
            .await?;
        serde_json::from_reader(body.reader()).map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Delete an acl policy.
    ///
    /// Sends a `DELETE` to `/v1/acl/policy/:id` to delete an ACL policy in Consul.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.  
    /// - `id` – the policy ID.
    ///
    /// # Errors:
    /// - [`ConsulError::InvalidRequest`] if the payload fails to serialize.  
    /// - [`ConsulError::ResponseDeserializationFailed`] if the Consul response can’t be parsed.
    pub async fn delete_acl_policy(&self, id: String) -> Result<()> {
        let uri = format!("{}/v1/acl/policy/{}", self.config.address, id);
        let request = hyper::Request::builder().method(Method::DELETE).uri(uri);
        self.execute_request(
            request,
            BoxBody::new(Empty::<Bytes>::new()),
            Some(Duration::from_secs(5)),
            Function::DeleteACLPolicy,
        )
        .await?;
        Ok(())
    }

    /// Creates a new ACL policy.
    ///
    /// Sends a `PUT` to `/v1/acl/policy` to define a new ACL policy in Consul.
    /// ACL policies consist of rules that can be attached to tokens to control access.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/policies#create-policy) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.  
    /// - `payload` – the [`CreateACLPolicyRequest`](crate::types::CreateACLPolicyRequest) payload.
    ///
    /// # Errors:
    /// - [`ConsulError::InvalidRequest`] if the payload fails to serialize.  
    /// - [`ConsulError::ResponseDeserializationFailed`] if the Consul response can’t be parsed.
    pub async fn create_acl_policy(&self, payload: &CreateACLPolicyRequest) -> Result<ACLPolicy> {
        let uri = format!("{}/v1/acl/policy", self.config.address);
        let request = hyper::Request::builder().method(Method::PUT).uri(uri);
        let payload = serde_json::to_string(payload).map_err(ConsulError::InvalidRequest)?;
        let (resp, _) = self
            .execute_request(
                request,
                BoxBody::new(Full::<Bytes>::new(Bytes::from(payload.into_bytes()))),
                Some(Duration::from_secs(5)),
                Function::CreateACLPolicy,
            )
            .await?;
        serde_json::from_reader(resp.reader()).map_err(ConsulError::ResponseDeserializationFailed)
    }
    /// Creates a new ACL token.
    ///
    /// Sends a `PUT` to `/v1/acl/token` to generate a new token which can be attached to ACL policies.
    /// Tokens grant the permissions defined by their associated policies.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/tokens#create-token) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.  
    /// - `payload` – the [`CreateACLTokenPayload`](crate::CreateACLTokenPayload) payload.
    ///
    /// # Errors:
    /// - [`ConsulError::InvalidRequest`] if the payload fails to serialize.  
    /// - [`ConsulError::ResponseDeserializationFailed`] if the response JSON can’t be parsed.
    pub async fn create_acl_token(&self, payload: &CreateACLTokenPayload) -> Result<ACLToken> {
        let uri = format!("{}/v1/acl/token", self.config.address);
        let request = hyper::Request::builder().method(Method::PUT).uri(uri);
        let payload = serde_json::to_string(payload).map_err(ConsulError::InvalidRequest)?;
        let (resp, _) = self
            .execute_request(
                request,
                BoxBody::new(Full::<Bytes>::new(Bytes::from(payload.into_bytes()))),
                Some(Duration::from_secs(5)),
                Function::CreateACLPolicy,
            )
            .await?;
        serde_json::from_reader(resp.reader()).map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Reads an ACL token.
    ///
    /// Fetches a single ACL token by its ID using the `/v1/acl/token/{token}` endpoint.
    /// Useful for inspecting the token’s properties and associated policies.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/tokens#read-token) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.  
    /// - `accessor_id` – the accessor_id to read.
    ///
    /// # Errors:
    /// - [`ConsulError::ResponseDeserializationFailed`] if the response JSON can’t be parsed.
    pub async fn read_acl_token(&self, accessor_id: String) -> Result<ACLToken> {
        let uri = format!("{}/v1/acl/token/{}", self.config.address, accessor_id);
        let request = hyper::Request::builder().method(Method::GET).uri(uri);
        let (resp_body, _) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::ReadACLToken,
            )
            .await?;
        serde_json::from_reader(resp_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Deletes an ACL token.
    ///
    /// Sends a `DELETE` to `/v1/acl/token/{token}` to remove the specified ACL token.
    /// Returns `false` if deletion failed, in which case this method returns an error.
    /// See the [Consul API docs](https://developer.hashicorp.com/consul/api-docs/acl/tokens#delete-token) for more information.
    ///
    /// # Arguments:
    /// - `&self` – the `Consul` client instance.  
    /// - `token` – the token ID to delete.
    ///
    /// # Errors:
    /// - [`ConsulError::ResponseDeserializationFailed`] if the response JSON can’t be parsed.  
    /// - [`ConsulError::TokenDeleteFailed`] if Consul indicates deletion did not succeed.
    pub async fn delete_acl_token(&self, token: String) -> Result<()> {
        let uri = format!("{}/v1/acl/token/{}", self.config.address, token);
        let request = hyper::Request::builder().method(Method::DELETE).uri(uri);
        let (resp_body, _) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                Some(Duration::from_secs(5)),
                crate::Function::DeleteACLToken,
            )
            .await?;
        let ok: bool = serde_json::from_reader(resp_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)?;
        if !ok {
            return Err(ConsulError::TokenDeleteFailed);
        }
        Ok(())
    }
}
