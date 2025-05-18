use std::time::Duration;

use serde::{self, Deserialize, Serialize};

/// Information related ACL token.
/// See https://developer.hashicorp.com/consul/docs/security/acl/tokens for more information.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ACLToken {
    /// Unique ID
    #[serde(rename = "AccessorID")]
    pub accessor_id: String,
    /// Secret for authenticatioIDn
    #[serde(rename = "SecretID")]
    pub secret_id: String,
    /// Description
    pub description: String,
    /// Policies
    pub policies: Option<Vec<ACLTokenPolicyLink>>,
    /// Token only valid in this datacenter
    #[serde(default)]
    pub local: bool,
    /// creation time
    pub create_time: String,
    /// hash
    pub hash: String,
    /// create index
    pub create_index: u64,
    /// ModifyIndex is the last index that modified this key.
    /// It can be used to establish blocking queries by setting the ?index query parameter.
    pub modify_index: i64,
}

/// Information related to Policies
/// see https://developer.hashicorp.com/consul/docs/security/acl/acl-policies for more information
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ACLTokenPolicyLink {
    /// Policy ID
    #[serde(rename = "ID")]
    pub id: Option<String>,
    /// Policy name
    pub name: Option<String>,
}

/// Create ACL token payload
/// See https://developer.hashicorp.com/consul/api-docs/acl/tokens for more information.
/// todo(): NodeIdentities,TemplatedPolicies, ServiceIdentities
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateACLTokenPayload {
    /// Unique ID
    #[serde(rename = "AccessorID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessor_id: Option<String>,
    /// Secret for authenticatioIDn
    #[serde(rename = "SecretID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Policies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<ACLTokenPolicyLink>>,
    /// Token only valid in this datacenter
    #[serde(default)]
    pub local: bool,
    /// creation time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    /// hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// duration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<Duration>,
}

/// Acl Policy
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ACLPolicy {
    /// id
    #[serde(rename = "ID")]
    pub id: String,
    /// name
    pub name: String,
    /// Description
    pub description: String,
    /// hash
    pub hash: String,
    /// Create index
    pub create_index: u32,
    /// Datacenters
    pub datacenters: Option<String>,
    /// modify index
    pub modify_index: u32,
}

/// Payload to create an ACL Policy
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateACLPolicyRequest {
    /// Name of the policy (unique)
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// rules in HCL format
    // todo: Make the rules strongly typed
    pub rules: Option<String>,
}
