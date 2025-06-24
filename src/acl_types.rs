use serde::{self, Deserialize, Serialize};

/// Information related ACL token.
/// See https://developer.hashicorp.com/consul/docs/security/acl/tokens for more information.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ACLToken {
    /// Unique ID
    #[serde(rename = "AccessorID")]
    pub accessor_id: String,
    /// Secret for authentication
    #[serde(rename = "SecretID")]
    pub secret_id: String,
    /// Description
    pub description: String,
    /// Policies
    #[serde(default)]
    pub policies: Vec<ACLTokenPolicyLink>,
    /// Token only valid in this datacenter
    #[serde(default)]
    pub local: bool,
    /// Creation time
    pub create_time: String,
    /// Hash
    pub hash: String,
    /// Create index
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
/// TODO: NodeIdentities,TemplatedPolicies, ServiceIdentities
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateACLTokenPayload {
    /// Unique ID
    #[serde(rename = "AccessorID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessor_id: Option<String>,
    /// Secret for authentication
    #[serde(rename = "SecretID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Policies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<ACLTokenPolicyLink>,
    /// Token only valid in this datacenter
    #[serde(default)]
    pub local: bool,
    /// Creation time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    /// Hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Optional expiration time for the ACL token.
    ///
    /// If set, this field specifies the point in time after which the token is considered revoked and eligible for destruction.
    /// The default value means the token does not expire.
    ///
    /// The expiration time must be between 1 minute and 24 hours in the future. This constraint is enforced by Consul to promote
    /// security best practices, ensuring that tokens are short-lived and reducing the risk of unauthorized access in case of token compromise.
    ///
    /// The value should be provided in RFC 3339 format, representing a date and time with optional fractional seconds and time zone offset.
    /// For example: "2025-05-29T15:00:00Z" or "2025-05-29T15:00:00+02:00".
    ///
    /// Added in Consul 1.5.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
}

/// Represents an ACL (Access Control List) policy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ACLPolicy {
    /// Unique identifier for the policy.
    #[serde(rename = "ID")]
    pub id: String,
    /// The name of the policy
    pub name: String,
    /// Description of the policy.
    pub description: String,
    /// Hash of the policy.
    pub hash: String,
    /// Index at which the policy was created.
    pub create_index: u32,
    // `datacenters` is an Option::Vec because Consul may return `null` for this field.
    // Using `Option` avoids the need for a custom deserializer that would be required
    // if the field was just a `Vec`.
    /// List of applicable datacenters.
    pub datacenters: Option<Vec<String>>,
    /// Index at which the policy was last modified.
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
    /// Rules in HCL format
    // TODO: Make the rules strongly typed
    pub rules: Option<String>,
}
