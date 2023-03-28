/*
MIT License

Copyright (c) 2023 Roblox

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

use std::collections::HashMap;
use std::time::Duration;

use serde::{self, de::Deserializer, de::Error as SerdeError, Deserialize, Serialize, Serializer};
use smart_default::SmartDefault;

// TODO retrofit other get APIs to use this struct
/// Query options for Consul endpoints.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Specifies the namespace to use.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    /// This is specified as part of the URL as a query parameter. Added in Consul 1.7.0.
    /// NOTE: usage of this query parameter requires Consul enterprise.
    pub namespace: Option<String>,
    /// Specifies the datacenter to query.
    /// This will default to the datacenter of the agent being queried.
    /// This is specified as part of the URL as a query parameter.
    pub datacenter: Option<String>,
    /// The timeout to apply to the query, if any, defaults to 5s.
    pub timeout: Option<Duration>,
    /// The index to supply as a query parameter, if the endpoint supports blocking queries.
    pub index: Option<u64>,
    /// The time to block for, when used in association with an index, if the endpoint supports blocking queries.
    /// Server side default of 5 minute is applied if not specified, with a limit of 10 minutes and maximum granularity of seconds.
    pub wait: Option<Duration>,
}
impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            namespace: None,
            datacenter: None,
            timeout: Some(Duration::from_secs(5)),
            index: None,
            wait: None,
        }
    }
}

/// Encapsulates a consul query response and the returned metadata, if any.
#[derive(Debug)]
pub struct ResponseMeta<T> {
    /// Query response.
    pub response: T,
    /// The index returned from the consul query via the X-Consul-Index header.
    pub index: u64,
}

/// Represents a request to delete a key or all keys sharing a prefix from Consul's Key Value store.
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
pub struct DeleteKeyRequest<'a> {
    /// Specifies the path of the key to delete.
    pub key: &'a str,
    /// Specifies the datacenter to query. This will default to the datacenter of the agent being queried.
    pub datacenter: &'a str,
    /// Specifies to delete all keys which have the specified prefix.
    /// Without this, only a key with an exact match will be deleted.
    pub recurse: bool,
    /// Specifies to use a Check-And-Set operation.
    /// This is very useful as a building block for more complex synchronization primitives.
    /// The index must be greater than 0 for Consul to take any action: a 0 index will not delete the key.
    /// If the index is non-zero, the key is only deleted if the index matches the ModifyIndex of that key.
    pub check_and_set: Option<u64>,
    /// Specifies the namespace to query.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    pub namespace: &'a str,
}

/// Represents a request to read a key from Consul's Key Value store.
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
pub struct ReadKeyRequest<'a> {
    /// Specifies the path of the key to read.
    pub key: &'a str,
    /// Specifies the namespace to query.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    /// For recursive lookups, the namespace may be specified as '*' and then results will be returned for all namespaces. Added in Consul 1.7.0.
    pub namespace: &'a str,
    /// Specifies the datacenter to query.
    /// This will default to the datacenter of the agent being queried.
    pub datacenter: &'a str,
    /// Specifies if the lookup should be recursive and key treated as a prefix instead of a literal match.
    pub recurse: bool,
    /// Specifies the string to use as a separator for recursive key lookups.
    /// This option is only used when paired with the keys parameter to limit the prefix of keys returned, only up to the given separator.
    pub separator: &'a str,
    /// The consistency mode for reads. See also [ConsistencyMode](consul::types::ConsistencyMode)
    pub consistency: ConsistencyMode,
    /// Endpoints that support blocking queries return an HTTP header named X-Consul-Index.
    /// This is a unique identifier representing the current state of the requested resource.
    /// On subsequent requests for this resource, the client can set the index query string parameter to the value of X-Consul-Index, indicating that the client wishes to wait for any changes subsequent to that index.
    pub index: Option<u64>,
    /// The time to wait for watching a lock in a blocking fashion.
    pub wait: Duration,
}

macro_rules! builder_fun {
    ($nm:ident, $fun:ident, $parm:ty) => {
        /// Builder-style method to set $nm on the object and return `self`
        pub fn $fun(self, $nm: $parm) -> Self {
            ReadKeyRequest { $nm, ..self }
        }
    };
}
impl<'a> ReadKeyRequest<'a> {
    /// Construct a default ReadKeyRequest to be used with the builder API
    /// e.g.
    /// ```rust
    /// use rs_consul::ReadKeyRequest;
    /// let req = ReadKeyRequest::new()
    ///     .set_key("bar")
    ///     .set_namespace("foo")
    ///     .set_recurse(true);
    /// ```
    pub fn new() -> Self {
        Default::default()
    }

    builder_fun!(key, set_key, &'a str);
    builder_fun!(namespace, set_namespace, &'a str);
    builder_fun!(datacenter, set_datacenter, &'a str);
    builder_fun!(recurse, set_recurse, bool);
    builder_fun!(separator, set_separator, &'a str);
    builder_fun!(consistency, set_consistency, ConsistencyMode);
    builder_fun!(index, set_index, Option<u64>);
    builder_fun!(wait, set_wait, Duration);
}

/// Represents a request to read a key from Consul's Key Value store.
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
pub struct LockWatchRequest<'a> {
    /// Specifies the path of the key to read.
    pub key: &'a str,
    /// Specifies the datacenter to query.
    /// This will default to the datacenter of the agent being queried.
    pub datacenter: &'a str,
    /// Specifies the namespace to query.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    /// For recursive lookups, the namespace may be specified as '*' and then results will be returned for all namespaces. Added in Consul 1.7.0.
    pub namespace: &'a str,
    /// The consistency mode for reads. See also [ConsistencyMode](consul::types::ConsistencyMode)
    pub consistency: ConsistencyMode,
    /// Endpoints that support blocking queries return an HTTP header named X-Consul-Index.
    /// This is a unique identifier representing the current state of the requested resource.
    /// On subsequent requests for this resource, the client can set the index query string parameter to the value of X-Consul-Index, indicating that the client wishes to wait for any changes subsequent to that index.
    pub index: Option<u64>,
    /// The time to wait for watching a lock in a blocking fashion.
    pub wait: Duration,
}

/// Represents a request to read a key from Consul Key Value store.
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
pub struct CreateOrUpdateKeyRequest<'a> {
    /// Specifies the path of the key.
    pub key: &'a str,
    /// Specifies the namespace to query.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    /// This is specified as part of the URL as a query parameter. Added in Consul 1.7.0.
    pub namespace: &'a str,
    /// Specifies the datacenter to query.
    /// This will default to the datacenter of the agent being queried.
    pub datacenter: &'a str,
    /// Specifies an unsigned value between 0 and (2^64)-1.
    /// Clients can choose to use this however makes sense for their application.
    pub flags: u64,
    /// Specifies to use a Check-And-Set operation.
    /// This is very useful as a building block for more complex synchronization primitives.
    /// If the index is 0, Consul will only put the key if it does not already exist.
    /// If the index is non-zero, the key is only set if the index matches the ModifyIndex of that key.
    pub check_and_set: Option<u64>,
    /// Supply a session ID to use in a lock acquisition operation.
    /// This is useful as it allows leader election to be built on top of Consul.
    /// If the lock is not held and the session is valid, this increments the LockIndex and sets the Session value of the key in addition to updating the key contents.
    /// A key does not need to exist to be acquired. If the lock is already held by the given session, then the LockIndex is not incremented but the key contents are updated.
    /// This lets the current lock holder update the key contents without having to give up the lock and reacquire it.
    /// Note that an update that does not include the acquire parameter will proceed normally even if another session has locked the key.
    pub acquire: &'a str,
    /// Supply a session ID to use in a release operation.
    /// This is useful when paired with ?acquire= as it allows clients to yield a lock.
    /// This will leave the LockIndex unmodified but will clear the associated Session of the key.
    /// The key must be held by this session to be unlocked.
    pub release: &'a str,
}

/// An operation to be executed within a transaction
/// See https://developer.hashicorp.com/consul/api-docs/txn for more info
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransactionOp<'a> {
    /// The type of operation to execute
    pub verb: TransactionOpVerb,
    /// The key on which to operate
    pub key: &'a str,
    /// The value to set (if applicable)
    pub value: Base64Vec,
    #[serde(rename = "Index")]
    /// The modify_index if it is a cas operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_and_set: Option<u64>,
    /// Optional flags to associate with the key
    pub flags: u64,
    /// Namespace on which to operate
    pub namespace: &'a str,
}

/// Response from Consul for a txn request
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransactionResponse {
    /// The key on which the operation was executed
    pub key: String,
    /// The resulting value from the key (if applicable)
    pub value: Option<Vec<u8>>,
    /// The index at which the key was created
    pub create_index: u64,
    /// The index at which the key was locked
    pub lock_index: u64,
    /// The index at which the key was modified
    pub modify_index: u64,
}

/// Represents a response from reading a key from Consul Key Value store.
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReadKeyResponse<T: Default = Base64Vec> {
    /// CreateIndex is the internal index value that represents when the entry was created.
    pub create_index: u64,
    /// ModifyIndex is the last index that modified this key.
    /// It can be used to establish blocking queries by setting the ?index query parameter.
    /// You can even perform blocking queries against entire subtrees of the KV store: if ?recurse is provided, the returned X-Consul-Index corresponds to the latest ModifyIndex within the prefix, and a blocking query using that ?index will wait until any key within that prefix is updated.
    pub modify_index: u64,
    /// LockIndex is the number of times this key has successfully been acquired in a lock.
    /// If the lock is held, the Session key provides the session that owns the lock.
    pub lock_index: u64,
    /// Key is simply the full path of the entry.
    pub key: String,
    /// Flags is an opaque unsigned integer that can be attached to each entry.
    /// Clients can choose to use this however makes sense for their application.
    pub flags: u64,
    /// Value is a base64-encoded blob of data.
    pub value: Option<T>,
    /// If a lock is held, the Session key provides the session that owns the lock.
    pub session: Option<String>,
}

/// Represents a request to create a lock .
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LockRequest<'a> {
    /// The key to use for locking.
    pub key: &'a str,
    /// The name of the session to use.
    pub session_id: &'a str,
    /// Specifies the namespace to use.
    /// If not provided, the namespace will be inferred from the request's ACL token, or will default to the default namespace.
    /// This is specified as part of the URL as a query parameter. Added in Consul 1.7.0.
    pub namespace: &'a str,
    /// Specifies the datacenter to query.
    /// This will default to the datacenter of the agent being queried.
    /// This is specified as part of the URL as a query parameter.
    pub datacenter: &'a str,
    /// Specifies the duration of a session (between 10s and 86400s).
    /// If provided, the session is invalidated if it is not renewed before the TTL expires.
    /// The lowest practical TTL should be used to keep the number of managed sessions low.
    /// When locks are forcibly expired, such as when following the leader election pattern in an application, sessions may not be reaped for up to double this TTL, so long TTL values (> 1 hour) should be avoided.
    /// Defaults to 10 seconds.
    #[default(_code = "Duration::from_secs(10)")]
    pub timeout: Duration,
    /// Controls the behavior to take when a session is invalidated. See also [LockExpirationBehavior](consul::types::LockExpirationBehavior)
    pub behavior: LockExpirationBehavior,
    /// Specifies the duration for the lock delay.
    /// Defaults to 1 second.
    #[default(_code = "Duration::from_secs(1)")]
    pub lock_delay: Duration,
}

/// Controls the behavior of locks when a session is invalidated. See [consul docs](https://www.consul.io/api-docs/session#behavior) for more information.
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LockExpirationBehavior {
    #[default]
    /// Causes any locks that are held to be released when a session is invalidated.
    Release,
    /// Causes any locks that are held to be deleted when a session is invalidated.
    Delete,
}

/// Most of the read query endpoints support multiple levels of consistency.
/// Since no policy will suit all clients' needs, these consistency modes allow the user to have the ultimate say in how to balance the trade-offs inherent in a distributed system.
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ConsistencyMode {
    /// If not specified, the default is strongly consistent in almost all cases.
    /// However, there is a small window in which a new leader may be elected during which the old leader may service stale values.
    /// The trade-off is fast reads but potentially stale values.
    /// The condition resulting in stale reads is hard to trigger, and most clients should not need to worry about this case.
    /// Also, note that this race condition only applies to reads, not writes.
    #[default]
    Default,
    /// This mode is strongly consistent without caveats.
    /// It requires that a leader verify with a quorum of peers that it is still leader.
    /// This introduces an additional round-trip to all server nodes. The trade-off is increased latency due to an extra round trip.
    /// Most clients should not use this unless they cannot tolerate a stale read.
    Consistent,
    /// This mode allows any server to service the read regardless of whether it is the leader.
    /// This means reads can be arbitrarily stale; however, results are generally consistent to within 50 milliseconds of the leader.
    /// The trade-off is very fast and scalable reads with a higher likelihood of stale values.
    /// Since this mode allows reads without a leader, a cluster that is unavailable will still be able to respond to queries.
    Stale,
}

/// Response from the session-creation step
#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionResponse {
    #[serde(rename = "ID")]
    /// The Id of the created session
    pub id: String,
}

#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateSessionRequest {
    #[default(_code = "Duration::from_secs(0)")]
    #[serde(serialize_with = "serialize_duration_as_string")]
    pub(crate) lock_delay: Duration,
    #[serde(skip_serializing_if = "std::string::String::is_empty")]
    pub(crate) name: String,
    #[serde(skip_serializing_if = "std::string::String::is_empty")]
    pub(crate) node: String,
    #[serde(skip_serializing_if = "std::vec::Vec::is_empty")]
    pub(crate) checks: Vec<String>,
    pub(crate) behavior: LockExpirationBehavior,
    #[serde(rename = "TTL")]
    #[default(_code = "Duration::from_secs(10)")]
    #[serde(serialize_with = "serialize_duration_as_string")]
    pub(crate) ttl: Duration,
}

/// Payload struct to register or update entries in consul's catalog.
/// See https://www.consul.io/api-docs/catalog#register-entity for more information.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterEntityRequest<'a> {
    /// Optional UUID to assign to the node. This string is required to be 36-characters and UUID formatted.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ID")]
    pub id: Option<&'a str>,
    /// Node ID to register.
    pub node: &'a str,
    /// The address to register.
    pub address: &'a str,
    /// The datacenter to register in, defaults to the agent's datacenter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacenter: Option<&'a str>,
    /// Tagged addressed to register with.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub tagged_addresses: HashMap<&'a str, &'a str>,
    /// KV metadata paris to register with.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub node_meta: HashMap<&'a str, &'a str>,
    /// Optional service to register.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<RegisterEntityService<'a>>,
    /// Optional check to register
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<RegisterEntityCheck>,
    /// Whether to skip updating the nodes information in the registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_node_update: Option<bool>,
}

/// The service to register with consul's global catalog.
/// See https://www.consul.io/api/agent/service for more information.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterEntityService<'a> {
    /// ID to register service will, defaults to Service.Service property.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ID")]
    pub id: Option<&'a str>,
    /// The name of the service.
    pub service: &'a str,
    /// Optional tags associated with the service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<&'a str>,
    /// Optional map of explicit LAN and WAN addresses for the service.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub tagged_addresses: HashMap<&'a str, &'a str>,
    /// Optional key value meta associated with the service.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub meta: HashMap<&'a str, &'a str>,
    /// The port of the service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The consul namespace to register the service in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<&'a str>,
}

/// Information related to registering a check.
/// See https://www.consul.io/docs/discovery/checks for more information.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterEntityCheck {
    /// The node to execute the check on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Optional check id, defaults to the name of the check.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CheckID")]
    pub check_id: Option<String>,
    /// The name associated with the check
    pub name: String,
    /// Opaque field encapsulating human-readable text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The status of the check. Must be one of 'passing', 'warning', or 'critical'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// ID of the service this check is for. If no ID of a service running on the node is provided,
    /// the check is treated as a node level check
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ServiceID")]
    pub service_id: Option<String>,
    /// Details for a TCP or HTTP health check.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub definition: HashMap<String, String>,
}

/// Request body for de-registering a check or service from the Catalog
/// See https://developer.hashicorp.com/consul/api-docs/catalog#deregister-entity for more
/// information
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeregisterEntityRequest<'a> {
    /// The node on which to execute the registration
    pub node: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional string to specify which datacenter to find the node. If not supplied, defaults to
    /// the DC of the agent to which this client is connected
    pub datacenter: Option<&'a str>,
    /// Specifies the ID of the Check to remove
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CheckID")]
    pub check_id: Option<&'a str>,
    /// Specifies the ID of the Service to remove
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ServiceID")]
    pub service_id: Option<&'a str>,
    /// The consul namespace to register the service in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<&'a str>,
}

/// Request for the nodes providing a specified service registered in Consul.
#[derive(Clone, Debug, SmartDefault, Serialize, PartialEq, Eq)]
pub struct GetServiceNodesRequest<'a> {
    /// Specifies the service to list services for. This is provided as part of the URL.
    pub service: &'a str,
    /// Specifies a node name to sort the node list in ascending order based on the estimated round trip time from that node.
    /// Passing `?near=_agent` will use the agent's node for the sort. This is specified as part of the URL as a query parameter.
    /// Note that using `near` will ignore `use_streaming_backend` and always use blocking queries, because the data required to
    /// sort the results is not available to the streaming backend.
    pub near: Option<&'a str>,
    /// (bool: false) Specifies that the server should return only nodes with all checks in the passing state.
    /// This can be used to avoid additional filtering on the client side.
    pub passing: bool,
    /// (string: "") Specifies the expression used to filter the queries results prior to returning the data.
    pub filter: Option<&'a str>,
}

pub(crate) type GetServiceNodesResponse = Vec<ServiceNode>;

#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
/// An instance of a node providing a Consul service.
pub struct ServiceNode {
    /// The Node information for this service
    pub node: Node,
    /// The Service information
    pub service: Service,
}

#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
/// The node information of an instance providing a Consul service.
/// provided by the Consul Health API
pub struct Node {
    /// The ID of the service node.
    #[serde(rename = "ID")]
    pub id: String,
    /// The name of the Consul node on which the service is registered
    pub node: String,
    /// The IP address of the Consul node on which the service is registered.
    pub address: String,
    /// The datacenter where this node is running on.
    pub datacenter: String,
    /// List of explicit WAN and LAN addresses for the node
    #[serde(deserialize_with = "null_to_default")]
    pub tagged_addresses: HashMap<String, String>,
    /// Map of metadata options
    #[serde(deserialize_with = "null_to_default")]
    pub meta: HashMap<String, String>,
}

#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
/// The node information as returned by the Consul Catalog API
pub struct NodeFull {
    id: String,
    node: String,
    address: String,
    datacenter: String,
    tagged_addresses: HashMap<String, String>,
    node_meta: HashMap<String, String>,
    create_index: u64,
    modify_index: u64,
    service_address: Option<String>,
    service_enable_tag_override: Option<bool>,
    #[serde(rename = "Service_ID")]
    service_id: Option<String>,
    service_name: Option<String>,
    service_port: Option<u16>,
    service_meta: HashMap<String, String>,
    service_tagged_addresses: HashMap<String, String>,
    service_tags: Vec<String>,
    namespace: Option<String>,
}

#[derive(Clone, Debug, SmartDefault, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
/// The service information of an instance providing a Consul service.
pub struct Service {
    /// The ID of the service instance, i.e. redis-1.
    #[serde(rename = "ID")]
    pub id: String,
    /// The name of the service, i.e. redis.
    pub service: String,
    /// The address of the instance.
    pub address: String,
    /// The port of the instance.
    pub port: u16,
}

pub(crate) fn serialize_duration_as_string<S>(
    duration: &Duration,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut res = duration.as_secs().to_string();
    res.push('s');
    serializer.serialize_str(&res)
}

pub(crate) fn duration_as_string(duration: &Duration) -> String {
    let mut res = duration.as_secs().to_string();
    res.push('s');
    res
}

/// Operation types for all available verbs within a Consul Transaction
/// See https://developer.hashicorp.com/consul/api-docs/txn#tables-of-operations for more
/// information
/// NOTE: Presently only the KV-based operations are supported by this client
#[derive(Clone, SmartDefault, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionOpVerb {
    #[default]
    /// Sets the Key to the given Value
    Set,
    /// Sets, but with CAS semantics
    Cas,
    /// Lock with the given session
    Lock,
    /// Unlock with the given session
    Unlock,
    /// Get the key, fails if the key doesn't exist
    Get,
    /// Get all keys using the 'key' field as a prefix
    GetTree,
    /// Fail if modify_index != index
    CheckIndex,
    /// Fail if not locked by the supplied session
    CheckSession,
    /// Fail if key exists
    CheckNotExists,
    /// Delete the key (and value at the key)
    Delete,
    /// Delete all keys/vals starting with prefix
    DeleteTree,
    /// Delete, but with CAS semantics
    DeleteCas,
}

/// A helper type which serializes a `Vec<u8>` from/to a bas64 encoded String
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Base64Vec(pub Vec<u8>);

impl Serialize for Base64Vec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::display::Base64Display::with_config(
            &self.0,
            base64::STANDARD,
        ))
    }
}

impl<'de> Deserialize<'de> for Base64Vec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = Base64Vec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: SerdeError>(self, v: &str) -> Result<Self::Value, E> {
                base64::decode(v).map(Base64Vec).map_err(SerdeError::custom)
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

impl From<Vec<u8>> for Base64Vec {
    fn from(a: Vec<u8>) -> Base64Vec {
        Base64Vec(a)
    }
}

impl From<Base64Vec> for Vec<u8> {
    fn from(a: Base64Vec) -> Vec<u8> {
        a.0
    }
}

fn null_to_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::deserialize(d)?;
    let val = opt.unwrap_or_default();
    Ok(val)
}
