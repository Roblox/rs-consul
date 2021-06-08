//! consul
//!
//! This crate provides access to a set of strongly typed apis to interact with consul (https://www.consul.io/)
#![deny(missing_docs)]

use hyper::{body::Buf, client::HttpConnector, Body, Method};
use hyper_tls::HttpsConnector;
use opentelemetry_wrapper::{
    global::{self, BoxedTracer},
    trace::{Span, StatusCode},
};
use quick_error::quick_error;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};
use std::{env, str::Utf8Error};
use tokio::time::timeout;

pub use types::*;
/// The strongly typed data structures representing canonical consul objects.
pub mod types;

quick_error! {
    /// The error type returned from all calls into this this crate.
    #[derive(Debug)]
    pub enum ConsulError {
        /// The request was invalid and could not be serialized to valid json.
        InvalidRequest(err: serde_json::error::Error) {}
        /// The request was invalid and could not be converted into a proper http request.
        RequestError(err: http::Error) {}
        /// The consul server response could not be converted into a proper http response.
        ResponseError(err: hyper::Error) {}
        /// The consul server response was invalid.
        InvalidResponse(err: hyper::Error) {}
        /// The consul server response could not be deserialized from json.
        ResponseDeserializationFailed(err: serde_json::error::Error) {}
        /// The consul server response could not be deserialized from bytes.
        ResponseStringDeserializationFailed(err: std::str::Utf8Error) {}
        /// The consul server response was something other than 200. The status code and the body of the response are included.
        UnexpectedResponseCode(status_code: hyper::http::StatusCode, body: String) {}
        /// The consul server refused a lock acquisition (usually because some other session has a lock).
        LockAcquisitionFailure(err: u64) {}
        /// Consul returned invalid UTF8.
        InvalidUtf8(err: Utf8Error) {
            from()
        }
        /// Consul returned invalid base64.
        InvalidBase64(err: base64::DecodeError) {
            from()
        }
        /// IO error from sync api.
        SyncIoError(err: std::io::Error) {
            from()
        }
        /// Response parse error from sync api.
        SyncInvalidResponseError(err: std::str::ParseBoolError) {
            from()
        }
        /// Unexpected response code from sync api.
        SyncUnexpectedResponseCode(status_code: u16, body: String) {}
        /// Consul request exceeded specified timeout.
        TimeoutExceeded(timeout: std::time::Duration) {
            display("Consul request exceeded timeout of {:?}", timeout)
        }
        /// Unable to resolve the service's instances in Consul.
        ServiceInstanceResolutionFailed(service_name: String) {
            display("Unable to resolve service '{}' to a concrete list of addresses and ports for its instances via consul.", service_name)
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, ConsulError>;

/// The config necessary to create a new consul client.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// The address of the consul server. This must include the protocol to connect over eg. http or https.
    pub address: String,
    /// The consul secret token to make authenticated requests to the consul server.
    pub token: Option<String>,
}

impl Config {
    /// Obtains a [`Config`](consul::Config) from environment variables.
    /// Specifically, looks for `CONSUL_HTTP_TOKEN` and `CONSUL_HTTP_ADDR` as environment variables.
    /// # Errors
    /// Returns an [error](env::VarError) if either environment variable is missing.
    pub fn from_env() -> Self {
        let token = env::var("CONSUL_HTTP_TOKEN").unwrap_or_default();
        let addr =
            env::var("CONSUL_HTTP_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8500".to_string());

        Config {
            address: addr,
            token: Some(token),
        }
    }
}

/// Represents a lock against Consul.
/// The lifetime of this object defines the validity of the lock against consul.
/// When the object is dropped, the lock is attempted to be released for the next consumer.
#[derive(Clone, Debug)]
pub struct Lock<'a> {
    /// The session ID of the lock.
    pub session_id: String,
    /// The key for the lock.
    pub key: String,
    /// The timeout of the session and the lock.
    pub timeout: std::time::Duration,
    /// The namespace this lock exists in.
    pub namespace: String,
    /// The datacenter of this lock.
    pub datacenter: String,
    /// The data in this lock's key
    pub value: Option<Vec<u8>>,
    /// The consul client this lock was acquired using.
    pub consul: &'a Consul,
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        let req = CreateOrUpdateKeyRequest {
            key: &self.key,
            namespace: &self.namespace,
            datacenter: &self.datacenter,
            release: &self.session_id,
            ..Default::default()
        };

        let val = self.value.clone().unwrap_or_default();

        // This can fail and that's okay. Consumers should not be using long session or locks.
        // Consul prefers liveness over safety so there's a chance the lock gets dropped.
        // For safe consumer patterns, see https://learn.hashicorp.com/tutorials/consul/application-leader-elections?in=consul/developer-configuration#next-steps
        let _res = self.consul.create_or_update_key_sync(req, val);
    }
}

#[derive(Debug)]
/// This struct defines the consul client and allows access to the consul api via method syntax.
pub struct Consul {
    https_client: hyper::Client<HttpsConnector<HttpConnector>, Body>,
    config: Config,
    tracer: BoxedTracer,
}

impl Consul {
    /// Creates a new instance of [`Consul`](consul::Consul).
    /// This is the entry point for this crate.
    /// #Arguments:
    /// - [Config](consul::Config)
    pub fn new(config: Config) -> Self {
        let https = HttpsConnector::new();
        let https_client = hyper::Client::builder().build::<_, hyper::Body>(https);
        Consul {
            https_client,
            config,
            tracer: global::tracer("consul"),
        }
    }

    /// Reads a key from Consul's KV store. See the [consul docs](https://www.consul.io/api-docs/kv#read-key) for more information.
    /// # Arguments:
    /// - request - the [ReadKeyRequest](consul::types::ReadKeyRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn read_key(&self, request: ReadKeyRequest<'_>) -> Result<Vec<ReadKeyResponse>> {
        let req = self.build_read_key_req(request);
        let (mut response_body, _index) = self
            .execute_request(req, hyper::Body::empty(), None)
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        serde_json::from_slice::<Vec<ReadKeyResponse>>(&bytes)
            .map_err(ConsulError::ResponseDeserializationFailed)?
            .into_iter()
            .map(|mut r| {
                r.value = match r.value {
                    Some(val) => Some(std::str::from_utf8(&base64::decode(val)?)?.to_string()),
                    None => None,
                };

                Ok(r)
            })
            .collect()
    }

    /// Creates or updates a key in Consul's KV store. See the [consul docs](https://www.consul.io/api-docs/kv#create-update-key) for more information.
    /// # Arguments:
    /// - request - the [CreateOrUpdateKeyRequest](consul::types::CreateOrUpdateKeyRequest)
    /// - value - the data to store as [Bytes](bytes::Bytes)
    /// # Returns:
    /// A tuple of a boolean and a 64 bit unsigned integer representing whether the operation was successful and the index for a subsequent blocking query.
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn create_or_update_key(
        &self,
        request: CreateOrUpdateKeyRequest<'_>,
        value: Vec<u8>,
    ) -> Result<(bool, u64)> {
        let url = self.build_create_or_update_url(request);
        let req = hyper::Request::builder().method(Method::PUT).uri(url);
        let (mut response_body, index) = self.execute_request(req, Body::from(value), None).await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        Ok((
            serde_json::from_slice(&bytes).map_err(ConsulError::ResponseDeserializationFailed)?,
            index,
        ))
    }

    /// Creates or updates a key in Consul's KV store. See the [consul docs](https://www.consul.io/api-docs/kv#create-update-key) for more information.
    /// This is the synchronous version of create_or_update_key
    /// # Arguments:
    /// - request - the [CreateOrUpdateKeyRequest](consul::types::CreateOrUpdateKeyRequest)
    /// - value - the data to store as [Bytes](bytes::Bytes)
    /// # Returns:
    /// A tuple of a boolean and a 64 bit unsigned integer representing whether the operation was successful and the index for a subsequent blocking query.
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub fn create_or_update_key_sync(
        &self,
        request: CreateOrUpdateKeyRequest<'_>,
        value: Vec<u8>,
    ) -> Result<bool> {
        // TODO: Emit OpenTelemetry span for this request

        let url = self.build_create_or_update_url(request);
        let res = ureq::put(&url)
            .set(
                "X-Consul-Token",
                &self.config.token.clone().unwrap_or_default(),
            )
            .send_bytes(&value);

        let status = res.status();
        if status == 200 {
            let val = res.into_string()?;
            let response: bool = std::str::FromStr::from_str(val.trim())?;
            return Ok(response);
        }

        let body = res.into_string()?;
        Err(ConsulError::SyncUnexpectedResponseCode(status, body))
    }

    /// Deletes a key from Consul's KV store. See the [consul docs](https://www.consul.io/api-docs/kv#delete-key) for more information.
    /// # Arguments:
    /// - request - the [DeleteKeyRequest](consul::types::DeleteKeyRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn delete_key(&self, request: DeleteKeyRequest<'_>) -> Result<bool> {
        let mut req = hyper::Request::builder().method(Method::DELETE);
        let mut url = String::new();
        url.push_str(&format!(
            "{}/v1/kv/{}?recurse={}",
            self.config.address, request.key, request.recurse
        ));
        if request.check_and_set != 0 {
            url.push_str(&format!("&cas={}", request.check_and_set));
        }

        url = add_namespace_and_datacenter(url, request.namespace, request.datacenter);
        req = req.uri(url);
        let (mut response_body, _index) = self
            .execute_request(req, hyper::Body::empty(), None)
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        Ok(serde_json::from_slice(&bytes).map_err(ConsulError::ResponseDeserializationFailed)?)
    }

    /// Obtains a lock against a specific key in consul. See the [consul docs](https://learn.hashicorp.com/tutorials/consul/application-leader-elections?in=consul/developer-configuration) for more information.
    /// # Arguments:
    /// - request - the [LockRequest](consul::types::LockRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn get_lock<'a, 'b>(
        &'b self,
        request: LockRequest<'a>,
        value: &[u8],
    ) -> Result<Lock<'b>> {
        let session = self.get_session(request).await?;
        let req = CreateOrUpdateKeyRequest {
            key: request.key,
            namespace: request.namespace,
            datacenter: request.datacenter,
            acquire: &session.id,
            ..Default::default()
        };
        let value_copy = value.to_vec();
        let (lock_acquisition_result, _index) = self.create_or_update_key(req, value_copy).await?;
        if lock_acquisition_result {
            let value_copy = value.to_vec();
            Ok(Lock {
                timeout: request.timeout,
                key: request.key.to_string(),
                session_id: session.id,
                consul: &self,
                datacenter: request.datacenter.to_string(),
                namespace: request.namespace.to_string(),
                value: Some(value_copy),
            })
        } else {
            let watch_req = ReadKeyRequest {
                key: request.key,
                datacenter: request.datacenter,
                namespace: request.namespace,
                index: Some(0),
                wait: std::time::Duration::from_secs(0),
                ..Default::default()
            };
            let lock_index_req = self.build_read_key_req(watch_req);
            let (_watch, index) = self
                .execute_request(lock_index_req, hyper::Body::empty(), None)
                .await?;
            Err(ConsulError::LockAcquisitionFailure(index))
        }
    }

    /// Watches lock against a specific key in consul. See the [consul docs](https://learn.hashicorp.com/tutorials/consul/application-leader-elections?in=consul/developer-configuration#watch-the-session) for more information.
    /// # Arguments:
    /// - request - the [LockWatchRequest](consul::types::LockWatchRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn watch_lock<'a>(
        &self,
        request: LockWatchRequest<'_>,
    ) -> Result<Vec<ReadKeyResponse>> {
        let req = ReadKeyRequest {
            key: request.key,
            namespace: request.namespace,
            datacenter: request.datacenter,
            index: request.index,
            wait: request.wait,
            consistency: request.consistency,
            ..Default::default()
        };
        self.read_key(req).await
    }

    /// returns the nodes providing the service indicated on the path.
    /// Users can also build in support for dynamic load balancing and other features by incorporating the use of health checks.
    /// See the [consul docs](https://www.consul.io/api-docs/health#list-nodes-for-service) for more information.
    /// # Arguments:
    /// - request - the [GetServiceNodesRequest](consul::types::GetServiceNodesRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn get_service_nodes(
        &self,
        request: GetServiceNodesRequest<'_>,
    ) -> Result<GetServiceNodesResponse> {
        let req = self.build_get_service_nodes_req(request);
        let (mut response_body, _index) = self
            .execute_request(
                req,
                hyper::Body::empty(),
                Some(std::time::Duration::from_secs(5)),
            )
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        Ok(serde_json::from_slice::<GetServiceNodesResponse>(&bytes)
            .map_err(ConsulError::ResponseDeserializationFailed)?)
    }

    /// Queries consul for a service and returns the Address:Port of all instances registered for that service.
    pub async fn get_service_addresses_and_ports(
        &self,
        service_name: &str,
    ) -> Result<Vec<(String, u16)>> {
        let request = GetServiceNodesRequest {
            service: service_name,
            passing: true,
            ..Default::default()
        };
        let services = self.get_service_nodes(request).await.map_err(|e| {
            let err = format!(
                "Unable to query consul to resolve service '{}' to a list of addresses and ports: {:?}",
                service_name, e
            );
            error!("{}", err);
            ConsulError::ServiceInstanceResolutionFailed(service_name.to_string())
        })?;

        let addresses_and_ports = services
            .into_iter()
            .map(Self::parse_host_port_from_service_node_response)
            .collect();
        info!(
            "resolved service '{}' to addresses and ports: '{:?}'",
            service_name, addresses_and_ports
        );

        Ok(addresses_and_ports)
    }

    /// Parse the address and port from a Consul [`ServiceNode`](`ServiceNode`) response.
    /// This chooses the Service address:port if the address is present. If not, it chooses the Node address with the service port.
    /// https://roblox.slack.com/archives/C01E58TBWVC/p1621622393146700?thread_ts=1621544799.123700&cid=C01E58TBWVC
    fn parse_host_port_from_service_node_response(sn: ServiceNode) -> (String, u16) {
        (
            if sn.service.address.is_empty() {
                info!(
                    "Consul service {service_name} instance had an empty Service address, with port:{port}",
                    service_name = &sn.service.service, port = sn.service.port
                );
                sn.node.address
            } else {
                sn.service.address
            },
            sn.service.port,
        )
    }

    fn build_read_key_req(&self, request: ReadKeyRequest<'_>) -> http::request::Builder {
        let req = hyper::Request::builder().method(Method::GET);
        let mut url = String::new();
        url.push_str(&format!(
            "{}/v1/kv/{}?recurse={}",
            self.config.address, request.key, request.recurse
        ));

        if !request.separator.is_empty() {
            url.push_str(&format!("&separator={}", request.separator));
        }
        if request.consistency == ConsistencyMode::Consistent {
            url.push_str("&consistent");
        } else if request.consistency == ConsistencyMode::Stale {
            url.push_str("&stale");
        }

        if let Some(index) = request.index {
            url.push_str(&format!("&index={}", index));
            if request.wait.as_secs() > 0 {
                url.push_str(&format!(
                    "&wait={}",
                    types::duration_as_string(&request.wait)
                ));
            }
        }
        url = add_namespace_and_datacenter(url, request.namespace, request.datacenter);
        req.uri(url)
    }

    async fn get_session(&self, request: LockRequest<'_>) -> Result<SessionResponse> {
        let session_req = CreateSessionRequest {
            lock_delay: request.lock_delay,
            behavior: request.behavior,
            ttl: request.timeout,
            ..Default::default()
        };

        let mut req = hyper::Request::builder().method(Method::PUT);
        let mut url = String::new();
        url.push_str(&format!("{}/v1/session/create?", self.config.address));
        url = add_namespace_and_datacenter(url, request.namespace, request.datacenter);
        req = req.uri(url);
        let create_session_json =
            serde_json::to_string(&session_req).map_err(ConsulError::InvalidRequest)?;
        let (mut response_body, _index) = self
            .execute_request(req, hyper::Body::from(create_session_json), None)
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        Ok(serde_json::from_slice(&bytes).map_err(ConsulError::ResponseDeserializationFailed)?)
    }

    fn build_get_service_nodes_req(
        &self,
        request: GetServiceNodesRequest<'_>,
    ) -> http::request::Builder {
        let req = hyper::Request::builder().method(Method::GET);
        let mut url = String::new();
        url.push_str(&format!(
            "{}/v1/health/service/{}",
            self.config.address, request.service
        ));
        url.push_str(&format!("?passing={}", request.passing));
        if let Some(near) = request.near {
            url.push_str(&format!("&near={}", near));
        }
        if let Some(filter) = request.filter {
            url.push_str(&format!("&filter={}", filter));
        }
        if let Some(ns) = request.namespace {
            url.push_str(&format!("&ns={}", ns));
        }
        if let Some(dc) = request.datacenter {
            url.push_str(&format!("&dc={}", dc));
        }
        req.uri(url)
    }

    async fn execute_request<'a>(
        &self,
        req: http::request::Builder,
        body: hyper::Body,
        duration: Option<std::time::Duration>,
    ) -> Result<(Box<dyn Buf>, u64)> {
        let req = req
            .header(
                "X-Consul-Token",
                self.config.token.clone().unwrap_or_default(),
            )
            .body(body);
        let req = req.map_err(ConsulError::RequestError)?;
        let span = opentelemetry_wrapper::span_for_request(&self.tracer, &req);
        let future = self.https_client.request(req);

        let response = if let Some(dur) = duration {
            match timeout(dur, future).await {
                Ok(resp) => resp.map_err(ConsulError::ResponseError)?,
                Err(_) => return Err(ConsulError::TimeoutExceeded(dur)),
            }
        } else {
            future.await.map_err(ConsulError::ResponseError)?
        };

        opentelemetry_wrapper::annotate_span_for_response(&span, &response);

        let status = response.status();
        if status != hyper::StatusCode::OK {
            let mut response_body = hyper::body::aggregate(response.into_body())
                .await
                .map_err(|e| ConsulError::UnexpectedResponseCode(status, e.to_string()))?;
            let bytes = response_body.copy_to_bytes(response_body.remaining());
            let resp = std::str::from_utf8(&*bytes)
                .map_err(|e| ConsulError::UnexpectedResponseCode(status, e.to_string()))?;
            return Err(ConsulError::UnexpectedResponseCode(
                status,
                resp.to_string(),
            ));
        }
        let index = match response.headers().get("x-consul-index") {
            Some(header) => header.to_str().unwrap_or("0").parse::<u64>().unwrap_or(0),
            None => 0,
        };

        match hyper::body::aggregate(response.into_body()).await {
            Ok(body) => Ok((Box::new(body), index)),
            Err(e) => {
                span.set_status(StatusCode::Error, e.to_string());
                return Err(ConsulError::InvalidResponse(e));
            }
        }
    }

    fn build_create_or_update_url(&self, request: CreateOrUpdateKeyRequest<'_>) -> String {
        let mut url = String::new();
        url.push_str(&format!("{}/v1/kv/{}", self.config.address, request.key,));
        let mut added_query_param = false;
        if request.flags != 0 {
            url = add_query_param_separator(url, added_query_param);
            url.push_str(&format!("flags={}", request.flags));
            added_query_param = true;
        }
        if !request.acquire.is_empty() {
            url = add_query_param_separator(url, added_query_param);
            url.push_str(&format!("acquire={}", request.acquire));
            added_query_param = true;
        }
        if !request.release.is_empty() {
            url = add_query_param_separator(url, added_query_param);
            url.push_str(&format!("release={}", request.release));
            added_query_param = true;
        }
        if request.check_and_set != 0 {
            url = add_query_param_separator(url, added_query_param);
            url.push_str(&format!("cas={}", request.check_and_set));
        }

        add_namespace_and_datacenter(url, request.namespace, request.datacenter)
    }
}

fn add_namespace_and_datacenter<'a>(
    mut url: String,
    namespace: &'a str,
    datacenter: &'a str,
) -> String {
    if !namespace.is_empty() {
        url.push_str(&format!("&ns={}", namespace));
    }
    if !datacenter.is_empty() {
        url.push_str(&format!("&dc={}", datacenter));
    }

    url
}

fn add_query_param_separator(mut url: String, already_added: bool) -> String {
    if already_added {
        url.push('&');
    } else {
        url.push('?');
    }

    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_read_key() {
        let consul = get_client();
        let key = "test/consul/read";
        let string_value = "This is a test";
        let res = create_or_update_key_value(&consul, key, string_value).await;
        assert_expected_result_with_index(res);

        let res = read_key(&consul, key).await;
        verify_single_value_matches(res, string_value);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_services_nodes() {
        let consul = get_client();
        let req = GetServiceNodesRequest {
            service: "nonexistent",
            passing: true,
            ..Default::default()
        };
        let res = consul.get_service_nodes(req).await.unwrap();
        assert_eq!(res.len(), 0);

        let req = GetServiceNodesRequest {
            service: "nomad",
            passing: false,
            ..Default::default()
        };
        let res = consul.get_service_nodes(req).await.unwrap();
        assert_eq!(res.len(), 3);

        let req = GetServiceNodesRequest {
            service: "crdb-entities-as-a-service-one",
            passing: true,
            ..Default::default()
        };
        let res = consul.get_service_nodes(req).await.unwrap();
        assert_eq!(res.len(), 3);

        let addresses: Vec<String> = res.into_iter().map(|sn| sn.service.address).collect();
        let expected_addresses = vec![
            "cockroachdb-node-1.".to_string(),
            "cockroachdb-node-2.".to_string(),
            "cockroachdb-node-3.".to_string(),
        ];
        assert!(expected_addresses
            .iter()
            .all(|item| addresses.contains(item)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_delete_key() {
        let consul = get_client();
        let key = "test/consul/again";
        let string_value = "This is a new test";
        let res = create_or_update_key_value(&consul, key, string_value).await;
        assert_expected_result_with_index(res);

        let res = delete_key(&consul, key).await;
        assert_expected_result(res);

        let res = read_key(&consul, key).await.unwrap_err();
        match res {
            ConsulError::UnexpectedResponseCode(code, _body) => {
                assert_eq!(code, hyper::http::StatusCode::NOT_FOUND)
            }
            _ => panic!(
                "Expected ConsulError::UnexpectedResponseCode, got {:#?}",
                res
            ),
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_release_lock() {
        let consul = get_client();
        let key = "test/consul/lock";
        let string_value = "This is a lock test";
        let new_string_value = "This is a changed lock test";
        let req = LockRequest {
            key: key,
            behavior: LockExpirationBehavior::Release,
            lock_delay: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        let session_id: String;
        {
            let res = consul
                .get_lock(req, &string_value.as_bytes().to_vec())
                .await;
            assert!(res.is_ok());
            let mut lock = res.unwrap();
            let res2 = consul
                .get_lock(req, &string_value.as_bytes().to_vec())
                .await;
            assert!(res2.is_err());
            let err = res2.unwrap_err();
            match err {
                ConsulError::LockAcquisitionFailure(_index) => (),
                _ => panic!(
                    "Expected ConsulError::LockAcquisitionFailure, got {:#?}",
                    err
                ),
            }
            session_id = lock.session_id.to_string();
            // Lets change the value before dropping the lock to ensure the change is persisted when the lock is dropped.
            lock.value = Some(new_string_value.as_bytes().to_vec())
            // lock gets dropped here.
        }

        sleep(Duration::from_secs(2)).await;
        let key_resp = read_key(&consul, key).await;
        verify_single_value_matches(key_resp, &new_string_value);

        let req = LockRequest {
            key: key,
            behavior: LockExpirationBehavior::Delete,
            lock_delay: std::time::Duration::from_secs(1),
            session_id: &session_id,
            ..Default::default()
        };
        let res = consul
            .get_lock(req, &string_value.as_bytes().to_vec())
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_watch_lock() {
        let consul = get_client();
        let key = "test/consul/watchedlock";
        let string_value = "This is a lock test";
        let req = LockRequest {
            key: key,
            behavior: LockExpirationBehavior::Release,
            lock_delay: std::time::Duration::from_secs(0),
            ..Default::default()
        };
        let start_index: u64;
        let res = consul
            .get_lock(req, &string_value.as_bytes().to_vec())
            .await;
        assert!(res.is_ok());
        let lock = res.unwrap();
        let res2 = consul
            .get_lock(req, &string_value.as_bytes().to_vec())
            .await;
        assert!(res2.is_err());
        let err = res2.unwrap_err();
        match err {
            ConsulError::LockAcquisitionFailure(index) => start_index = index,
            _ => panic!(
                "Expected ConsulError::LockAcquisitionFailure, got {:#?}",
                err
            ),
        }

        assert!(start_index > 0);
        let watch_req = LockWatchRequest {
            key: key,
            consistency: ConsistencyMode::Consistent,
            index: Some(start_index),
            wait: Duration::from_secs(60),
            ..Default::default()
        };
        // The lock will timeout and this this will return.
        let res = consul.watch_lock(watch_req).await;
        assert!(res.is_ok());
        std::mem::drop(lock); // This ensures the lock is not dropped until after the request to watch it completes.

        let res = consul
            .get_lock(req, &string_value.as_bytes().to_vec())
            .await;
        assert!(res.is_ok());
    }

    #[test]
    fn test_service_node_parsing() {
        let node = Node {
            id: "node".to_string(),
            node: "node".to_string(),
            address: "1.1.1.1".to_string(),
        };

        let service = Service {
            id: "node".to_string(),
            service: "node".to_string(),
            address: "2.2.2.2".to_string(),
            port: 32,
        };

        let empty_service = Service {
            id: "".to_string(),
            service: "".to_string(),
            address: "".to_string(),
            port: 32,
        };

        let sn = ServiceNode {
            node: node.clone(),
            service: service.clone(),
        };

        let (host, port) = Consul::parse_host_port_from_service_node_response(sn);
        assert_eq!(service.port, port);
        assert_eq!(service.address, host);

        let sn = ServiceNode {
            node: node.clone(),
            service: empty_service.clone(),
        };

        let (host, port) = Consul::parse_host_port_from_service_node_response(sn);
        assert_eq!(service.port, port);
        assert_eq!(node.address, host);
    }

    fn get_client() -> Consul {
        let conf: Config = Config::from_env();
        Consul::new(conf)
    }

    async fn create_or_update_key_value(
        consul: &Consul,
        key: &str,
        value: &str,
    ) -> Result<(bool, u64)> {
        let req = CreateOrUpdateKeyRequest {
            key: key,
            ..Default::default()
        };
        Ok(consul
            .create_or_update_key(req, value.as_bytes().to_vec())
            .await?)
    }

    async fn read_key(consul: &Consul, key: &str) -> Result<Vec<ReadKeyResponse>> {
        let req = ReadKeyRequest {
            key: key,
            ..Default::default()
        };
        consul.read_key(req).await
    }

    async fn delete_key(consul: &Consul, key: &str) -> Result<bool> {
        let req = DeleteKeyRequest {
            key: key,
            ..Default::default()
        };
        consul.delete_key(req).await
    }

    fn assert_expected_result_with_index(res: Result<(bool, u64)>) {
        assert!(res.is_ok());
        let (result, _index) = res.unwrap();
        assert!(result);
    }

    fn assert_expected_result(res: Result<bool>) {
        assert!(res.is_ok());
        assert!(res.unwrap());
    }

    fn verify_single_value_matches(res: Result<Vec<ReadKeyResponse>>, value: &str) {
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().into_iter().next().unwrap().value.unwrap(),
            value
        )
    }
}
