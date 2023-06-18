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

//! consul
//!
//! This crate provides access to a set of strongly typed apis to interact with consul (https://www.consul.io/)
#![deny(missing_docs)]

use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{env, str::Utf8Error};

use hyper::{body::Buf, client::HttpConnector, Body, Method};
#[cfg(any(feature = "rustls-native", feature = "rustls-webpki"))]
use hyper_rustls::HttpsConnector;
#[cfg(feature = "default-tls")]

#[cfg(feature = "metrics")]
use lazy_static::lazy_static;
use opentelemetry::global;
use opentelemetry::global::BoxedTracer;
use opentelemetry::trace::Span;
use opentelemetry::trace::Status;
use quick_error::quick_error;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};
use tokio::time::timeout;

pub use types::*;

mod hyper_wrapper;
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
        /// The request failed either due to an unexpected status code or a transport error.
        RequestFailedError(err: ureq::Error) {
            from()
        }

    }
}

#[cfg(feature = "metrics")]
lazy_static! {
    static ref CONSUL_REQUESTS_TOTAL: prometheus::CounterVec = prometheus::register_counter_vec!(
        prometheus::opts!("consul_requests_total", "Total requests made to consul"),
        &["method", "function"]
    )
    .unwrap();
    static ref CONSUL_REQUESTS_FAILED_TOTAL: prometheus::CounterVec =
        prometheus::register_counter_vec!(
            prometheus::opts!(
                "consul_requests_failed_total",
                "Total requests made to consul that failed"
            ),
            &["method", "function"]
        )
        .unwrap();
    static ref CONSUL_REQUESTS_DURATION_MS: prometheus::HistogramVec =
        prometheus::register_histogram_vec!(
            prometheus::histogram_opts!(
                "consul_requests_duration_milliseconds",
                "Time it takes for a consul request to complete"
            ),
            &["method", "function"]
        )
        .unwrap();
}

const READ_KEY_METHOD_NAME: &str = "read_key";
const CREATE_OR_UPDATE_KEY_METHOD_NAME: &str = "create_or_update_key";
const CREATE_OR_UPDATE_KEY_SYNC_METHOD_NAME: &str = "create_or_update_key_sync";
const DELETE_KEY_METHOD_NAME: &str = "delete_key";
const GET_LOCK_METHOD_NAME: &str = "get_lock";
const REGISTER_ENTITY_METHOD_NAME: &str = "register_entity";
const GET_ALL_REGISTERED_SERVICE_NAMES_METHOD_NAME: &str = "get_all_registered_service_names";
const GET_SERVICE_NODES_METHOD_NAME: &str = "get_service_nodes";
const GET_SESSION_METHOD_NAME: &str = "get_session";

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

fn https_client() -> HttpsConnector<HttpConnector> {
    #[cfg(feature = "rustls-native")]
    return hyper_rustls::HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().build();
    #[cfg(feature = "rustls-webpki")]
    return hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots().https_or_http().enable_http1().build();
    #[cfg(feature = "default-tls")]
    return HttpsConnector::new();
}

impl Consul {
    /// Creates a new instance of [`Consul`](consul::Consul).
    /// This is the entry point for this crate.
    /// #Arguments:
    /// - [Config](consul::Config)
    pub fn new(config: Config) -> Self {
        let https = https_client();
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
            .execute_request(req, hyper::Body::empty(), None, READ_KEY_METHOD_NAME)
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
        let (mut response_body, index) = self
            .execute_request(
                req,
                Body::from(value),
                None,
                CREATE_OR_UPDATE_KEY_METHOD_NAME,
            )
            .await?;
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

        record_request_metric_if_enabled(&Method::PUT, CREATE_OR_UPDATE_KEY_SYNC_METHOD_NAME);
        let step_start_instant = Instant::now();
        let result = ureq::put(&url)
            .set(
                "X-Consul-Token",
                &self.config.token.clone().unwrap_or_default(),
            )
            .send_bytes(&value);

        record_duration_metric_if_enabled(
            &Method::PUT,
            CREATE_OR_UPDATE_KEY_SYNC_METHOD_NAME,
            step_start_instant.elapsed().as_millis() as f64,
        );
        let response = result.map_err(|e| {
                    record_failure_metric_if_enabled(&Method::PUT, CREATE_OR_UPDATE_KEY_SYNC_METHOD_NAME);
                    ConsulError::RequestFailedError(e)
                })?;
        let status = response.status();
        if status == 200 {
            let val = response.into_string()?;
            let response: bool = std::str::FromStr::from_str(val.trim())?;
            return Ok(response);
        }

        let body = response.into_string()?;
        record_failure_metric_if_enabled(&Method::PUT, CREATE_OR_UPDATE_KEY_SYNC_METHOD_NAME);
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
            .execute_request(req, hyper::Body::empty(), None, DELETE_KEY_METHOD_NAME)
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        serde_json::from_slice(&bytes).map_err(ConsulError::ResponseDeserializationFailed)
    }

    /// Obtains a lock against a specific key in consul. See the [consul docs](https://learn.hashicorp.com/tutorials/consul/application-leader-elections?in=consul/developer-configuration) for more information.
    /// # Arguments:
    /// - request - the [LockRequest](consul::types::LockRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn get_lock(&self, request: LockRequest<'_>, value: &[u8]) -> Result<Lock<'_>> {
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
                consul: self,
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
                .execute_request(
                    lock_index_req,
                    hyper::Body::empty(),
                    None,
                    GET_LOCK_METHOD_NAME,
                )
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

    /// Registers or updates entries in consul's global catalog.
    /// See https://www.consul.io/api-docs/catalog#register-entity for more information.
    /// # Arguments:
    /// - payload: The [`RegisterEntityPayload`](RegisterEntityPayload) to provide the register entity API.
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn register_entity(&self, payload: &RegisterEntityPayload) -> Result<()> {
        let uri = format!("{}/v1/catalog/register", self.config.address);
        let request = hyper::Request::builder().method(Method::PUT).uri(uri);
        let payload = serde_json::to_string(payload).map_err(ConsulError::InvalidRequest)?;
        self.execute_request(
            request,
            payload.into(),
            Some(Duration::from_secs(5)),
            REGISTER_ENTITY_METHOD_NAME,
        )
        .await?;
        Ok(())
    }

    /// Returns all services currently registered with consul.
    /// See https://www.consul.io/api-docs/catalog#list-services for more information.
    /// # Arguments:
    /// - query_opts: The [`QueryOptions`](QueryOptions) to apply for this endpoint.
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn get_all_registered_service_names(
        &self,
        query_opts: Option<QueryOptions>,
    ) -> Result<ResponseMeta<Vec<String>>> {
        let mut uri = format!("{}/v1/catalog/services", self.config.address);
        let query_opts = query_opts.unwrap_or_default();
        add_query_option_params(&mut uri, &query_opts, '?');

        let request = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri.clone());
        let (mut response_body, index) = self
            .execute_request(
                request,
                hyper::Body::empty(),
                query_opts.timeout,
                GET_ALL_REGISTERED_SERVICE_NAMES_METHOD_NAME,
            )
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        let service_tags_by_name = serde_json::from_slice::<HashMap<String, Vec<String>>>(&bytes)
            .map_err(ConsulError::ResponseDeserializationFailed)?;

        Ok(ResponseMeta {
            response: service_tags_by_name.keys().cloned().collect(),
            index,
        })
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
        query_opts: Option<QueryOptions>,
    ) -> Result<ResponseMeta<GetServiceNodesResponse>> {
        let query_opts = query_opts.unwrap_or_default();
        let req = self.build_get_service_nodes_req(request, &query_opts);
        let (mut response_body, index) = self
            .execute_request(
                req,
                hyper::Body::empty(),
                query_opts.timeout,
                GET_SERVICE_NODES_METHOD_NAME,
            )
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        let response = serde_json::from_slice::<GetServiceNodesResponse>(&bytes)
            .map_err(ConsulError::ResponseDeserializationFailed)?;
        Ok(ResponseMeta { response, index })
    }

    /// Queries consul for a service and returns the Address:Port of all instances registered for that service.
    pub async fn get_service_addresses_and_ports(
        &self,
        service_name: &str,
        query_opts: Option<QueryOptions>,
    ) -> Result<Vec<(String, u16)>> {
        let request = GetServiceNodesRequest {
            service: service_name,
            passing: true,
            ..Default::default()
        };
        let services = self.get_service_nodes(request, query_opts).await.map_err(|e| {
            let err = format!(
                "Unable to query consul to resolve service '{}' to a list of addresses and ports: {:?}",
                service_name, e
            );
            error!("{}", err);
            ConsulError::ServiceInstanceResolutionFailed(service_name.to_string())
        })?;

        let addresses_and_ports = services
            .response
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
    /// Context: To get a list of healthy instances for a service to return their IP/ports.
    /// ServiceAddress is the IP address of the service host — if empty, node address should be used per
    /// See: https://www.consul.io/api-docs/catalog#list-nodes-for-service
    /// More context: there is a slight difference in the health vs catalog
    /// endpoints but that's already described in that we use the service port.
    /// What was confirmed was to use the node port but that doesn't exist
    /// in the health endpoint. These requests models are primarily for the
    /// health endpoints
    /// https://www.consul.io/api-docs/health#list-nodes-for-service
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
            .execute_request(
                req,
                hyper::Body::from(create_session_json),
                None,
                GET_SESSION_METHOD_NAME,
            )
            .await?;
        let bytes = response_body.copy_to_bytes(response_body.remaining());
        serde_json::from_slice(&bytes).map_err(ConsulError::ResponseDeserializationFailed)
    }

    fn build_get_service_nodes_req(
        &self,
        request: GetServiceNodesRequest<'_>,
        query_opts: &QueryOptions,
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
        add_query_option_params(&mut url, query_opts, '&');
        req.uri(url)
    }

    async fn execute_request<'a>(
        &self,
        req: http::request::Builder,
        body: hyper::Body,
        duration: Option<std::time::Duration>,
        request_name: &str,
    ) -> Result<(Box<dyn Buf>, u64)> {
        let req = req
            .header(
                "X-Consul-Token",
                self.config.token.clone().unwrap_or_default(),
            )
            .body(body);
        let req = req.map_err(ConsulError::RequestError)?;
        let mut span = crate::hyper_wrapper::span_for_request(&self.tracer, &req);

        let method = req.method().clone();
        record_request_metric_if_enabled(&method, request_name);
        let future = self.https_client.request(req);

        let step_start_instant = Instant::now();
        let response = if let Some(dur) = duration {
            match timeout(dur, future).await {
                Ok(resp) => resp.map_err(ConsulError::ResponseError),
                Err(_) => Err(ConsulError::TimeoutExceeded(dur)),
            }
        } else {
            future.await.map_err(ConsulError::ResponseError)
        };

        record_duration_metric_if_enabled(
            &method,
            request_name,
            step_start_instant.elapsed().as_millis() as f64,
        );
        if response.is_err() {
            record_failure_metric_if_enabled(&method, request_name);
        }

        let response = response?;

        crate::hyper_wrapper::annotate_span_for_response(&mut span, &response);

        let status = response.status();
        if status != hyper::StatusCode::OK {
            record_failure_metric_if_enabled(&method, request_name);

            let mut response_body = hyper::body::aggregate(response.into_body())
                .await
                .map_err(|e| ConsulError::UnexpectedResponseCode(status, e.to_string()))?;
            let bytes = response_body.copy_to_bytes(response_body.remaining());
            let resp = std::str::from_utf8(&bytes)
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
                record_failure_metric_if_enabled(&method, request_name);

                span.set_status(Status::Error { description: e.to_string().into() });
                Err(ConsulError::InvalidResponse(e))
            }
        }
    }

    fn build_create_or_update_url(&self, request: CreateOrUpdateKeyRequest<'_>) -> String {
        let mut url = String::new();
        url.push_str(&format!("{}/v1/kv/{}", self.config.address, request.key));
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
        if let Some(cas_idx) = request.check_and_set {
            url = add_query_param_separator(url, added_query_param);
            url.push_str(&format!("cas={}", cas_idx));
        }

        add_namespace_and_datacenter(url, request.namespace, request.datacenter)
    }
}

fn add_query_option_params(uri: &mut String, query_opts: &QueryOptions, mut separator: char) {
    if let Some(ns) = &query_opts.namespace {
        if !ns.is_empty() {
            uri.push_str(&format!("{}ns={}", separator, ns));
            separator = '&';
        }
    }
    if let Some(dc) = &query_opts.datacenter {
        if !dc.is_empty() {
            uri.push_str(&format!("{}dc={}", separator, dc));
            separator = '&';
        }
    }
    if let Some(idx) = query_opts.index {
        uri.push_str(&format!("{}index={}", separator, idx));
        separator = '&';
        if let Some(wait) = query_opts.wait {
            uri.push_str(&format!(
                "{}wait={}",
                separator,
                types::duration_as_string(&wait)
            ));
        }
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

fn record_request_metric_if_enabled(_method: &Method, _function: &str) {
    #[cfg(feature = "metrics")]
    {
        CONSUL_REQUESTS_TOTAL
            .with_label_values(&[_method.as_str(), _function])
            .inc();
    }
}

fn record_failure_metric_if_enabled(_method: &Method, _function: &str) {
    #[cfg(feature = "metrics")]
    {
        CONSUL_REQUESTS_FAILED_TOTAL
            .with_label_values(&[_method.as_str(), _function])
            .inc();
    }
}

fn record_duration_metric_if_enabled(_method: &Method, _function: &str, _duration: f64) {
    #[cfg(feature = "metrics")]
    {
        CONSUL_REQUESTS_DURATION_MS
            .with_label_values(&[_method.as_str(), _function])
            .observe(_duration);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;

    use super::*;

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_and_retrieve_services() {
        let consul = get_client();

        let new_service_name = "test-service-44".to_string();

        // verify a service by this name is currently not registered
        let ResponseMeta {
            response: service_names_before_register,
            ..
        } = consul
            .get_all_registered_service_names(None)
            .await
            .expect("expected get_registered_service_names request to succeed");
        assert!(!service_names_before_register.contains(&new_service_name));

        // register a new service
        let payload = RegisterEntityPayload {
            ID: None,
            Node: "local".to_string(),
            Address: "127.0.0.1".to_string(),
            Datacenter: None,
            TaggedAddresses: Default::default(),
            NodeMeta: Default::default(),
            Service: Some(RegisterEntityService {
                ID: None,
                Service: new_service_name.clone(),
                Tags: vec![],
                TaggedAddresses: Default::default(),
                Meta: Default::default(),
                Port: Some(42424),
                Namespace: None,
            }),
            Check: None,
            SkipNodeUpdate: None,
        };
        consul
            .register_entity(&payload)
            .await
            .expect("expected register_entity request to succeed");

        // verify the newly registered service is retrieved
        let ResponseMeta {
            response: service_names_after_register,
            ..
        } = consul
            .get_all_registered_service_names(None)
            .await
            .expect("expected get_registered_service_names request to succeed");
        assert!(service_names_after_register.contains(&new_service_name));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_services_nodes() {
        let consul = get_client();
        let req = GetServiceNodesRequest {
            service: "nonexistent",
            passing: true,
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_service_nodes(req, None).await.unwrap();
        assert_eq!(response.len(), 0);

        let req = GetServiceNodesRequest {
            service: "test-service",
            passing: true,
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_service_nodes(req, None).await.unwrap();
        assert_eq!(response.len(), 3);

        let addresses: Vec<String> = response
            .iter()
            .map(|sn| sn.service.address.clone())
            .collect();
        let expected_addresses = vec![
            "1.1.1.1".to_string(),
            "2.2.2.2".to_string(),
            "3.3.3.3".to_string(),
        ];
        assert!(expected_addresses
            .iter()
            .all(|item| addresses.contains(item)));

        let _: Vec<_> = response
            .iter()
            .map(|sn| assert_eq!("dc1", sn.node.datacenter))
            .collect();
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
            key,
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
            key,
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
            key,
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
            key,
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
            datacenter: "datacenter".to_string(),
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
            service: empty_service,
        };

        let (host, port) = Consul::parse_host_port_from_service_node_response(sn);
        assert_eq!(service.port, port);
        assert_eq!(node.address, host);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn properly_handle_check_and_set() {
        let consul = get_client();
        let key = "test/consul/proper_cas_handling";
        let string_value1 = "This is CAS test";
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: Some(0),
            ..Default::default()
        };

        // Key does not exist, with CAS set and modify index set to 0
        // it should be created.
        let (set, _) = consul.create_or_update_key(req.clone(), string_value1.as_bytes().to_vec()).await
            .expect("failed to create key initially");
        assert!(set);
        let (value, mod_idx1) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value1, &value.unwrap());

        // Subsequent request with CAS set to 0 should not override the
        // value.
        let string_value2 = "This is CAS test - not valid";
        let (set, _) = consul.create_or_update_key(req, string_value2.as_bytes().to_vec()).await
            .expect("failed to run subsequent create_or_update_key");
        assert!(!set);
        // Value and modify index should not have changed because set failed.
        let (value, mod_idx2) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value1, &value.unwrap());
        assert_eq!(mod_idx1, mod_idx2);

        // Successfully set value with proper CAS value.
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: Some(mod_idx1),
            ..Default::default()
        };
        let string_value3 = "This is correct CAS updated";
        let (set, _) = consul.create_or_update_key(req, string_value3.as_bytes().to_vec()).await
            .expect("failed to run create_or_update_key with proper CAS value");
        assert!(set);
        // Verify that value was updated and the index changed.
        let (value, mod_idx3) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value3, &value.unwrap());
        assert_ne!(mod_idx1, mod_idx3);

        // Successfully set value without CAS.
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: None,
            ..Default::default()
        };
        let string_value4 = "This is non CAS update";
        let (set, _) = consul.create_or_update_key(req, string_value4.as_bytes().to_vec()).await
            .expect("failed to run create_or_update_key without CAS");
        assert!(set);
        // Verify that value was updated and the index changed.
        let (value, mod_idx4) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value4, &value.unwrap());
        assert_ne!(mod_idx3, mod_idx4);
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
            key,
            ..Default::default()
        };
        Ok(consul
            .create_or_update_key(req, value.as_bytes().to_vec())
            .await?)
    }

    async fn read_key(consul: &Consul, key: &str) -> Result<Vec<ReadKeyResponse>> {
        let req = ReadKeyRequest {
            key,
            ..Default::default()
        };
        consul.read_key(req).await
    }

    async fn delete_key(consul: &Consul, key: &str) -> Result<bool> {
        let req = DeleteKeyRequest {
            key,
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

    async fn get_single_key_value_with_index(consul: &Consul, key: &str) -> (Option<String>, i64) {
        let res = read_key(consul, key).await
            .expect("failed to read key");
        let r = res.into_iter().next().unwrap();
        (r.value, r.modify_index)
    }

    fn verify_single_value_matches(res: Result<Vec<ReadKeyResponse>>, value: &str) {
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().into_iter().next().unwrap().value.unwrap(),
            value
        )
    }
}
