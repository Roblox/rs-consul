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
use http_body_util::BodyExt;

#[cfg(feature = "metrics")]
use metrics::MetricInfoWrapper;

use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::time::Duration;

use base64::Engine;
use http_body_util::combinators::BoxBody;
use http_body_util::{Empty, Full};
use hyper::body::Bytes;
use hyper::{Method, body::Buf};
use hyper_util::client::legacy::{Builder, Client, connect::HttpConnector};
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};
use tokio::time::timeout;

pub use errors::ConsulError;
use errors::Result;
/// Consul Distributed lock
mod lock;
/// General utils tools
mod utils;
#[cfg(feature = "metrics")]
use http::StatusCode;

#[cfg(feature = "trace")]
use opentelemetry::global;
#[cfg(feature = "trace")]
use opentelemetry::global::BoxedTracer;
#[cfg(feature = "trace")]
use opentelemetry::trace::Span;
#[cfg(feature = "trace")]
use opentelemetry::trace::Status;

pub use lock::*;
#[cfg(feature = "metrics")]
pub use metrics::MetricInfo;
pub use metrics::{Function, HttpMethod};
pub use types::*;

/// Consul errors and Result type
mod errors;
#[cfg(feature = "trace")]
mod hyper_wrapper;
/// Types exposed for metrics on the consuming application without taking a dependency on a metrics library or a specific implementation.
mod metrics;
/// The strongly typed data structures representing canonical consul objects.
pub mod types;

/// The config necessary to create a new consul client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The address of the consul server. This must include the protocol to connect over eg. http or https.
    pub address: String,
    /// The consul secret token to make authenticated requests to the consul server.
    pub token: Option<String>,

    /// The hyper builder for the internal http client.
    #[serde(skip)]
    #[serde(default = "default_builder")]
    pub hyper_builder: hyper_util::client::legacy::Builder,
}

fn default_builder() -> Builder {
    // https://github.com/hyperium/hyper/issues/2312
    Builder::new(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_millis(0))
        .pool_max_idle_per_host(0)
        .to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            address: String::default(),
            token: None,
            hyper_builder: default_builder(),
        }
    }
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
            hyper_builder: default_builder(),
        }
    }
}

/// Type alias for a Hyper client using a hyper_rusttls HttpsConnector
pub type HttpsClient =
    Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>;

#[derive(Debug)]
/// This struct defines the consul client and allows access to the consul api via method syntax.
pub struct Consul {
    https_client: HttpsClient,
    config: Config,
    #[cfg(feature = "trace")]
    tracer: BoxedTracer,
    #[cfg(feature = "metrics")]
    metrics_tx: tokio::sync::mpsc::UnboundedSender<MetricInfo>,
    #[cfg(feature = "metrics")]
    metrics_rx: Option<tokio::sync::mpsc::UnboundedReceiver<MetricInfo>>,
}

fn https_connector() -> hyper_rustls::HttpsConnector<HttpConnector> {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build()
}

/// This struct defines a builder for the consul client
/// This allows a Consul client to be built using a custom HTTPS client
pub struct ConsulBuilder {
    config: Config,
    https_client: Option<HttpsClient>,
}

impl ConsulBuilder {
    /// Creates a new instance of [`ConsulBuilder`](consul::ConsulBuilder)
    pub fn new(config: Config) -> Self {
        Self {
            config,
            https_client: None,
        }
    }

    /// Sets the HTTPS client to be used when building an instance of [`Consul`](consul::Consul).
    /// #Arguments:
    /// - [HttpsClient](consul::HttpsClient)
    pub fn with_https_client(mut self, https_client: HttpsClient) -> Self {
        self.https_client = Some(https_client);
        self
    }

    /// Creates a new instance of [`Consul`](consul::Consul) using the supplied HTTPS client (if any).
    pub fn build(self) -> Consul {
        let https_client = self.https_client.unwrap_or_else(|| {
            let https = https_connector();
            self.config
                .hyper_builder
                .build::<_, BoxBody<Bytes, Infallible>>(https)
        });

        Consul::new_with_client(self.config, https_client)
    }
}

impl Consul {
    /// Creates a new instance of [`Consul`](consul::Consul).
    /// This is the entry point for this crate.
    /// #Arguments:
    /// - [Config](consul::Config)
    pub fn new(config: Config) -> Self {
        ConsulBuilder::new(config).build()
    }

    /// Creates a new instance of [`Consul`](consul::Consul) using the supplied HTTPS client.
    /// This is the entry point for this crate.
    /// #Arguments:
    /// - [Config](consul::Config)
    /// - [HttpsClient](consul::HttpsClient)
    pub fn new_with_client(config: Config, https_client: HttpsClient) -> Self {
        #[cfg(feature = "metrics")]
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<MetricInfo>();
        Consul {
            https_client,
            config,
            #[cfg(feature = "trace")]
            tracer: global::tracer("consul"),
            #[cfg(feature = "metrics")]
            metrics_tx: tx,
            #[cfg(feature = "metrics")]
            metrics_rx: Some(rx),
        }
    }

    #[cfg(feature = "metrics")]
    /// Returns the metrics receiver for the consul client.
    pub fn metrics_receiver(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<MetricInfo>> {
        self.metrics_rx.take()
    }

    /// Reads a key from Consul's KV store. See the [consul docs](https://www.consul.io/api-docs/kv#read-key) for more information.
    /// # Arguments:
    /// - request - the [ReadKeyRequest](consul::types::ReadKeyRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn read_key(
        &self,
        request: ReadKeyRequest<'_>,
    ) -> Result<ResponseMeta<Vec<ReadKeyResponse>>> {
        let req = self.build_read_key_req(request);
        let (response_body, index) = self
            .execute_request(
                req,
                BoxBody::new(http_body_util::Empty::<Bytes>::new()),
                None,
                Function::ReadKey,
            )
            .await?;
        Ok(ResponseMeta {
            response: serde_json::from_reader::<_, Vec<ReadKeyResponse>>(response_body.reader())
                .map_err(ConsulError::ResponseDeserializationFailed)?
                .into_iter()
                .map(|mut r| {
                    r.value = match r.value {
                        Some(val) => Some(
                            std::str::from_utf8(
                                &base64::engine::general_purpose::STANDARD.decode(val)?,
                            )?
                            .to_string(),
                        ),
                        None => None,
                    };

                    Ok(r)
                })
                .collect::<Result<Vec<_>>>()?,
            index,
        })
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
        let (response_body, index) = self
            .execute_request(
                req,
                BoxBody::new(Full::<Bytes>::new(Bytes::from(value))),
                None,
                Function::CreateOrUpdateKey,
            )
            .await?;
        Ok((
            serde_json::from_reader(response_body.reader())
                .map_err(ConsulError::ResponseDeserializationFailed)?,
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
        #[cfg(feature = "metrics")]
        let mut metrics_info_wrapper = MetricInfoWrapper::new(
            HttpMethod::Put,
            Function::CreateOrUpdateKey,
            None,
            self.metrics_tx.clone(),
        );
        let result = ureq::put(&url)
            .header(
                "X-Consul-Token",
                &self.config.token.clone().unwrap_or_default(),
            )
            .send(&value);

        let response = result.map_err(|e| match e {
            ureq::Error::StatusCode(code) => {
                let code = hyper::StatusCode::from_u16(code).unwrap_or_default();
                #[cfg(feature = "metrics")]
                {
                    metrics_info_wrapper.set_status(code);
                    metrics_info_wrapper.emit_metrics();
                }
                ConsulError::UnexpectedResponseCode(code, None)
            }
            e => ConsulError::UReqError(e),
        })?;
        let status = response.status();
        if status == 200 {
            let val = response
                .into_body()
                .read_to_string()
                .map_err(ConsulError::UReqError)?;
            let response: bool = std::str::FromStr::from_str(val.trim())?;
            #[cfg(feature = "metrics")]
            {
                metrics_info_wrapper.set_status(StatusCode::OK);
                metrics_info_wrapper.emit_metrics();
            }
            return Ok(response);
        }

        let body = response
            .into_body()
            .read_to_string()
            .map_err(ConsulError::UReqError)?;
        Err(ConsulError::SyncUnexpectedResponseCode(
            hyper::StatusCode::as_u16(&status),
            body,
        ))
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

        url = utils::add_namespace_and_datacenter(url, request.namespace, request.datacenter);
        req = req.uri(url);
        let (response_body, _index) = self
            .execute_request(
                req,
                BoxBody::new(Empty::<Bytes>::new()),
                None,
                Function::DeleteKey,
            )
            .await?;
        serde_json::from_reader(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
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
            BoxBody::new(Full::<Bytes>::new(Bytes::from(payload.into_bytes()))),
            Some(Duration::from_secs(5)),
            Function::RegisterEntity,
        )
        .await?;
        Ok(())
    }

    /// Removes entries from consul's global catalog.
    /// See https://www.consul.io/api-docs/catalog#deregister-entity for more information.
    /// # Arguments:
    /// - payload: The [`DeregisterEntityPayload`](DeregisterEntityPayload) to provide the register entity API.
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn deregister_entity(&self, payload: &DeregisterEntityPayload) -> Result<()> {
        let uri = format!("{}/v1/catalog/deregister", self.config.address);
        let request = hyper::Request::builder().method(Method::PUT).uri(uri);
        let payload = serde_json::to_string(payload).map_err(ConsulError::InvalidRequest)?;
        self.execute_request(
            request,
            BoxBody::new(Full::<Bytes>::new(Bytes::from(payload.into_bytes()))),
            Some(Duration::from_secs(5)),
            Function::DeregisterEntity,
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
        utils::add_query_option_params(&mut uri, &query_opts, '?');

        let request = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri.clone());
        let (response_body, index) = self
            .execute_request(
                request,
                BoxBody::new(Empty::<Bytes>::new()),
                query_opts.timeout,
                Function::GetAllRegisteredServices,
            )
            .await?;
        let service_tags_by_name =
            serde_json::from_reader::<_, HashMap<String, Vec<String>>>(response_body.reader())
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
        let (response_body, index) = self
            .execute_request(
                req,
                BoxBody::new(Empty::<Bytes>::new()),
                query_opts.timeout,
                Function::GetServiceNodes,
            )
            .await?;
        let response =
            serde_json::from_reader::<_, GetServiceNodesResponse>(response_body.reader())
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

    /// Returns the nodes registered in the Consul catalog.
    /// # Arguments:
    /// - request - the [GetNodesRequest](consul::types::GetNodesRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
    pub async fn get_nodes(
        &self,
        request: GetNodesRequest<'_>,
        query_opts: Option<QueryOptions>,
    ) -> Result<ResponseMeta<GetNodesResponse>> {
        let query_opts = query_opts.unwrap_or_default();
        let req = self.build_get_nodes_req(request, &query_opts);
        let (response_body, index) = self
            .execute_request(
                req,
                BoxBody::new(Empty::<Bytes>::new()),
                query_opts.timeout,
                Function::GetNodes,
            )
            .await?;
        let response = serde_json::from_reader::<_, GetNodesResponse>(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)?;
        Ok(ResponseMeta { response, index })
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
                    service_name = &sn.service.service,
                    port = sn.service.port
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
        url = utils::add_namespace_and_datacenter(url, request.namespace, request.datacenter);
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
        url = utils::add_namespace_and_datacenter(url, request.namespace, request.datacenter);
        req = req.uri(url);
        let create_session_json =
            serde_json::to_string(&session_req).map_err(ConsulError::InvalidRequest)?;
        let (response_body, _index) = self
            .execute_request(
                req,
                BoxBody::new(Full::<Bytes>::new(Bytes::from(
                    create_session_json.into_bytes(),
                ))),
                None,
                Function::GetSession,
            )
            .await?;
        serde_json::from_reader(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
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
        utils::add_query_option_params(&mut url, query_opts, '&');
        req.uri(url)
    }

    // We assign to added_query_param for future proofing in case we add more parameters.
    fn build_get_nodes_req(
        &self,
        request: GetNodesRequest<'_>,
        query_opts: &QueryOptions,
    ) -> http::request::Builder {
        let req = hyper::Request::builder().method(Method::GET);
        let mut url = String::new();
        url.push_str(&format!("{}/v1/catalog/nodes", self.config.address));
        let mut added_query_param = false;
        if let Some(near) = request.near {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("near={}", near));
            added_query_param = true;
        }
        if let Some(filter) = request.filter {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("filter={}", filter));
            added_query_param = true;
        }
        if let Some(dc) = &query_opts.datacenter {
            if !dc.is_empty() {
                url = utils::add_query_param_separator(url, added_query_param);
                url.push_str(&format!("dc={}", dc));
            }
        }

        req.uri(url)
    }

    async fn execute_request(
        &self,
        req: http::request::Builder,
        body: BoxBody<Bytes, Infallible>,
        duration: Option<std::time::Duration>,
        _function: Function,
    ) -> Result<(Box<dyn Buf>, u64)> {
        let req = req
            .header(
                "X-Consul-Token",
                self.config.token.clone().unwrap_or_default(),
            )
            .body(body);
        let req = req.map_err(ConsulError::RequestError)?;
        #[cfg(feature = "trace")]
        let mut span = crate::hyper_wrapper::span_for_request(&self.tracer, &req);

        #[cfg(feature = "metrics")]
        let mut metrics_info_wrapper = MetricInfoWrapper::new(
            req.method().clone().into(),
            _function,
            None,
            self.metrics_tx.clone(),
        );
        let future = self.https_client.request(req);
        let response = if let Some(dur) = duration {
            match timeout(dur, future).await {
                Ok(resp) => resp.map_err(ConsulError::ResponseError),
                Err(_) => {
                    #[cfg(feature = "metrics")]
                    {
                        metrics_info_wrapper.set_status(StatusCode::REQUEST_TIMEOUT);
                        metrics_info_wrapper.emit_metrics();
                    }
                    Err(ConsulError::TimeoutExceeded(dur))
                }
            }
        } else {
            future.await.map_err(ConsulError::ResponseError)
        };

        let response = response.inspect_err(|_| {
            #[cfg(feature = "metrics")]
            metrics_info_wrapper.emit_metrics();
        })?;

        #[cfg(feature = "trace")]
        crate::hyper_wrapper::annotate_span_for_response(&mut span, &response);

        let status = response.status();
        if status != hyper::StatusCode::OK {
            #[cfg(feature = "metrics")]
            {
                metrics_info_wrapper.set_status(status);
                metrics_info_wrapper.emit_metrics();
            }

            let mut response_body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| ConsulError::UnexpectedResponseCode(status, Some(e.to_string())))?
                .aggregate();
            let bytes = response_body.copy_to_bytes(response_body.remaining());
            let resp = std::str::from_utf8(&bytes)
                .map_err(|e| ConsulError::UnexpectedResponseCode(status, Some(e.to_string())))?;
            return Err(ConsulError::UnexpectedResponseCode(
                status,
                Some(resp.to_string()),
            ));
        }
        let index = match response.headers().get("x-consul-index") {
            Some(header) => header.to_str().unwrap_or("0").parse::<u64>().unwrap_or(0),
            None => 0,
        };

        match response.into_body().collect().await.map(|b| b.aggregate()) {
            Ok(body) => Ok((Box::new(body), index)),
            Err(e) => {
                #[cfg(feature = "trace")]
                span.set_status(Status::error(e.to_string()));
                Err(ConsulError::InvalidResponse(e))
            }
        }
    }

    fn build_create_or_update_url(&self, request: CreateOrUpdateKeyRequest<'_>) -> String {
        let mut url = String::new();
        url.push_str(&format!("{}/v1/kv/{}", self.config.address, request.key));
        let mut added_query_param = false;
        if request.flags != 0 {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("flags={}", request.flags));
            added_query_param = true;
        }
        if !request.acquire.is_empty() {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("acquire={}", request.acquire));
            added_query_param = true;
        }
        if !request.release.is_empty() {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("release={}", request.release));
            added_query_param = true;
        }
        if let Some(cas_idx) = request.check_and_set {
            url = utils::add_query_param_separator(url, added_query_param);
            url.push_str(&format!("cas={}", cas_idx));
        }

        utils::add_namespace_and_datacenter(url, request.namespace, request.datacenter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            tags: vec!["foo".to_string(), "bar=baz".to_string()],
        };

        let empty_service = Service {
            id: "".to_string(),
            service: "".to_string(),
            address: "".to_string(),
            port: 32,
            tags: vec![],
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
}
