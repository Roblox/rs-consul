use http::Method;
use http_body_util::{Full, combinators::BoxBody};
use hyper::body::Buf;
use hyper::body::Bytes;

use crate::{
    Consul, CreateOrUpdateKeyRequest, CreateSessionRequest, LockRequest, LockWatchRequest,
    ReadKeyRequest, ReadKeyResponse, ResponseMeta, Result, SessionResponse, errors::ConsulError,
    utils,
};

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
impl Consul {
    /// Obtains a session ID
    /// # Arguments:
    /// - request - the [LockRequest](consul::types::LockRequest)
    /// # Errors:
    /// [ConsulError](consul::ConsulError) describes all possible errors returned by this api.
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
                crate::Function::GetSession,
            )
            .await?;
        serde_json::from_reader(response_body.reader())
            .map_err(ConsulError::ResponseDeserializationFailed)
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
                    BoxBody::new(http_body_util::Empty::<Bytes>::new()),
                    None,
                    crate::Function::ReadKey,
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
    pub async fn watch_lock(
        &self,
        request: LockWatchRequest<'_>,
    ) -> Result<ResponseMeta<Vec<ReadKeyResponse>>> {
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
}
