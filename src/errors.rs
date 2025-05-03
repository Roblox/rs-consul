use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, ConsulError>;

/// The error type returned from all calls into this crate.
#[derive(Debug, Error)]
pub enum ConsulError {
    /// The request was invalid and could not be serialized to valid json.
    #[error("Invalid request: {0}")]
    InvalidRequest(#[source] serde_json::Error),

    /// The request was invalid and could not be converted into a proper http request.
    #[error("Request error: {0}")]
    RequestError(#[source] http::Error),

    /// The consul server response could not be converted into a proper http response.
    #[error("Response error: {0}")]
    ResponseError(#[source] hyper_util::client::legacy::Error),

    /// The consul server response was invalid.
    #[error("Invalid response: {0}")]
    InvalidResponse(#[source] hyper::Error),

    /// The consul server response could not be deserialized from json.
    #[error("Response deserialization failed: {0}")]
    ResponseDeserializationFailed(#[source] serde_json::Error),

    /// The consul server response could not be deserialized from bytes.
    #[error("Response string deserialization failed: {0}")]
    ResponseStringDeserializationFailed(#[source] std::str::Utf8Error),

    /// The consul server response was something other than 200.
    #[error("Unexpected response code: {0}, body: {1:?}")]
    UnexpectedResponseCode(hyper::http::StatusCode, Option<String>),

    /// The consul server refused a lock acquisition.
    #[error("Lock acquisition failure: {0}")]
    LockAcquisitionFailure(u64),

    /// Consul returned invalid UTF8.
    #[error("Invalid UTF8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    /// Consul returned invalid base64.
    #[error("Invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// IO error from sync api.
    #[error("Sync IO error: {0}")]
    SyncIoError(#[from] std::io::Error),

    /// Response parse error from sync api.
    #[error("Sync invalid response error: {0}")]
    SyncInvalidResponseError(#[from] std::str::ParseBoolError),

    /// Unexpected response code from sync api.
    #[error("Sync unexpected response code: {0}, body: {1}")]
    SyncUnexpectedResponseCode(u16, String),

    /// Consul request exceeded specified timeout.
    #[error("Consul request exceeded timeout of {0:?}")]
    TimeoutExceeded(std::time::Duration),

    /// Unable to resolve the service's instances in Consul.
    #[error("Unable to resolve service '{0}' to a concrete list of addresses and ports for its instances via consul.")]
    ServiceInstanceResolutionFailed(String),

    /// An error from ureq occurred.
    #[error("UReq error: {0}")]
    UReqError(#[from] ureq::Error),
}
