use quick_error::quick_error;
pub(crate) type Result<T> = std::result::Result<T, ConsulError>;
quick_error! {
    /// The error type returned from all calls into this this crate.
    #[derive(Debug)]
    pub enum ConsulError {
        /// The request was invalid and could not be serialized to valid json.
        InvalidRequest(err: serde_json::error::Error) {}
        /// The request was invalid and could not be converted into a proper http request.
        RequestError(err: http::Error) {}
        /// The consul server response could not be converted into a proper http response.
        ResponseError(err: hyper_util::client::legacy::Error) {}
        /// The consul server response was invalid.
        InvalidResponse(err: hyper::Error) {}
        /// The consul server response could not be deserialized from json.
        ResponseDeserializationFailed(err: serde_json::error::Error) {}
        /// The consul server response could not be deserialized from bytes.
        ResponseStringDeserializationFailed(err: std::str::Utf8Error) {}
        /// The consul server response was something other than 200. The status code and the body of the response are included.
        UnexpectedResponseCode(status_code: hyper::http::StatusCode, body: Option<String>) {}
        /// The consul server refused a lock acquisition (usually because some other session has a lock).
        LockAcquisitionFailure(err: u64) {}
        /// Consul returned invalid UTF8.
        InvalidUtf8(err: std::str::Utf8Error) {
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
        /// An error from ureq occured.
        UReqError(err: ureq::Error) {
            display("UReq error: {}", err)
        }
    }
}
