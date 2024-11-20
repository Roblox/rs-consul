#[cfg(feature = "metrics")]
use http::StatusCode;
#[cfg(feature = "metrics")]
use std::time::Duration;

/// A struct to hold information about a calls to consul for metrics.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone, Copy)]
pub struct MetricInfo {
    /// The HTTP method used in the call.
    pub method: HttpMethod,
    /// The function called in the consul client.
    pub function: Function,
    /// The status code returned by the call if any.
    pub status: Option<StatusCode>,
    /// The duration of the call.
    pub duration: Option<Duration>,
}

#[cfg(feature = "metrics")]
impl MetricInfo {
    fn new(method: HttpMethod, function: Function, status: Option<StatusCode>) -> Self {
        Self {
            method,
            function,
            status,
            duration: None,
        }
    }

    /// Get the labels for the metric as an array of `&str`.
    pub fn labels(&self) -> [&str; 3] {
        if let Some(status) = self.status.and_then(|o| o.canonical_reason()) {
            [self.method.as_str(), self.function.as_str(), status]
        } else {
            [self.method.as_str(), self.function.as_str(), "unknown"]
        }
    }
}

#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub(crate) struct MetricInfoWrapper {
    metrics: MetricInfo,
    sender: Option<std::sync::mpsc::Sender<MetricInfo>>,
    start: std::time::Instant,
}

#[cfg(feature = "metrics")]
impl MetricInfoWrapper {
    pub fn new(
        method: HttpMethod,
        function: Function,
        status: Option<StatusCode>,
        sender: std::sync::mpsc::Sender<MetricInfo>,
    ) -> Self {
        Self {
            metrics: MetricInfo::new(method, function, status),
            sender: Some(sender),
            start: std::time::Instant::now(),
        }
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.metrics.status = Some(status);
    }
}

#[cfg(feature = "metrics")]
impl Drop for MetricInfoWrapper {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let mut metrics = self.metrics;
            metrics.duration = Some(self.start.elapsed());
            let _ = sender.send(self.metrics);
        }
    }
}

/// The HTTP methods supported by the consul API.
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    /// The OPTIONS method.
    Options,
    /// The GET method.
    Get,
    /// The POST method.
    Post,
    /// The PUT method.
    Put,
    /// The DELETE method.
    Delete,
    /// The HEAD method.
    Head,
    /// The TRACE method.
    Trace,
    /// The CONNECT method.
    Connect,
    /// The PATCH method.
    Patch,
    /// Extensions to the HTTP methods.
    Extensions,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Options => "options",
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Delete => "delete",
            HttpMethod::Head => "head",
            HttpMethod::Trace => "trace",
            HttpMethod::Connect => "connect",
            HttpMethod::Patch => "patch",
            HttpMethod::Extensions => "extensions",
        }
    }
}

impl From<http::Method> for HttpMethod {
    fn from(method: http::Method) -> Self {
        match method {
            http::Method::OPTIONS => HttpMethod::Options,
            http::Method::GET => HttpMethod::Get,
            http::Method::POST => HttpMethod::Post,
            http::Method::PUT => HttpMethod::Put,
            http::Method::DELETE => HttpMethod::Delete,
            http::Method::HEAD => HttpMethod::Head,
            http::Method::TRACE => HttpMethod::Trace,
            http::Method::CONNECT => HttpMethod::Connect,
            http::Method::PATCH => HttpMethod::Patch,
            _ => HttpMethod::Extensions,
        }
    }
}

/// The functions supported by the consul client.
#[derive(Debug, Clone, Copy)]
pub enum Function {
    /// The read_key function.
    ReadKey,
    /// The create_or_update_key function.
    CreateOrUpdateKey,
    /// The delete_key function.
    DeleteKey,
    /// The register_entity function.
    RegisterEntity,
    /// The deregister_entity function.
    DeregisterEntity,
    /// The get_service_nodes function.
    GetServiceNodes,
    /// The get_all_registered_services function.
    GetAllRegisteredServices,
    /// The get_session function.
    GetSession,
}

impl Function {
    /// Get the function as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Function::ReadKey => "read_key",
            Function::CreateOrUpdateKey => "create_or_update_key",
            Function::DeleteKey => "delete_key",
            Function::RegisterEntity => "register_entity",
            Function::DeregisterEntity => "deregister_entity",
            Function::GetServiceNodes => "get_service_nodes",
            Function::GetAllRegisteredServices => "get_all_registered_services",
            Function::GetSession => "get_session",
        }
    }
}
