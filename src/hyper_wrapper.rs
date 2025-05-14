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
use hyper::Version;
use opentelemetry::{
    KeyValue,
    global::{BoxedSpan, BoxedTracer},
    trace::{Span, Status, Tracer},
};

/// Create an OpenTelemetry Span for the given HTTP request, according to the OpenTelemetry
/// semantic conventions for HTTP traffic.
/// See https://github.com/open-telemetry/opentelemetry-specification/blob/v0.5.0/specification/trace/semantic_conventions/http.md
pub fn span_for_request<T>(tracer: &BoxedTracer, req: &hyper::Request<T>) -> BoxedSpan {
    let mut span = tracer.start(format!(
        "HTTP {} {}",
        req.method(),
        req.uri().host().unwrap_or("<unknown>")
    ));
    span.set_attribute(KeyValue::new("span.kind", "client"));
    span.set_attribute(KeyValue::new("http.method", req.method().to_string()));
    span.set_attribute(KeyValue::new("http.url", req.uri().to_string()));
    if let Some(path_and_query) = req.uri().path_and_query() {
        span.set_attribute(KeyValue::new("http.target", path_and_query.to_string()));
    }
    if let Some(host) = req.uri().host() {
        span.set_attribute(KeyValue::new("http.host", host.to_owned()));
    }
    if let Some(scheme) = req.uri().scheme_str() {
        span.set_attribute(KeyValue::new("http.scheme", scheme.to_string()));
    }

    // Using strings from https://github.com/open-telemetry/opentelemetry-specification/blob/v0.5.0/specification/trace/semantic_conventions/http.md#common-attributes
    let serialized_version = match req.version() {
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "unknown",
    };
    span.set_attribute(KeyValue::new("http.flavor", serialized_version));

    // TODO: Emit UserAgent
    // TODO: Expose non-HTTP specific attributes https://github.com/open-telemetry/opentelemetry-specification/blob/v0.5.0/specification/trace/semantic_conventions/span-general.md#general-network-connection-attributes

    span
}

/// Annotate a span that has previously been created given the HTTP response.
/// The passed in span must have been created for the HTTP request for which we got the response.
pub fn annotate_span_for_response<T>(span: &mut BoxedSpan, response: &hyper::Response<T>) {
    let status = response.status();

    span.set_attribute(KeyValue::new(
        "http.status_code",
        status.as_u16().to_string(),
    ));
    if let Some(canonical_reason) = status.canonical_reason() {
        span.set_attribute(KeyValue::new(
            "http.status_text",
            canonical_reason.to_owned(),
        ));
    }

    // Mark server errors (5xx) and client errors (4xx) as span errors per OpenTelemetry specs
    // See: https://opentelemetry.io/docs/specs/semconv/http/http-spans/#status
    if status.is_client_error() || status.is_server_error() {
        span.set_status(Status::error(status.as_str().to_owned()));
    }
}
