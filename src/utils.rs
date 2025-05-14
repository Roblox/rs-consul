use crate::{QueryOptions, types};

pub(crate) fn add_query_option_params(
    uri: &mut String,
    query_opts: &QueryOptions,
    mut separator: char,
) {
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

pub(crate) fn add_namespace_and_datacenter<'a>(
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

pub(crate) fn add_query_param_separator(mut url: String, already_added: bool) -> String {
    if already_added {
        url.push('&');
    } else {
        url.push('?');
    }

    url
}
