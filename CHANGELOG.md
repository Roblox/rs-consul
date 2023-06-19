# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `rustls-native` (default), and `rustls-webpki` features to allow usage of rustls for the https client.

### Changed

- Fixed `create_or_update_key` to properly handle a `check_and_set` value of 0 (instead of omitting it when set to 0). As a result, the type has changed from `i64` to `Option<i64>` in `CreateOrUpdateKeyRequest`.
- `opentelemetry` feature must be specified to enable opentelemetry/tracing support.
- `opentelemetry` updated to version `0.19` from `0.15`.
- `base64` updated to version `0.21` from `0.13`.
- `rustls` updated to `0.24` from `0.22`.
- `smart_default` updated to `0.7` from `0.6`.
- `ureq` updated to `2` from `1.5.4`.

### Deprecated

### Removed

### Fixed

### Security

## 0.2.3 - 2022-08-24

- Add `datacenter` field to `Node`

## 0.2.2 - 2022-06-08

- Add metrics to calls to Consul for increased visibility

## 0.2.1 - 2022-03-08

- Fix `wait` serialization for Consul APIs that were missing unit suffix

## 0.2.0 - 2021-07-20

### Added

- register_entity method and RegisterEntityPayload, and associated, structs
- get_all_registered_service_names method
- introduced QueryOptions struct to encapsulate common query options
- introduced ResponseMeta to encapsulate the index returned

### Changed

- get_service_nodes and get_service_addresses_and_ports methods now take QueryOptions as a new parameter
- get_service_nodes return a ReponseMeta
- GetServiceNodesRequest was modified to remove redundant fields

- clippy warnings for some tests

### Security

## 0.1.0 - 2021-06-10

### Added

- Initialized repository
- Added CHANGELOG
- Added CI workflow
- Added README
