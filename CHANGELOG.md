# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.8.2 - 2024-11-22

- Fix metrics being emitted more than once.

## 0.8.1 - 2024-11-20

### Changed

- `opentelemetry` upgraded to version `0.27` from `0.24`.
- Removed `prometheus` dependency in the `metrics` feature, replacing it with a `metrics_receiver` in a metrics library agnostic fashion.

## 0.8.0 - 2024-11-20

- YANKED because `Consul` was no longer `Sync`.

## 0.7.0 - 2024-06-25

### Changed

- `opentelemetry` updated to version `0.24` from `0.22`.
- `http` updated to version `1.0` from `0.2`.
- `hyper` updated to version `1.0` from `0.14`.
- `hyper-rustls` updated to version `0.27` from `0.24`.
- `get_service_nodes` now supports tags thanks to @gautamg795
- `read_key` now also returns the index thanks to @badalex
- Allow configuring `Consul` with a custom http client thanks to @LeonHartley
- Removed `rustls-native-roots` feature and now defaults to `rustls-webpki-roots` (which has been removed). This addresses the bug that features were not additive.

## 0.6.0 - 2024-04-01

### Changed

- `opentelemetry` updated to version `0.22` from `0.21`.
- `base64` updated to version `0.22` from `0.21`.

## 0.5.0 - 2023-11-20

### Added

- Added support for `deregister-entity`.

### Changed

- `opentelemetry` updated to version `0.21` from `0.20`.

### Changed

- `opentelemetry` updated to version `0.20` from `0.19`.

## 0.4.0 - 2023-08-25

### Changed

- `opentelemetry` updated to version `0.20` from `0.19`.

## 0.3.0 - 2023-06-19

### Added

- `rustls-native` (default), and `rustls-webpki` features to allow usage of rustls for the https client.
- `hyper_builder` field was added to `Config` in order to allow specifying additional hyper options.

### Changed

- Fixed `create_or_update_key` to properly handle a `check_and_set` value of 0 (instead of omitting it when set to 0). As a result, the type has changed from `i64` to `Option<i64>` in `CreateOrUpdateKeyRequest`.
- `trace` feature must be specified to enable opentelemetry/tracing support.
- `opentelemetry` updated to version `0.19` from `0.15`.
- `base64` updated to version `0.21` from `0.13`.
- `rustls` updated to `0.24` from `0.22`.
- `smart_default` updated to `0.7` from `0.6`.
- `ureq` updated to `2` from `1.5.4`.

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
