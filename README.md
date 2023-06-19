# rs-consul

[![Crates.io: rs-consul](https://img.shields.io/crates/v/rs-consul.svg)](https://crates.io/crates/rs-consul)
[![Documentation](https://docs.rs/rs-consul/badge.svg)](https://docs.rs/rs-consul)
[![Main](https://github.com/Roblox/rs-consul/actions/workflows/main.yml/badge.svg)](https://github.com/Roblox/rs-consul/actions/workflows/main.yml)

This crate provides access to a set of strongly typed apis to interact with
consul (<https://www.consul.io/>)

## Installation

Simply include the rs-consul in your Cargo dependencies.

```toml
[dependencies]
rs-consul = "0.1.0"
```

## Development

```bash
cargo build
```

### Tests

#### Local Consul

Start consul locally with a docker image.

```bash
docker-compose up -d
```

#### CI Consul

In CI, we start a service container for the test.

#### Running Tests

```bash
cargo test
```

## Contributions

For contributions, please:

1. Make a pull request
2. Make sure the tests pass
3. Add a bullet to the Changelog

## License

rs-consul is available under the MIT license. See [LICENSE](LICENSE) for details.
