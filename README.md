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
rs-consul = "0.9.0"
```
## Usage
Check [/examples](/examples) for more detailed usage
### Initialize the client
#### Environment Configuration (Recommended)
The client can be configured automatically using environment variables:
```rust
use rs_consul::{types::*, Config, Consul};

let consul_config = Config::from_env();
let consul = Consul::new(consul_config);
```
#### Manual Configuration
Alternatively, you can configure the client manually:
```rust
let consul_config = Config {
    address: "http://localhost:8500".to_string(), 
    token: None, // No token required in development mode
    ..Default::default() // Uses default values for other settings
};

let consul = Consul::new(consul_config);
```
### Register a Service
```rust
    let node_id = "root-node"; //node name
    let service_name = "new-service-1"; //service name

    let payload = RegisterEntityPayload {
        ID: None,
        Node: node_id.to_string(),
        Address: "127.0.0.1".to_string(), //server address
        Datacenter: None,
        TaggedAddresses: Default::default(),
        NodeMeta: Default::default(),
        Service: Some(RegisterEntityService {
            ID: None,
            Service: service_name.to_string(),
            Tags: vec![],
            TaggedAddresses: Default::default(),
            Meta: Default::default(),
            Port: Some(42424), 
            Namespace: None,
        }),
        Check: None,
        SkipNodeUpdate: None,
    };

    consul.register_entity(&payload).await.unwrap();
```
### Deregister a service
```rust
    let node_id = "root-node";
    let service_name = "new-service-1";

    let payload = DeregisterEntityPayload {
        Node: Some(node_id.to_string()),
        Datacenter: None,
        CheckID: None,
        ServiceID: Some(service_name.to_string()),
        Namespace: None,
    };
    consul.deregister_entity(&payload).await.unwrap();
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
