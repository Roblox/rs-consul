use rs_consul::{Config, Consul, types::*};

#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: None, // Token is None in developpement mode
        ..Default::default()
    };
    let consul = Consul::new(consul_config);

    let node_id = "root-node";
    let service_name = "new-service-1";
    let payload = RegisterEntityPayload {
        ID: None,
        Node: node_id.to_string(),
        Address: "127.0.0.1".to_string(),
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
        Checks: Vec::new(),
        SkipNodeUpdate: None,
    };
    consul.register_entity(&payload).await.unwrap();
}
