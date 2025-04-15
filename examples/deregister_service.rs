use rs_consul::{types::*, Config, Consul};

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

    let payload = DeregisterEntityPayload {
        Node: Some(node_id.to_string()),
        Datacenter: None,
        CheckID: None,
        ServiceID: Some(service_name.to_string()),
        Namespace: None,
    };
    consul.deregister_entity(&payload).await.unwrap();
}
