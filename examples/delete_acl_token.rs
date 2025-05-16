use rs_consul::{Config, Consul};

#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: Some(String::from("8fc9e787-674f-0709-cfd5-bfdabd73a70d")), // use bootstraped
        // token (with write perm)
        ..Default::default()
    };
    let consul = Consul::new(consul_config);
    let _res = consul
        .delete_acl_token("58df5025-134c-8999-6bc3-992fe268a39e".to_string())
        .await
        .unwrap();

    println!("Token deleted successfully");
}
