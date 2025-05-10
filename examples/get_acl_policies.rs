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
    let acl_policies = consul.list_acl_policies().await.unwrap();

    println!("{} Policies found", acl_policies.len());
    for (i, policy) in acl_policies.iter().enumerate() {
        println!(
            "id #{}\n\
        ├─ ID: {}\n\
        ├─ Name: {}\n\
        └─ Description: {}",
            i + 1,
            policy.id,
            policy.name,
            policy.description,
        );
        println!("\n=========\n")
    }
}
