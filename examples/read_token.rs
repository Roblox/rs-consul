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
    // this is equivalent to consul/token/self
    let result = consul
        .read_acl_token("dd72f645-4dc2-5b25-9a0b-70134ab5d1dc".to_owned())
        .await
        .unwrap();
    println!(
        "Token:
            accessor_id: {}
            secret_id: {}
            description: {}
            policies: {:#?}
            hash: {}
            local: {}
            create_time:{}
        ",
        result.accessor_id,
        result.secret_id,
        result.description,
        result.policies,
        result.local,
        result.create_time,
        result.hash,
    );
}
