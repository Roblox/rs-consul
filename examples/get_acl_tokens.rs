use rs_consul::{Config, Consul};

#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: None, // Token is None in developpement mode
        ..Default::default()
    };
    let consul = Consul::new(consul_config);
    let acl_tokens = consul.list_acl_tokens().await.unwrap();

    println!("{} Tokens found", acl_tokens.len());
    for (i, token) in acl_tokens.iter().enumerate() {
        println!(
            "Token #{}\n\
        ├─ Accessor ID: {}\n\
        ├─ Secret ID: {}\n\
        ├─ Description: {}\n\
        └─ Policies: {}",
            i + 1,
            token.accessor_id,
            token.secret_id,
            token.description,
            token
                .policies
                .iter()
                .map(|p| format!("{} ({})", p.name, p.id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("=========")
    }
}
