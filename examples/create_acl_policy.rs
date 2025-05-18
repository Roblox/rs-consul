use rs_consul::{Config, Consul, CreateACLPolicyRequest};

#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: Some(String::from("8fc9e787-674f-0709-cfd5-bfdabd73a70d")), // use bootstraped
        // token (with write perm)
        ..Default::default()
    };
    let consul = Consul::new(consul_config);
    let policy_payload = CreateACLPolicyRequest {
        name: "dev-policy-test-1".to_owned(),
        description: Some("this is not a test policy".to_owned()),
        rules: Some("".to_owned()),
    };
    consul.create_acl_policy(&policy_payload).await.unwrap();
}
