//
// curl --request PUT \
//   --url http://localhost:8500/v1/acl/token \
//   --header "X-Consul-Token: 8fc9e787-674f-0709-cfd5-bfdabd73a70d" \
//   --header "Content-Type: application/json" \
//   --data '{
//     "Description": "Minimal token for read-only access",
//     "Policies": [
//       {
//         "Name": "dev-policy-test-1"
//       }
//     ]
//   }'
//

use rs_consul::{Config, Consul, CreateACLTokenPayload};
#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: Some(String::from("8fc9e787-674f-0709-cfd5-bfdabd73a70d")), // use bootstraped
        // token (with write perm)
        ..Default::default()
    };
    let consul = Consul::new(consul_config);
    let token_payload = CreateACLTokenPayload {
        description: Some("Test token".to_owned()),
        ..Default::default()
    };
    let result = consul.create_acl_token(&token_payload).await.unwrap();
    println!(
        "
Token created successfully:
    accessor_id: {}
    secret_id: {}
    description: {}
    policies: {:#?}
    local: {}
    create_time:{}
    hash: {}
",
        result.accessor_id.unwrap_or_default(),
        result.secret_id.unwrap_or_default(),
        result.description.unwrap_or_default(),
        result.policies.unwrap_or_default(),
        result.local,
        result.create_time.unwrap_or_default(),
        result.hash.unwrap_or_default(),
    );
}
