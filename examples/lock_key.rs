use std::time::Duration;

use rs_consul::{Config, Consul, types::*};
use tokio::time::sleep;

#[tokio::main] // Enables async main
async fn main() {
    let consul_config = Config {
        address: "http://localhost:8500".to_string(),
        token: None, // Token is None in developpement mode
        ..Default::default()
    };
    let consul = Consul::new(consul_config);

    let key = "key-locked";
    let key_value = "\"locked_value\"";
    // Lock request
    let req = LockRequest {
        key,
        behavior: LockExpirationBehavior::Release,
        lock_delay: std::time::Duration::from_secs(1),
        ..Default::default()
    };
    let _res = consul.get_lock(req, key_value.as_bytes()).await.unwrap();
    println!("Lock aquired for `locked-key`");
    sleep(Duration::from_secs(5)).await; // Aquire the lock for 5 seconds
    println!("Lock released");
}
