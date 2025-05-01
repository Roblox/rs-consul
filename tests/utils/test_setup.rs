use rs_consul::*;
type Result<T> = std::result::Result<T, rs_consul::ConsulError>;

pub(crate) fn get_client() -> Consul {
    let conf: Config = Config::from_env();
    Consul::new(conf)
}
pub(crate) async fn register_entity(consul: &Consul, service_name: &String, node_id: &str) {
    let ResponseMeta {
        response: service_names_before_register,
        ..
    } = consul
        .get_all_registered_service_names(None)
        .await
        .expect("expected get_registered_service_names request to succeed");
    assert!(!service_names_before_register.contains(service_name));

    let payload = RegisterEntityPayload {
        ID: None,
        Node: node_id.to_string(),
        Address: "127.0.0.1".to_string(),
        Datacenter: None,
        TaggedAddresses: Default::default(),
        NodeMeta: Default::default(),
        Service: Some(RegisterEntityService {
            ID: None,
            Service: service_name.clone(),
            Tags: vec![],
            TaggedAddresses: Default::default(),
            Meta: Default::default(),
            Port: Some(42424),
            Namespace: None,
        }),
        Check: None,
        SkipNodeUpdate: None,
    };
    consul
        .register_entity(&payload)
        .await
        .expect("expected register_entity request to succeed");
}

pub(crate) async fn is_registered(consul: &Consul, service_name: &String) -> bool {
    let ResponseMeta {
        response: service_names_after_register,
        ..
    } = consul
        .get_all_registered_service_names(None)
        .await
        .expect("expected get_registered_service_names request to succeed");
    service_names_after_register.contains(service_name)
}

pub(crate) async fn create_or_update_key_value(
    consul: &Consul,
    key: &str,
    value: &str,
) -> Result<(bool, u64)> {
    let req = CreateOrUpdateKeyRequest {
        key,
        ..Default::default()
    };
    consul
        .create_or_update_key(req, value.as_bytes().to_vec())
        .await
}

pub(crate) async fn read_key(
    consul: &Consul,
    key: &str,
) -> Result<ResponseMeta<Vec<ReadKeyResponse>>> {
    let req = ReadKeyRequest {
        key,
        ..Default::default()
    };
    consul.read_key(req).await
}

pub(crate) async fn delete_key(consul: &Consul, key: &str) -> Result<bool> {
    let req = DeleteKeyRequest {
        key,
        ..Default::default()
    };
    consul.delete_key(req).await
}

pub(crate) fn assert_expected_result_with_index(res: Result<(bool, u64)>) {
    assert!(res.is_ok());
    let (result, _index) = res.unwrap();
    assert!(result);
}

pub(crate) fn assert_expected_result(res: Result<bool>) {
    assert!(res.is_ok());
    assert!(res.unwrap());
}

pub(crate) async fn get_single_key_value_with_index(
    consul: &Consul,
    key: &str,
) -> (Option<String>, i64) {
    let res = read_key(consul, key).await.expect("failed to read key");
    let r = res.response.into_iter().next().unwrap();
    (r.value, res.index as i64)
}

pub(crate) fn verify_single_value_matches(
    res: Result<ResponseMeta<Vec<ReadKeyResponse>>>,
    value: &str,
) {
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap()
            .response
            .into_iter()
            .next()
            .unwrap()
            .value
            .unwrap(),
        value
    )
}
