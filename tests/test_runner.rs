use rs_consul::*;
use std::collections::HashMap;

#[path = "utils/test_setup.rs"]
mod test_setup;
use test_setup::*;

pub use types::*;

#[cfg(feature = "acl")]
mod acl_tests {
    use super::*;
    #[tokio::test(flavor = "multi_thread")]
    async fn test_acl_retrieve_tokens() {
        let consul = get_privileged_client();
        let result = consul.get_acl_tokens().await.unwrap();

        // test against the initial managment token hardcoded in config.hcl
        assert!(result
            .iter()
            .any(|token| token.secret_id == "8fc9e787-674f-0709-cfd5-bfdabd73a70d"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_acl_create_token() {
        let consul = get_privileged_client();

        let token_payload = CreateACLTokenPayload {
            description: Some("Test token".to_owned()),
            secret_id: Some("00000000-0000-1111-1111-222222222223".to_owned()),
            ..Default::default()
        };
        let result = consul.create_acl_token(&token_payload).await.unwrap();

        assert!(result.secret_id == "00000000-0000-1111-1111-222222222223");
        assert!(result.description == "Test token");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_read_token() {
        let consul = get_privileged_client();

        // create and token with a specigic accessor_id for testing
        let token_payload = CreateACLTokenPayload {
            description: Some("Token created in acl_tests::test_read_token".to_owned()),
            secret_id: Some("00000000-9494-1111-1111-222222222229".to_owned()),
            accessor_id: Some("8d5faa9a-ec33-4514-b0c8-52ea5346d814".to_owned()),
            ..Default::default()
        };
        let _ = consul.create_acl_token(&token_payload).await.unwrap();
        // now read the token by the accessor_id
        let result = consul
            .read_acl_token("8d5faa9a-ec33-4514-b0c8-52ea5346d814".to_owned())
            .await
            .unwrap();

        assert!(result.secret_id == "00000000-9494-1111-1111-222222222229");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_acl_policies() {
        let consul = get_privileged_client();

        let result = consul.get_acl_policies().await.unwrap();

        assert!(result
            .iter()
            .any(|policy| policy.name == "global-management"
                && policy.id == "00000000-0000-0000-0000-000000000001"));
    }
}

#[cfg(feature = "acl")]
mod smoke_acl {

    use super::*;

    #[tokio::test]
    async fn smoke_test_token_policy_retrieval() {
        // get an instance of a privileged acl client
        let consul = get_privileged_client();

        // Create a policy
        let policy_payload = CreateACLPolicyRequest {
            name: "smoke_test_policy_1".to_owned(),
            ..Default::default()
        };
        let policy_result = consul.create_acl_policy(&policy_payload).await.unwrap();

        // Create a token with the newly created policy
        let policy_link_vec = vec![ACLTokenPolicyLink {
            name: Some("smoke_test_policy_1".to_owned()),
            ..Default::default()
        }];
        let token_payload = CreateACLTokenPayload {
            description: Some("Smmoke test".to_owned()),
            secret_id: Some("00000000-9494-1111-1111-222222222229".to_owned()),
            accessor_id: Some("8d5faa9a-1111-1111-b0c8-52ea5346d814".to_owned()),
            policies: Some(policy_link_vec),
            ..Default::default()
        };
        let _ = consul.create_acl_token(&token_payload).await.unwrap();

        // read the newly created token
        let result = consul
            .read_acl_token("8d5faa9a-1111-1111-b0c8-52ea5346d814".to_owned())
            .await
            .unwrap();
        assert!(
            result.policies.unwrap().first().unwrap().name
                == Some("smoke_test_policy_1".to_owned())
        );

        assert!(result.secret_id == "00000000-9494-1111-1111-222222222229".to_owned());

        // delete the created token
        let token_delete_result = consul
            .delete_acl_token("00000000-9494-1111-1111-222222222229".to_owned())
            .await
            .unwrap();
        let policy_delete_result = consul.delete_acl_policy(policy_result.id).await.unwrap();

        // delete the policy
        assert_eq!(token_delete_result, ());
        assert_eq!(policy_delete_result, ());
    }
}

mod tests {
    use std::time::Duration;

    use rs_consul::ConsulError;
    use tokio::time::sleep;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_read_key() {
        let consul = get_client();
        let key = "test/consul/read";
        let string_value = "This is a test";
        let res = create_or_update_key_value(&consul, key, string_value).await;
        assert_expected_result_with_index(res);

        let res = read_key(&consul, key).await.unwrap();
        let index = res.index;
        verify_single_value_matches(Ok(res), string_value);

        let res = read_key(&consul, key).await.unwrap();
        assert_eq!(res.index, index);
        create_or_update_key_value(&consul, key, string_value)
            .await
            .unwrap();
        assert_eq!(res.index, index);
        create_or_update_key_value(&consul, key, "This is a new test")
            .await
            .unwrap();
        let res = read_key(&consul, key).await.unwrap();
        assert!(res.index > index);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_and_retrieve_services() {
        let consul = get_client();

        let new_service_name = "test-service-44".to_string();
        register_entity(&consul, &new_service_name, "local").await;

        assert!(is_registered(&consul, &new_service_name).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_deregister_and_retrieve_services() {
        let consul = get_client();

        let new_service_name = "test-service-45".to_string();
        let node_id = "local";
        register_entity(&consul, &new_service_name, node_id).await;

        let payload = DeregisterEntityPayload {
            Node: Some(node_id.to_string()),
            Datacenter: None,
            CheckID: None,
            ServiceID: None,
            Namespace: None,
        };
        consul
            .deregister_entity(&payload)
            .await
            .expect("expected deregister_entity request to succeed");

        assert!(!is_registered(&consul, &new_service_name).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_services_nodes() {
        let consul = get_client();
        let req = GetServiceNodesRequest {
            service: "nonexistent",
            passing: true,
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_service_nodes(req, None).await.unwrap();
        assert_eq!(response.len(), 0);

        let req = GetServiceNodesRequest {
            service: "test-service",
            passing: true,
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_service_nodes(req, None).await.unwrap();
        assert_eq!(response.len(), 3);

        let addresses: Vec<String> = response
            .iter()
            .map(|sn| sn.service.address.clone())
            .collect();
        let expected_addresses = [
            "1.1.1.1".to_string(),
            "2.2.2.2".to_string(),
            "3.3.3.3".to_string(),
        ];
        assert!(
            expected_addresses
                .iter()
                .all(|item| addresses.contains(item))
        );

        let tags: Vec<String> = response
            .iter()
            .flat_map(|sn| sn.service.tags.clone().into_iter())
            .collect();
        let expected_tags = [
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
        ];
        assert_eq!(expected_tags.len(), 3);
        assert!(expected_tags.iter().all(|tag| tags.contains(tag)));

        let _: Vec<_> = response
            .iter()
            .map(|sn| assert_eq!("dc1", sn.node.datacenter))
            .collect();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_delete_key() {
        let consul = get_client();
        let key = "test/consul/again";
        let string_value = "This is a new test";
        let res = create_or_update_key_value(&consul, key, string_value).await;
        assert_expected_result_with_index(res);

        let res = delete_key(&consul, key).await;
        assert_expected_result(res);

        let res = read_key(&consul, key).await.unwrap_err();
        match res {
            ConsulError::UnexpectedResponseCode(code, _body) => {
                assert_eq!(code, hyper::http::StatusCode::NOT_FOUND)
            }
            _ => panic!(
                "Expected ConsulError::UnexpectedResponseCode, got {:#?}",
                res
            ),
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_release_lock() {
        let consul = get_client();
        let key = "test/consul/lock";
        let string_value = "This is a lock test";
        let new_string_value = "This is a changed lock test";
        let req = LockRequest {
            key,
            behavior: LockExpirationBehavior::Release,
            lock_delay: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        let session_id: String;
        {
            let res = consul.get_lock(req, string_value.as_bytes()).await;
            assert!(res.is_ok());
            let mut lock = res.unwrap();
            let res2 = consul.get_lock(req, string_value.as_bytes()).await;
            assert!(res2.is_err());
            let err = res2.unwrap_err();
            match err {
                ConsulError::LockAcquisitionFailure(_index) => (),
                _ => panic!(
                    "Expected ConsulError::LockAcquisitionFailure, got {:#?}",
                    err
                ),
            }
            session_id = lock.session_id.to_string();
            // Lets change the value before dropping the lock to ensure the change is persisted when the lock is dropped.
            lock.value = Some(new_string_value.as_bytes().to_vec())
            // lock gets dropped here.
        }

        sleep(Duration::from_secs(2)).await;
        let key_resp = read_key(&consul, key).await;
        verify_single_value_matches(key_resp, new_string_value);

        let req = LockRequest {
            key,
            behavior: LockExpirationBehavior::Delete,
            lock_delay: std::time::Duration::from_secs(1),
            session_id: &session_id,
            ..Default::default()
        };
        let res = consul.get_lock(req, string_value.as_bytes()).await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_and_watch_lock() {
        let consul = get_client();
        let key = "test/consul/watchedlock";
        let string_value = "This is a lock test";
        let req = LockRequest {
            key,
            behavior: LockExpirationBehavior::Release,
            lock_delay: std::time::Duration::from_secs(0),
            ..Default::default()
        };
        let res = consul.get_lock(req, string_value.as_bytes()).await;
        assert!(res.is_ok());
        let lock = res.unwrap();
        let res2 = consul.get_lock(req, string_value.as_bytes()).await;
        assert!(res2.is_err());
        let err = res2.unwrap_err();
        let start_index = match err {
            ConsulError::LockAcquisitionFailure(index) => index,
            _ => panic!(
                "Expected ConsulError::LockAcquisitionFailure, got {:#?}",
                err
            ),
        };

        assert!(start_index > 0);
        let watch_req = LockWatchRequest {
            key,
            consistency: ConsistencyMode::Consistent,
            index: Some(start_index),
            wait: Duration::from_secs(60),
            ..Default::default()
        };
        // The lock will timeout and this this will return.
        let res = consul.watch_lock(watch_req).await;
        assert!(res.is_ok());
        std::mem::drop(lock); // This ensures the lock is not dropped until after the request to watch it completes.

        let res = consul.get_lock(req, string_value.as_bytes()).await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn properly_handle_check_and_set() {
        let consul = get_client();
        let key = "test/consul/proper_cas_handling";
        let string_value1 = "This is CAS test";
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: Some(0),
            ..Default::default()
        };

        // Key does not exist, with CAS set and modify index set to 0
        // it should be created.
        let (set, _) = consul
            .create_or_update_key(req.clone(), string_value1.as_bytes().to_vec())
            .await
            .expect("failed to create key initially");
        assert!(set);
        let (value, mod_idx1) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value1, &value.unwrap());

        // Subsequent request with CAS set to 0 should not override the
        // value.
        let string_value2 = "This is CAS test - not valid";
        let (set, _) = consul
            .create_or_update_key(req, string_value2.as_bytes().to_vec())
            .await
            .expect("failed to run subsequent create_or_update_key");
        assert!(!set);
        // Value and modify index should not have changed because set failed.
        let (value, mod_idx2) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value1, &value.unwrap());
        assert_eq!(mod_idx1, mod_idx2);

        // Successfully set value with proper CAS value.
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: Some(mod_idx1),
            ..Default::default()
        };
        let string_value3 = "This is correct CAS updated";
        let (set, _) = consul
            .create_or_update_key(req, string_value3.as_bytes().to_vec())
            .await
            .expect("failed to run create_or_update_key with proper CAS value");
        assert!(set);
        // Verify that value was updated and the index changed.
        let (value, mod_idx3) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value3, &value.unwrap());
        assert_ne!(mod_idx1, mod_idx3);

        // Successfully set value without CAS.
        let req = CreateOrUpdateKeyRequest {
            key,
            check_and_set: None,
            ..Default::default()
        };
        let string_value4 = "This is non CAS update";
        let (set, _) = consul
            .create_or_update_key(req, string_value4.as_bytes().to_vec())
            .await
            .expect("failed to run create_or_update_key without CAS");
        assert!(set);
        // Verify that value was updated and the index changed.
        let (value, mod_idx4) = get_single_key_value_with_index(&consul, key).await;
        assert_eq!(string_value4, &value.unwrap());
        assert_ne!(mod_idx3, mod_idx4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_with_health_checks() {
        let consul = get_client();

        let new_service_name = "test-service-99".to_string();
        let checks = [
            RegisterEntityCheck {
                Node: None,
                CheckID: None,
                Name: "Service Check".to_string(),
                Notes: None,
                Status: Some("passing".to_string()),
                ServiceID: Some(service_id(&new_service_name)),
                Definition: HashMap::new(),
            },
            RegisterEntityCheck {
                Node: Some("local".to_string()),
                CheckID: None,
                Name: "Node check".to_string(),
                Notes: None,
                Status: Some("passing".to_string()),
                ServiceID: None,
                Definition: HashMap::new(),
            },
        ]
        .to_vec();
        register_entity_with_checks(&consul, &new_service_name, "local", checks).await;

        assert!(is_registered(&consul, &new_service_name).await);
    }
}
