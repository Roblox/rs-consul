use rs_consul::*;
use std::collections::HashMap;

#[path = "utils/test_setup.rs"]
mod test_setup;
use test_setup::*;

pub use types::*;

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

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
        let node_id = format!("{new_service_name}-node");
        register_entity(&consul, &new_service_name, &node_id).await;

        assert!(is_registered(&consul, &new_service_name).await);
        remove_service_node(&consul, node_id, Some(new_service_name)).await;
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
        assert!(expected_addresses
            .iter()
            .all(|item| addresses.contains(item)));

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
    async fn get_nodes() {
        let consul = get_client();
        let ts: Duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let service_name = format!("get-nodes-test-{}", ts.as_millis());
        let base_node_name = format!("{service_name}-node");
        register_entity_with_address(
            &consul,
            &service_name,
            &format!("{base_node_name}-0"),
            "127.0.0.1",
        )
        .await;
        register_entity_with_address(
            &consul,
            &service_name,
            &format!("{base_node_name}-1"),
            "127.0.0.2",
        )
        .await;
        register_entity_with_address(
            &consul,
            &service_name,
            &format!("{base_node_name}-2"),
            "127.0.0.1",
        )
        .await;

        let req = GetNodesRequest {
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_nodes(req, None).await.unwrap();
        // We have the default node, maybe some nodes from other tests  and the 3 nodes we added with registration.
        assert!(response.len() > 3, "Nodes: {response:?}");
        let filter = format!("Node+contains+%22{base_node_name}%22");
        let req = GetNodesRequest {
            filter: Some(&filter),
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_nodes(req, None).await.unwrap();
        // Only our nodes should be there.
        assert_eq!(response.len(), 3);

        let _: Vec<_> = response
            .iter()
            .map(|cn| assert_eq!("dc1", cn.datacenter))
            .collect();
        let filter = format!("Meta+contains+%22meta-key-1%22");
        let req = GetNodesRequest {
            filter: Some(&filter),
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_nodes(req, None).await.unwrap();
        // Only our nodes should be there.
        assert_eq!(response.len(), 3);
        // Unregister the service on these nodes
        deregister_entity(
            &consul,
            format!("{base_node_name}-0"),
            Some(service_name.to_string()),
        )
        .await;
        deregister_entity(
            &consul,
            format!("{base_node_name}-1"),
            Some(service_name.to_string()),
        )
        .await;
        deregister_entity(
            &consul,
            format!("{base_node_name}-2"),
            Some(service_name.to_string()),
        )
        .await;
        // The nodes should still exist, even without services:
        let filter = format!("Meta+contains+%22meta-key-1%22");
        let req = GetNodesRequest {
            filter: Some(&filter),
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_nodes(req, None).await.unwrap();
        // Only our nodes should be there.
        assert_eq!(response.len(), 3);
        deregister_entity(&consul, format!("{base_node_name}-0"), None).await;
        deregister_entity(&consul, format!("{base_node_name}-1"), None).await;
        deregister_entity(&consul, format!("{base_node_name}-2"), None).await;
        let filter = format!("Node+contains+%22{base_node_name}%22");
        let req = GetNodesRequest {
            filter: Some(&filter),
            ..Default::default()
        };
        let ResponseMeta { response, .. } = consul.get_nodes(req, None).await.unwrap();
        // The nodes should be gone, and we should only have the default node.
        assert_eq!(response.len(), 0, "Nodes: {response:?}");
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

        let delete_request = DeleteKeyRequest {
            key,
            check_and_set: 0,
            ..Default::default()
        };
        assert!(
            consul
                .delete_key(delete_request)
                .await
                .expect("failed to delete key"),
            "Key should have been deleted"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_with_health_checks() {
        let consul = get_client();

        let new_service_name = "test-service-99".to_string();
        let node_id = format!("{new_service_name}-node");
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
                Node: Some(node_id.clone()),
                CheckID: None,
                Name: "Node check".to_string(),
                Notes: None,
                Status: Some("passing".to_string()),
                ServiceID: None,
                Definition: HashMap::new(),
            },
        ]
        .to_vec();
        register_entity_with_checks(&consul, &new_service_name, &node_id, checks).await;

        assert!(is_registered(&consul, &new_service_name).await);
        remove_service_node(&consul, node_id, Some(new_service_name)).await;
    }
}
