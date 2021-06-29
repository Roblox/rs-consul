acl {
  enabled = true
  default_policy = "allow"
  enable_token_persistence = true
}

# CockroachDB cluster 'crdb-test-service-one'
services {
  id = "crdb-test-service-one-1"
  name = "crdb-test-service-one"
  address = "cockroachdb-node-1."
  port = 26257
  checks = [
    {
      args = ["/usr/bin/nc", "-z", "cockroachdb-node-1.", "26257"]
      interval = "10s"
      timeout = "5s"
    }
  ]
}
services {
  id = "crdb-test-service-one-2"
  name = "crdb-test-service-one"
  address = "cockroachdb-node-2."
  port = 26257
  checks = [
    {
      args = ["/usr/bin/nc", "-z", "cockroachdb-node-2.", "26257"]
      interval = "10s"
      timeout = "5s"
    }
  ]
}
services {
  id = "crdb-test-service-one-3"
  name = "crdb-test-service-one"
  address = "cockroachdb-node-3."
  port = 26257
  checks = [
    {
      args = ["/usr/bin/nc", "-z", "cockroachdb-node-3.", "26257"]
      interval = "10s"
      timeout = "5s"
    }
  ]
}
