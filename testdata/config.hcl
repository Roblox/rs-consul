acl {
  enabled = true
  default_policy = "allow"
  enable_token_persistence = true
}

# CockroachDB cluster 'crdb-entities-as-a-service-one'
services {
  id = "crdb-entities-as-a-service-one-1"
  name = "crdb-entities-as-a-service-one"
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
  id = "crdb-entities-as-a-service-one-2"
  name = "crdb-entities-as-a-service-one"
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
  id = "crdb-entities-as-a-service-one-3"
  name = "crdb-entities-as-a-service-one"
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
