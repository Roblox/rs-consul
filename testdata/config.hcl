acl {
  enabled = true
  default_policy = "allow"
  enable_token_persistence = true
}

# A service with 3 instances.
services {
  id = "test-service-1"
  name = "test-service"
  address = "1.1.1.1"
  port = 26257
  checks = []
}

services {
  id = "test-service-2"
  name = "test-service"
  address = "2.2.2.2"
  port = 26257
  checks = []
}

services {
  id = "test-service-3"
  name = "test-service"
  address = "3.3.3.3"
  port = 26257
  checks = []
}
