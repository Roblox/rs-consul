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
  port = 20001
  checks = []
  tags = ["first"]
}

services {
  id = "test-service-2"
  name = "test-service"
  address = "2.2.2.2"
  port = 20002
  checks = []
  tags = ["second"]
}

services {
  id = "test-service-3"
  name = "test-service"
  address = "3.3.3.3"
  port = 20003
  checks = []
  tags = ["third"]
}
