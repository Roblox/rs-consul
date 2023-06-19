default: build

# Specify which test file to use.
TEST_FILE_NAME?=""

# Specify which test names to filter by.
TEST_FILTER?=""

build:
	cargo build --all-targets

lint:
	cargo clippy -- -D warnings -A dead_code

fmt:
	cargo fmt --all
	cargo sort --workspace

# Stops the local testing infrastructure
stop-test-env:
	docker-compose -f core-compose.yml down --volumes --remove-orphans

# Helper target to build the image used by test-crates-in-docker. Allows splitting out build vs test time.
build-crates-tester-docker:
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose -f test-compose.yml build --progress=plain -- crates-tester

test-crates:
	cargo test --workspace

# Target used by CI as we can not assume that all infrastructure is hosted via localhost in that environment.
test-crates-in-docker:
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose -f test-compose.yml up --exit-code-from crates-tester crates-tester