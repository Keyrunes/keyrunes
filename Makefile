.PHONY: help db-create db-drop db-reset migrate run build test test-unit test-hurl test-all test-stress clean dev setup superadmin sqlx-prepare check lint

# Variables
DATABASE_URL ?= postgres://postgres_user:pass123@localhost:5432/keyrunes
ADMIN_EMAIL ?= admin@example.com
ADMIN_USERNAME ?= admin
ADMIN_PASSWORD ?= Admin123

help:
	@echo "Commands available:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Environment variables:"
	@echo "  DATABASE_URL=$(DATABASE_URL)"
	@echo "  ADMIN_EMAIL=$(ADMIN_EMAIL)"
	@echo "  ADMIN_USERNAME=$(ADMIN_USERNAME)"

## Database
db-create: ## Creates the database
	@echo "Creating database..."
	sqlx database create

db-drop: ## Removes the database (CAUTION: deletes all data!)
	@echo "Removing database..."
	sqlx database drop -y

db-reset: db-drop db-create migrate ## Resets the database (drop + create + migrate)
	@echo "Database reset successfully!"

migrate: ## Runs the migrations
	@echo "Running migrations..."
	sqlx migrate run
	@echo "Migrations applied!"

migrate-revert: ## Reverts the last migration
	@echo "Reverting last migration..."
	sqlx migrate revert

## Build & Run
build: ## Compiles the project
	@echo "Compiling..."
	cargo build

build-release: ## Compiles in release mode
	@echo "Compiling release..."
	cargo build --release

run: ## Runs the server
	@echo "Starting server..."
	cargo run

run-release: ## Runs the server in release mode
	@echo "Starting server (release)..."
	cargo run --release

dev: ## Runs the server with auto-reload (requires cargo-watch)
	@echo "Development mode with hot-reload..."
	cargo watch -x run

## CLI
cli-superadmin: ## Creates the first superadmin
	@echo "Creating superadmin..."
	cargo run --bin cli -- create-superadmin \
		--email $(ADMIN_EMAIL) \
		--username $(ADMIN_USERNAME) \
		--password $(ADMIN_PASSWORD)
	@echo "Superadmin created!"

cli-list-groups: ## Lists all groups
	@echo "Listing groups..."
	cargo run --bin cli -- list-groups

cli-create-group: ## Creates a group (usage: make cli-create-group NAME=developers DESC="Dev team")
	@echo "Creating group $(NAME)..."
	cargo run --bin cli -- create-group --name $(NAME) --description "$(DESC)"

## Tests
test: ## Runs all Rust tests
	@echo "Running Rust tests..."
	cargo test

test-unit: ## Runs only unit tests
	@echo "Running unit tests..."
	cargo test --lib

test-integration: ## Runs only integration tests
	@echo "Running integration tests..."
	cargo test --test '*'

test-hurl: ## Runs Hurl tests (requires server running)
	@echo "Running Hurl tests..."
	@if ! curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "Server is not running! Run 'make run' first."; \
		exit 1; \
	fi
	./hurl/run_hurl_tests.sh

test-hurl-quick: ## Runs Hurl tests without cleanup (direct)
	@echo "Running Hurl tests (direct, without cleanup)..."
	@if ! curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "Server is not running! Run 'make run' first."; \
		exit 1; \
	fi
	@export TEST_TIMESTAMP=$$(date +%s) && \
	hurl --variable BASE_URL=http://localhost:3000 --variable TEST_TIMESTAMP=$$TEST_TIMESTAMP --test hurl/*.hurl

test-hurl-verbose: ## Runs Hurl tests in verbose mode
	@echo "Running Hurl tests (verbose)..."
	./hurl/run_hurl_tests.sh --verbose

test-all: test test-hurl ## Runs all tests (Rust + Hurl)

test-stress: ## Runs Goose stress tests (requires server running)
	@echo "Running stress tests..."
	@if ! curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "Server is not running! Run 'make run' first."; \
		exit 1; \
	fi
	cargo test --test stress_test -- --ignored --test-threads=1

## SQLx
sqlx-prepare: ## Prepares SQLx metadata offline
	@echo "Preparing SQLx metadata..."
	cargo sqlx prepare

sqlx-check: ## Verifies if SQLx queries are correct
	@echo "Verifying SQLx queries..."
	cargo sqlx prepare --check

## Complete Setup
setup: db-create migrate cli-superadmin ## Complete setup (creates DB, migrations, superadmin)
	@echo ""
	@echo "Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Start the server: make run"
	@echo "  2. Access: http://127.0.0.1:3000/login"
	@echo "  3. Login: $(ADMIN_USERNAME) / $(ADMIN_PASSWORD)"
	@echo "  4. Admin: http://127.0.0.1:3000/admin"
	@echo ""

## Development
check: ## Checks the code without compiling
	@echo "Checking code..."
	cargo check --all-targets

lint: ## Runs clippy (linter)
	@echo "Running linter..."
	cargo clippy -- -D warnings

fmt: ## Formats the code
	@echo "Formatting code..."
	cargo fmt

fmt-check: ## Verifies formatting without changing
	@echo "Verifying formatting..."
	cargo fmt -- --check

clean: ## Cleans build files
	@echo "Cleaning..."
	cargo clean

## Docker
docker-up: ## Starts Postgres via docker-compose
	@echo "Starting Docker..."
	docker-compose up -d
	@echo "Waiting for Postgres to start..."
	@sleep 3
	@echo "Postgres is running!"

docker-down: ## Stops Postgres
	@echo "Stopping Docker..."
	docker-compose down

docker-reset: docker-down docker-up ## Resets Docker containers
	@echo "Docker reset successfully!"

docker-logs: ## Shows Postgres logs
	docker-compose logs -f postgres

## Quick commands
fresh-start: docker-reset db-reset setup ## Starts from scratch (Docker + DB + Setup)
	@echo ""
	@echo "Environment ready for development!"
	@echo "Run: make run"

restart: docker-down docker-up migrate ## Restarts development environment
	@echo "Environment restarted!"

## Info
env: ## Shows environment variables
	@echo "DATABASE_URL: $(DATABASE_URL)"
	@echo "ADMIN_EMAIL: $(ADMIN_EMAIL)"
	@echo "ADMIN_USERNAME: $(ADMIN_USERNAME)"
	@echo "ADMIN_PASSWORD: $(ADMIN_PASSWORD)"

status: ## Shows environment status
	@echo "Environment Status"
	@echo ""
	@echo "Docker:"
	@docker-compose ps 2>/dev/null || echo "  Docker is not running"
	@echo ""
	@echo "Server:"
	@if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "  Server running (http://localhost:3000)"; \
	else \
		echo "  Server is not running"; \
	fi
	@echo ""
	@echo "Database:"
	@if psql $(DATABASE_URL) -c "SELECT 1" > /dev/null 2>&1; then \
		echo "  Connected"; \
	else \
		echo "  Not connected"; \
	fi
