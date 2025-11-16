.PHONY: help build run test clean up down logs show-policies test-user test-manager test-admin

API_URL := http://localhost:8080

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image
	@echo "Building Docker image..."
	docker-compose build
	@echo "✅ Build complete"

up: build ## Start the server with Docker
	@echo "Starting server..."
	docker-compose up -d
	@echo "Waiting for server to be ready..."
	@sleep 3
	@echo "✅ Server running at $(API_URL)"

down: ## Stop the server
	@echo "Stopping server..."
	docker-compose down
	@echo "✅ Server stopped"

run: ## Run locally (requires Go)
	@echo "Starting server locally..."
	go run main.go

logs: ## Show server logs
	docker-compose logs -f

test: ## Run Go tests
	@echo "Running tests..."
	go test -v ./...

show-policies: ## Display all policies and roles
	@echo "Current Policies:"
	@curl -s $(API_URL)/api/policies | python3 -m json.tool

health: ## Check server health
	@curl -s $(API_URL)/health | python3 -m json.tool

# Test as different users
test-user: ## Test as user (bob)
	@echo "\n=== Testing as USER (bob) ==="
	@echo "\n1. List documents (should succeed):"
	@curl -s -H "X-User: bob" $(API_URL)/api/documents | python3 -m json.tool
	@echo "\n2. Create document (should fail):"
	@curl -s -X POST -H "X-User: bob" -H "Content-Type: application/json" \
		-d '{"title":"Test","content":"Hello"}' $(API_URL)/api/documents | python3 -m json.tool

test-manager: ## Test as manager (alice)
	@echo "\n=== Testing as MANAGER (alice) ==="
	@echo "\n1. List documents (should succeed):"
	@curl -s -H "X-User: alice" $(API_URL)/api/documents | python3 -m json.tool
	@echo "\n2. Create document (should succeed):"
	@curl -s -X POST -H "X-User: alice" -H "Content-Type: application/json" \
		-d '{"title":"Manager Doc","content":"Created by manager"}' $(API_URL)/api/documents | python3 -m json.tool
	@echo "\n3. Delete document (should fail):"
	@curl -s -X DELETE -H "X-User: alice" $(API_URL)/api/documents/1 | python3 -m json.tool

test-admin: ## Test as admin (admin_user)
	@echo "\n=== Testing as ADMIN (admin_user) ==="
	@echo "\n1. List documents (should succeed):"
	@curl -s -H "X-User: admin_user" $(API_URL)/api/documents | python3 -m json.tool
	@echo "\n2. Create document (should succeed):"
	@curl -s -X POST -H "X-User: admin_user" -H "Content-Type: application/json" \
		-d '{"title":"Admin Doc","content":"Created by admin"}' $(API_URL)/api/documents | python3 -m json.tool
	@echo "\n3. Delete document (should succeed):"
	@curl -s -X DELETE -H "X-User: admin_user" $(API_URL)/api/documents/1 | python3 -m json.tool

test-all: test-user test-manager test-admin ## Run all user role tests

get-permissions: ## Get permissions for a user (usage: make get-permissions USER=alice)
	@curl -s $(API_URL)/api/permissions/$(USER) | python3 -m json.tool

list-documents: ## List all documents
	@curl -s -H "X-User: alice" $(API_URL)/api/documents | python3 -m json.tool

create-document: ## Create a document (usage: make create-document USER=alice TITLE="My Doc")
	@curl -s -X POST -H "X-User: $(USER)" -H "Content-Type: application/json" \
		-d '{"title":"$(TITLE)","content":"Created via make"}' $(API_URL)/api/documents | python3 -m json.tool

clean: down ## Clean up everything
	@echo "Cleaning up..."
	docker-compose down -v
	@echo "✅ Cleanup complete"

install-deps: ## Install Go dependencies
	@echo "Installing dependencies..."
	go mod download
	@echo "✅ Dependencies installed"

format: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...
	@echo "✅ Code formatted"
