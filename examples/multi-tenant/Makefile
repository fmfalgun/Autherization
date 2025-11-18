.PHONY: help up down logs clean test-alice test-bob test-cross-tenant load-policy load-data

API_URL := http://localhost:5000/api
OPA_URL := http://localhost:8181

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start all services
	@echo "Starting multi-tenant demo..."
	docker-compose up --build -d
	@echo "Waiting for services..."
	@sleep 5
	@make load-policy
	@make load-data
	@echo "✅ API running at $(API_URL)"
	@echo "✅ OPA running at $(OPA_URL)"

down: ## Stop all services
	@echo "Stopping services..."
	docker-compose down
	@echo "✅ Services stopped"

logs: ## Show all logs
	docker-compose logs -f

logs-api: ## Show API logs
	docker-compose logs -f api

logs-opa: ## Show OPA logs
	docker-compose logs -f opa

load-policy: ## Load OPA policy
	@echo "Loading policy..."
	@curl -X PUT $(OPA_URL)/v1/policies/multitenant \
		--data-binary @policy.rego \
		-H "Content-Type: text/plain" 2>/dev/null || echo "Waiting for OPA..."
	@echo "✅ Policy loaded"

load-data: ## Load tenant data into OPA
	@echo "Loading tenant data..."
	@curl -X PUT $(OPA_URL)/v1/data/tenants \
		-H "Content-Type: application/json" \
		-d @tenants.json 2>/dev/null || echo "Waiting for OPA..."
	@echo "✅ Data loaded"

health: ## Check health
	@curl -s $(API_URL:=/api=)/health | python3 -m json.tool

# Test different users
test-alice: ## Test as Alice (Acme admin)
	@echo "\n=== Testing as Alice (Acme Admin) ==="
	@$(eval TOKEN := $(shell curl -s -X POST $(API_URL)/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"alice","password":"alice123"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"))
	@echo "\n1. List Acme resources:"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/resources | python3 -m json.tool

test-bob: ## Test as Bob (Acme user)
	@echo "\n=== Testing as Bob (Acme User) ==="
	@$(eval TOKEN := $(shell curl -s -X POST $(API_URL)/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"bob","password":"bob123"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"))
	@echo "\n1. List resources (should see Acme only):"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/resources | python3 -m json.tool
	@echo "\n2. Try to create resource (should fail):"
	@curl -s -X POST -H "Authorization: Bearer $(TOKEN)" \
		-H "Content-Type: application/json" \
		-d '{"name":"Test","type":"document"}' \
		$(API_URL)/resources | python3 -m json.tool

test-charlie: ## Test as Charlie (Globex admin)
	@echo "\n=== Testing as Charlie (Globex Admin) ==="
	@$(eval TOKEN := $(shell curl -s -X POST $(API_URL)/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"charlie","password":"charlie123"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"))
	@echo "\n1. List Globex resources:"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/resources | python3 -m json.tool

test-superadmin: ## Test as root (superadmin)
	@echo "\n=== Testing as Root (Superadmin) ==="
	@$(eval TOKEN := $(shell curl -s -X POST $(API_URL)/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"root","password":"root123"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"))
	@echo "\n1. List all tenants:"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/tenants | python3 -m json.tool
	@echo "\n2. List all resources:"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/resources | python3 -m json.tool

test-isolation: ## Test tenant isolation
	@echo "\n=== Testing Tenant Isolation ==="
	@echo "Alice (Acme) should NOT see Globex resources"
	@$(eval TOKEN := $(shell curl -s -X POST $(API_URL)/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"alice","password":"alice123"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"))
	@echo "\nAlice's accessible resources:"
	@curl -s -H "Authorization: Bearer $(TOKEN)" $(API_URL)/resources | python3 -m json.tool

test-all: test-alice test-bob test-charlie test-superadmin test-isolation ## Run all tests

clean: down ## Clean up everything
	@echo "Cleaning up..."
	docker-compose down -v
	@echo "✅ Cleanup complete"

run-local: ## Run API locally (requires Python)
	@echo "Starting API locally..."
	@echo "Make sure OPA is running: docker run -p 8181:8181 openpolicyagent/opa run --server"
	python3 app.py

install: ## Install Python dependencies
	pip3 install -r requirements.txt
