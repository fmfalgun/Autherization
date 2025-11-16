.PHONY: up down load-policy load-data test check run clean logs help

# OPA server URL
OPA_URL := http://localhost:8181

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start OPA server
	@echo "Starting OPA server..."
	docker-compose up -d
	@echo "Waiting for OPA to be ready..."
	@sleep 3
	@echo "✅ OPA server is running at $(OPA_URL)"

down: ## Stop OPA server
	@echo "Stopping OPA server..."
	docker-compose down
	@echo "✅ OPA server stopped"

load-policy: ## Load policy into OPA
	@echo "Loading policy..."
	curl -X PUT $(OPA_URL)/v1/policies/authz \
		--data-binary @policy.rego \
		-H "Content-Type: text/plain"
	@echo "\n✅ Policy loaded"

load-data: ## Load data into OPA
	@echo "Loading data..."
	curl -X PUT $(OPA_URL)/v1/data \
		-H "Content-Type: application/json" \
		-d @data.json
	@echo "✅ Data loaded"

test: ## Run policy tests
	@echo "Running policy tests..."
	docker run --rm -v $(PWD):/policies openpolicyagent/opa:latest \
		test /policies -v

check: ## Check policy syntax
	@echo "Checking policy syntax..."
	docker run --rm -v $(PWD):/policies openpolicyagent/opa:latest \
		check /policies/policy.rego
	@echo "✅ Policy syntax is valid"

run: ## Run the Python client
	@echo "Running client application..."
	python3 app.py

setup: up load-policy load-data ## Complete setup (start + load policy + load data)
	@echo "✅ Setup complete! Run 'make run' to test authorization"

logs: ## Show OPA logs
	docker-compose logs -f opa

clean: down ## Clean up everything
	@echo "Cleaning up..."
	docker-compose down -v
	@echo "✅ Cleanup complete"

query-alice-read: ## Example: Check if Alice can read document123
	@curl -s -X POST $(OPA_URL)/v1/data/authz/allow \
		-H "Content-Type: application/json" \
		-d '{"input": {"user": "alice", "action": "read", "resource": "document123"}}' | \
		python3 -m json.tool

query-bob-write-own: ## Example: Check if Bob can write his own document
	@curl -s -X POST $(OPA_URL)/v1/data/authz/allow \
		-H "Content-Type: application/json" \
		-d '{"input": {"user": "bob", "action": "write", "resource": "document123"}}' | \
		python3 -m json.tool

query-charlie-delete: ## Example: Check if Charlie can delete
	@curl -s -X POST $(OPA_URL)/v1/data/authz/allow \
		-H "Content-Type: application/json" \
		-d '{"input": {"user": "charlie", "action": "delete", "resource": "document123"}}' | \
		python3 -m json.tool

view-data: ## View all data in OPA
	@curl -s $(OPA_URL)/v1/data | python3 -m json.tool

health: ## Check OPA health
	@curl -s $(OPA_URL)/health && echo " - OPA is healthy ✅"
