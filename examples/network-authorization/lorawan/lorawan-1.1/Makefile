.PHONY: help up down load-policy load-data test logs clean

OPA_URL := http://localhost:8181

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start OPA server
	@docker-compose up -d
	@sleep 2
	@make load-policy
	@make load-data
	@echo "✅ lorawan-1.1 OPA running at $(OPA_URL)"

down: ## Stop OPA server
	@docker-compose down

load-policy: ## Load policy
	@curl -X PUT $(OPA_URL)/v1/policies/lorawan_1.1 --data-binary @policy.rego -H "Content-Type: text/plain" 2>/dev/null
	@echo "✅ Policy loaded"

load-data: ## Load test data
	@curl -X PUT $(OPA_URL)/v1/data -H "Content-Type: application/json" -d @data.json 2>/dev/null
	@echo "✅ Data loaded"

test: ## Run tests
	@docker run --rm -v $(PWD):/policies openpolicyagent/opa:latest test /policies -v

test-auth: ## Test authentication
	@curl -s -X POST $(OPA_URL)/v1/data/lorawan_1.1/allow -d '{"input": {"action": "authenticate", "device": {"id": "device-001"}}}' | python3 -m json.tool

logs: ## Show logs
	@docker-compose logs -f

clean: ## Clean up
	@docker-compose down -v
