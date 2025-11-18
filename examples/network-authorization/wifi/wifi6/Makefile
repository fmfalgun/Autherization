.PHONY: help up down load-policy load-data test logs clean

OPA_URL := http://localhost:8181

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start OPA server
	@echo "Starting WiFi 6 authorization service..."
	docker-compose up -d
	@sleep 3
	@make load-policy
	@make load-data
	@echo "✅ WiFi 6 OPA running at $(OPA_URL)"

down: ## Stop OPA server
	docker-compose down

load-policy: ## Load policy into OPA
	@curl -X PUT $(OPA_URL)/v1/policies/wifi6 \
		--data-binary @policy.rego \
		-H "Content-Type: text/plain" 2>/dev/null
	@echo "✅ Policy loaded"

load-data: ## Load test data
	@curl -X PUT $(OPA_URL)/v1/data \
		-H "Content-Type: application/json" \
		-d @data.json 2>/dev/null
	@echo "✅ Data loaded"

test: ## Run OPA tests
	@docker run --rm -v $(PWD):/policies openpolicyagent/opa:latest \
		test /policies -v

query-auth: ## Test device authentication
	@curl -s -X POST $(OPA_URL)/v1/data/wifi6/allow \
		-d '{"input": {"action": "authenticate", "device": {"mac": "AA:BB:CC:DD:EE:FF", "security_protocol": "WPA3-SAE", "pmf_capable": true, "wifi6_capable": true}}}' | python3 -m json.tool

query-connect: ## Test device connection
	@curl -s -X POST $(OPA_URL)/v1/data/wifi6/allow \
		-d '{"input": {"action": "connect", "device": {"mac": "AA:BB:CC:DD:EE:FF"}, "network": {"ssid": "Enterprise-WiFi6"}}}' | python3 -m json.tool

logs: ## Show logs
	docker-compose logs -f

clean: ## Clean up
	docker-compose down -v
