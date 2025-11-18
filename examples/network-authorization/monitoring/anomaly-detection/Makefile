.PHONY: help up down load-policy load-data test logs clean

OPA_URL := http://localhost:8181

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start OPA server
	@echo "Starting monitoring authorization service..."
	docker-compose up -d
	@sleep 3
	@make load-policy
	@make load-data
	@echo "✅ Monitoring OPA running at $(OPA_URL)"

down: ## Stop OPA server
	docker-compose down

load-policy: ## Load policy into OPA
	@curl -X PUT $(OPA_URL)/v1/policies/monitoring \
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

test-register-node: ## Test node registration
	@curl -s -X POST $(OPA_URL)/v1/data/monitoring/allow \
		-d '{"input": {"action": "register_node", "node": {"certificate": {"subject": "CN=Test-Node", "issuer": "CN=Monitoring-CA", "expiry_timestamp": 1893456000000000000}, "location": {"building": "HQ", "floor": 1}}}}' | python3 -m json.tool

test-report-anomaly: ## Test anomaly reporting
	@curl -s -X POST $(OPA_URL)/v1/data/monitoring/allow \
		-d '{"input": {"action": "report_anomaly", "node_id": "wifi-sniffer-01", "anomaly": {"network_type": "wifi", "type": "deauth_flood", "severity_score": 80, "confidence": 0.95}}}' | python3 -m json.tool

test-block-device: ## Test device blocking
	@curl -s -X POST $(OPA_URL)/v1/data/monitoring/allow \
		-d '{"input": {"action": "block_device", "node_id": "ble-sniffer-02", "device_id": "AA:BB:CC:DD:EE:FF", "block": {"type": "temporary", "severity": "high", "duration_hours": 24}, "anomaly": {"severity": "high", "confidence": 0.92}}}' | python3 -m json.tool

logs: ## Show logs
	docker-compose logs -f

clean: ## Clean up
	docker-compose down -v
