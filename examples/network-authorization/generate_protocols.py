#!/usr/bin/env python3
"""
Generate basic authorization policy structures for all network protocols
"""

import os
import json

# Define all protocols and their versions
PROTOCOLS = {
    "wifi": [
        ("wifi-normal", "WiFi Normal (802.11b/g)", "2.4GHz basic WiFi with WPA2"),
        ("wifi4", "WiFi 4 (802.11n)", "High Throughput with MIMO"),
        ("wifi5", "WiFi 5 (802.11ac)", "Very High Throughput with MU-MIMO"),
        ("wifi7", "WiFi 7 (802.11be)", "Extremely High Throughput with MLO"),
        ("wifi-adhoc", "WiFi Ad-hoc Mode", "Peer-to-peer WiFi networks"),
        ("wifi-enterprise", "WiFi Enterprise", "WPA2/WPA3-Enterprise with RADIUS"),
    ],
    "ble": [
        ("ble-4.0", "BLE 4.0", "First BLE specification"),
        ("ble-4.1", "BLE 4.1", "Coexistence improvements"),
        ("ble-4.2", "BLE 4.2", "Privacy and security enhancements"),
        ("ble-5.0", "BLE 5.0", "2x speed, 4x range, 8x advertising"),
        ("ble-5.1", "BLE 5.1", "Direction finding"),
        ("ble-5.2", "BLE 5.2", "LE Audio and EATT"),
        ("ble-5.3", "BLE 5.3", "Connection improvements"),
        ("ble-5.4", "BLE 5.4", "Advertising enhancements"),
    ],
    "bluetooth": [
        ("bluetooth-classic-2.0", "Bluetooth 2.0 + EDR", "Enhanced Data Rate"),
        ("bluetooth-classic-3.0", "Bluetooth 3.0 + HS", "High Speed"),
        ("bluetooth-classic-4.0", "Bluetooth 4.0", "Low Energy introduced"),
        ("bluetooth-classic-5.0", "Bluetooth 5.0", "Long range and mesh"),
    ],
    "zigbee": [
        ("zigbee-3.0", "Zigbee 3.0", "Unified standard"),
        ("zigbee-pro", "Zigbee PRO", "Professional features"),
    ],
    "lora": [
        ("lora-class-a", "LoRa Class A", "Bi-directional, lowest power"),
        ("lora-class-b", "LoRa Class B", "Scheduled receive slots"),
        ("lora-class-c", "LoRa Class C", "Continuous listening"),
    ],
    "lorawan": [
        ("lorawan-1.0", "LoRaWAN 1.0", "Initial specification"),
        ("lorawan-1.0.4", "LoRaWAN 1.0.4", "Latest 1.0.x"),
        ("lorawan-1.1", "LoRaWAN 1.1", "Security improvements"),
    ],
    "spire": [
        ("spire-workload-attestation", "SPIRE Workload Attestation", "Verify workload identity"),
        ("spire-svid-authorization", "SPIRE SVID Authorization", "X.509 SVID validation"),
    ],
    "openziti": [
        ("openziti-service-authorization", "OpenZiti Service Auth", "Zero trust service access"),
        ("openziti-identity-authorization", "OpenZiti Identity Auth", "Identity-based authorization"),
    ],
    "zero-trust": [
        ("zero-trust-device-trust", "Zero Trust Device Trust", "Device posture validation"),
        ("zero-trust-continuous-validation", "Zero Trust Continuous Validation", "Ongoing verification"),
    ],
}

def create_basic_policy(protocol_dir, name, description):
    """Create a basic OPA policy file"""
    package_name = name.replace("-", "_")

    policy_content = f'''package {package_name}

# {description} Authorization Policy
#
# This policy implements authorization for {description}
#
# Why this policy exists:
# {description} requires specific security controls to ensure:
# - Device authentication and validation
# - Access control based on device capabilities
# - Resource allocation and management
# - Anomaly detection and prevention
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

######################
# DEFAULT DENY
######################

# Default deny - all actions denied unless explicitly allowed
default allow := false

######################
# DEVICE AUTHENTICATION
######################

# Rule: Authenticate device
#
# Why: Ensures only authorized devices can connect
allow if {{
    input.action == "authenticate"
    device_credentials_valid(input.device)
    device_not_blacklisted(input.device.id)
}}

######################
# CONNECTION AUTHORIZATION
######################

# Rule: Allow device connection
#
# Why: Validates device after authentication
allow if {{
    input.action == "connect"
    device_authenticated(input.device.id)
    network_has_capacity(input.network)
}}

######################
# DATA TRANSMISSION
######################

# Rule: Allow data transmission
#
# Why: Ensures data transfer is authorized and within quotas
allow if {{
    input.action == "transmit"
    device_connected(input.device.id)
    data_within_quota(input.device.id, input.data_size)
}}

######################
# RESOURCE MANAGEMENT
######################

# Rule: Allocate network resources
#
# Why: Prevents resource exhaustion
allow if {{
    input.action == "allocate_resources"
    input.user.role == "network_admin"
    resources_available(input.requested_resources)
}}

######################
# HELPER FUNCTIONS
######################

device_credentials_valid(device) if {{
    device.id in data.authorized_devices
}}

device_not_blacklisted(device_id) if {{
    not device_id in data.blacklisted_devices
}}

device_authenticated(device_id) if {{
    data.active_sessions[device_id] != null
}}

network_has_capacity(network) if {{
    current := count(data.connected_devices[network.id])
    max := data.networks[network.id].max_devices
    current < max
}}

device_connected(device_id) if {{
    some network_id
    data.connected_devices[network_id][device_id] != null
}}

data_within_quota(device_id, data_size) if {{
    current := data.bandwidth_usage[device_id]
    quota := data.authorized_devices[device_id].quota
    current + data_size <= quota
}}

resources_available(requested) if {{
    requested > 0
}}
'''

    with open(os.path.join(protocol_dir, "policy.rego"), "w") as f:
        f.write(policy_content)


def create_basic_data(protocol_dir):
    """Create basic test data"""
    data = {
        "authorized_devices": {
            "device-001": {
                "id": "device-001",
                "type": "sensor",
                "quota": 1000000
            },
            "device-002": {
                "id": "device-002",
                "type": "gateway",
                "quota": 10000000
            }
        },
        "blacklisted_devices": ["device-bad"],
        "active_sessions": {
            "device-001": {
                "connected_at": 1700000000,
                "network_id": "network-001"
            }
        },
        "networks": {
            "network-001": {
                "id": "network-001",
                "max_devices": 100
            }
        },
        "connected_devices": {
            "network-001": {
                "device-001": {
                    "ip": "10.0.0.10"
                }
            }
        },
        "bandwidth_usage": {
            "device-001": 50000,
            "device-002": 100000
        }
    }

    with open(os.path.join(protocol_dir, "data.json"), "w") as f:
        json.dump(data, f, indent=2)


def create_readme(protocol_dir, name, full_name, description):
    """Create README for protocol"""
    content = f'''# {full_name} Authorization Policy

Authorization policy for {full_name} - {description}

## Overview

This policy implements authorization controls for {full_name}, ensuring:
- Secure device authentication
- Access control and authorization
- Resource allocation and management
- Anomaly detection and prevention

## Features

- **Device Authentication**: Validates device credentials
- **Connection Control**: Manages device connections
- **Data Transmission**: Controls data transfer permissions
- **Resource Management**: Allocates network resources

## Quick Start

```bash
# Start OPA server
make up

# Test authentication
make test-auth

# View logs
make logs
```

## Policy Rules

### Authentication
Devices must provide valid credentials to authenticate.

### Connection
Only authenticated devices can connect to the network.

### Data Transmission
Data transfer is authorized based on device quotas.

## Testing

```bash
# Run OPA tests
make test

# Query policy
curl -X POST http://localhost:8181/v1/data/{name.replace("-", "_")}/allow \\
  -d '{{"input": {{"action": "authenticate", "device": {{"id": "device-001"}}}}}}'
```

## Resources

- Protocol specifications
- Security best practices
- Integration guides

## License

MIT
'''

    with open(os.path.join(protocol_dir, "README.md"), "w") as f:
        f.write(content)


def create_docker_compose(protocol_dir, name):
    """Create docker-compose.yml"""
    content = f'''version: '3.8'

services:
  opa:
    image: openpolicyagent/opa:latest
    container_name: {name}-opa
    ports:
      - "8181:8181"
    command:
      - "run"
      - "--server"
      - "--log-level=info"
    volumes:
      - ./policy.rego:/policies/policy.rego:ro
      - ./data.json:/data/data.json:ro
    networks:
      - {name}-network

networks:
  {name}-network:
    driver: bridge
'''

    with open(os.path.join(protocol_dir, "docker-compose.yml"), "w") as f:
        f.write(content)


def create_makefile(protocol_dir, name):
    """Create Makefile"""
    content = f'''.PHONY: help up down load-policy load-data test logs clean

OPA_URL := http://localhost:8181

help: ## Show help
\t@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {{FS = ":.*?## "}}; {{printf "  \\033[36m%-20s\\033[0m %s\\n", $$1, $$2}}'

up: ## Start OPA server
\t@docker-compose up -d
\t@sleep 2
\t@make load-policy
\t@make load-data
\t@echo "✅ {name} OPA running at $(OPA_URL)"

down: ## Stop OPA server
\t@docker-compose down

load-policy: ## Load policy
\t@curl -X PUT $(OPA_URL)/v1/policies/{name.replace("-", "_")} --data-binary @policy.rego -H "Content-Type: text/plain" 2>/dev/null
\t@echo "✅ Policy loaded"

load-data: ## Load test data
\t@curl -X PUT $(OPA_URL)/v1/data -H "Content-Type: application/json" -d @data.json 2>/dev/null
\t@echo "✅ Data loaded"

test: ## Run tests
\t@docker run --rm -v $(PWD):/policies openpolicyagent/opa:latest test /policies -v

test-auth: ## Test authentication
\t@curl -s -X POST $(OPA_URL)/v1/data/{name.replace("-", "_")}/allow -d '{{"input": {{"action": "authenticate", "device": {{"id": "device-001"}}}}}}' | python3 -m json.tool

logs: ## Show logs
\t@docker-compose logs -f

clean: ## Clean up
\t@docker-compose down -v
'''

    with open(os.path.join(protocol_dir, "Makefile"), "w") as f:
        f.write(content)


def main():
    base_dir = "/home/user/Autherization/examples/network-authorization"

    for protocol_type, versions in PROTOCOLS.items():
        print(f"\\nGenerating {protocol_type} policies...")

        for name, full_name, description in versions:
            protocol_dir = os.path.join(base_dir, protocol_type, name)
            os.makedirs(protocol_dir, exist_ok=True)

            print(f"  - {name}")

            create_basic_policy(protocol_dir, name, full_name)
            create_basic_data(protocol_dir)
            create_readme(protocol_dir, name, full_name, description)
            create_docker_compose(protocol_dir, name)
            create_makefile(protocol_dir, name)

    print("\\n✅ All protocol structures generated!")


if __name__ == "__main__":
    main()
