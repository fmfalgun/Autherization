# Network Authorization Policies

Comprehensive OPA-based authorization policies for IoT and network protocols including WiFi, BLE, Bluetooth, Zigbee, LoRa, LoRaWAN, Spire, OpenZiti, and Zero Trust architectures.

## Overview

This directory contains production-ready authorization policies for various network protocols and IoT frameworks. Each policy is implemented using Open Policy Agent (OPA) and Rego, providing:

- **Device Authentication & Onboarding**
- **Access Control & Authorization**
- **Data Transmission Permissions**
- **Resource Allocation & Management**
- **Continuous Monitoring & Anomaly Detection**

## Network Protocols Covered

### Wireless & IoT Protocols

| Protocol | Versions/Types | Use Cases |
|----------|---------------|-----------|
| **WiFi (802.11)** | Normal, WiFi2-7, Ad-hoc, Enterprise | WLAN access control, WPA2/WPA3 enterprise auth |
| **BLE** | 4.0, 4.1, 4.2, 5.0, 5.1, 5.2, 5.3, 5.4 | IoT device pairing, sensor networks |
| **Bluetooth Classic** | 1.0, 2.0, 3.0, 4.0, 5.0 | Device pairing, audio streaming |
| **Zigbee** | 1.0, 2.0, 3.0, Pro | Smart home, industrial automation |
| **LoRa** | Class A, B, C | Long-range IoT, agriculture, smart cities |
| **LoRaWAN** | 1.0, 1.0.1-1.0.4, 1.1 | Network server authorization, gateway access |

### Zero Trust & Security Frameworks

| Framework | Components | Use Cases |
|-----------|-----------|-----------|
| **Spire** | Workload attestation, SVID, Federation | Service mesh identity, zero trust workloads |
| **OpenZiti** | Service auth, Identity, Edge router | Zero trust networking, secure overlay |
| **Zero Trust Protocols** | Device trust, User verification, Segmentation | Continuous validation, least privilege |

### Monitoring & Security

| Module | Purpose | Capabilities |
|--------|---------|--------------|
| **Continuous Monitoring** | Network anomaly detection | Alert triggering, access restriction, database logging |

## Directory Structure

```
network-authorization/
├── wifi/                    # WiFi 802.11 standards
│   ├── wifi-normal/        # 802.11b/g
│   ├── wifi4/              # 802.11n (WiFi 4)
│   ├── wifi5/              # 802.11ac (WiFi 5)
│   ├── wifi6/              # 802.11ax (WiFi 6)
│   ├── wifi7/              # 802.11be (WiFi 7)
│   ├── wifi-adhoc/         # Ad-hoc mode
│   └── wifi-enterprise/    # WPA2/WPA3 Enterprise
│
├── ble/                     # Bluetooth Low Energy
│   ├── ble-4.0/
│   ├── ble-5.0/
│   ├── ble-5.4/
│   └── ...
│
├── bluetooth/               # Bluetooth Classic
│   ├── bluetooth-classic-2.0/
│   ├── bluetooth-classic-5.0/
│   └── ...
│
├── zigbee/                  # Zigbee protocol
│   ├── zigbee-3.0/
│   ├── zigbee-pro/
│   └── ...
│
├── lora/                    # LoRa device classes
│   ├── lora-class-a/
│   ├── lora-class-b/
│   └── lora-class-c/
│
├── lorawan/                 # LoRaWAN versions
│   ├── lorawan-1.0/
│   ├── lorawan-1.1/
│   └── ...
│
├── spire/                   # Spire framework
│   ├── spire-workload-attestation/
│   └── spire-svid-authorization/
│
├── openziti/                # OpenZiti framework
│   ├── openziti-service-authorization/
│   └── openziti-identity-authorization/
│
├── zero-trust/              # Zero Trust protocols
│   ├── zero-trust-device-trust/
│   └── zero-trust-continuous-validation/
│
└── monitoring/              # Continuous monitoring
    ├── wifi-monitoring/
    ├── anomaly-detection/
    └── ...
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- OPA CLI (optional, for testing)
- Python 3.8+ (for test clients)

### Running a Policy

Each protocol directory contains a complete, executable example:

```bash
# Example: WiFi 6 authorization
cd wifi/wifi6
make up          # Start OPA server with policy
make test        # Run test cases
make query       # Query authorization decisions
```

### Testing Authorization

```bash
# Check if device can connect
curl -X POST http://localhost:8181/v1/data/wifi6/allow \
  -d '{
    "input": {
      "device": {"mac": "AA:BB:CC:DD:EE:FF", "type": "smartphone"},
      "action": "connect",
      "network": {"ssid": "Corp-WiFi-6", "security": "WPA3"}
    }
  }'
```

## Policy Structure

Each protocol directory contains:

```
protocol-version/
├── policy.rego              # OPA authorization policy
├── data.json                # Test data (devices, networks, rules)
├── test_policy.rego         # OPA unit tests
├── README.md                # Protocol-specific documentation
├── docker-compose.yml       # OPA server setup
├── Makefile                 # Helper commands
└── examples/                # Usage examples
    ├── client.py           # Python client
    └── test_cases.json     # Test scenarios
```

## Authorization Scenarios

### 1. Device Authentication & Onboarding

Validates device identity and credentials before network access:

```rego
allow {
    input.action == "onboard"
    valid_device_credentials(input.device)
    device_not_blacklisted(input.device)
}
```

### 2. Access Control

Determines who/what can connect to the network:

```rego
allow {
    input.action == "connect"
    device_has_permission(input.device, input.network)
    network_capacity_available(input.network)
}
```

### 3. Data Transmission Permissions

Controls what data can be transmitted:

```rego
allow {
    input.action == "transmit"
    data_within_quota(input.device, input.data_size)
    destination_allowed(input.destination)
}
```

### 4. Resource Allocation

Manages bandwidth, channels, and network resources:

```rego
allow {
    input.action == "allocate_bandwidth"
    user_has_role(input.user, "admin")
    bandwidth_available(input.requested_bandwidth)
}
```

## Continuous Monitoring

The monitoring module validates data from network sniffing nodes and authorizes security actions:

```rego
# Validate monitoring node
allow {
    input.action == "report_metrics"
    valid_monitoring_node(input.node_id)
    data_signature_valid(input.data, input.signature)
}

# Authorize security action
allow {
    input.action == "block_device"
    anomaly_detected(input.device)
    monitoring_node_authorized(input.node_id)
}
```

### Monitoring Actions

- ✅ Database updates (metrics, logs, alerts)
- ✅ Admin alerts (email, SMS, dashboard)
- ✅ Warning markers
- ✅ Device blocking (temporary/permanent)
- ✅ Network segmentation

## Security Features

### Standard Security

- **Default Deny**: All access denied unless explicitly allowed
- **Principle of Least Privilege**: Minimum required permissions
- **Device Whitelisting/Blacklisting**
- **Rate Limiting & Quotas**
- **Encryption Requirements** (WPA3, AES, etc.)

### Advanced Security

- **Anomaly Detection**: ML-based behavioral analysis
- **Certificate-based Authentication**: X.509, SVID
- **Multi-factor Authentication**: For sensitive networks
- **Temporal Access Control**: Time-based restrictions
- **Geofencing**: Location-based access

## Use Cases

### Enterprise WiFi

```bash
cd wifi/wifi-enterprise
# Authenticate employees with RADIUS
# Separate guest network policies
# Department-based access control
```

### Smart Home (Zigbee)

```bash
cd zigbee/zigbee-3.0
# Device pairing authorization
# Command validation (lights, locks, sensors)
# Guest device restrictions
```

### Industrial IoT (LoRaWAN)

```bash
cd lorawan/lorawan-1.1
# Sensor onboarding
# Gateway authorization
# Data transmission quotas
```

### Service Mesh (Spire)

```bash
cd spire/spire-workload-attestation
# Workload identity verification
# Service-to-service authorization
# SVID validation
```

## Testing

### Run All Tests

```bash
# Test all WiFi policies
make test-wifi

# Test all BLE policies
make test-ble

# Test monitoring modules
make test-monitoring

# Test everything
make test-all
```

### Individual Protocol Tests

```bash
cd wifi/wifi6
make test                    # Run OPA tests
make test-client             # Run client tests
make test-anomaly            # Test anomaly detection
```

## Common Patterns

### Pattern 1: Role-Based Access

```rego
allow {
    user_has_role(input.user, "network_admin")
    input.action in ["configure", "monitor", "block"]
}
```

### Pattern 2: Device Trust Score

```rego
allow {
    input.action == "connect"
    device_trust_score(input.device) >= 80
    device_compliant(input.device)
}
```

### Pattern 3: Conditional Access

```rego
allow {
    input.action == "access_resource"
    business_hours
    user_on_corporate_network(input.user)
    device_encrypted(input.device)
}
```

## Performance Considerations

- **Policy Caching**: OPA caches policy decisions
- **Bundle Server**: For large-scale deployments
- **Partial Evaluation**: Pre-compute policies
- **Database Integration**: PostgreSQL, MongoDB adapters

## Production Deployment

### High Availability

```yaml
# Deploy OPA cluster
services:
  opa-1:
    image: openpolicyagent/opa:latest
  opa-2:
    image: openpolicyagent/opa:latest
  opa-3:
    image: openpolicyagent/opa:latest
```

### Monitoring & Logging

- Prometheus metrics
- Grafana dashboards
- ELK stack integration
- Audit logging

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines on adding new protocol policies.

## Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [WiFi Alliance](https://www.wi-fi.org/)
- [Bluetooth SIG](https://www.bluetooth.com/)
- [Zigbee Alliance](https://zigbeealliance.org/)
- [LoRa Alliance](https://lora-alliance.org/)
- [Spire Documentation](https://spiffe.io/docs/latest/spire/)
- [OpenZiti Documentation](https://openziti.github.io/)

## License

MIT

---

**Note**: These policies are reference implementations. Adapt them to your specific security requirements and compliance needs before production deployment.
