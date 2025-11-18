# WiFi 6 (802.11ax) Authorization Policy

Comprehensive OPA-based authorization policy for WiFi 6 (802.11ax) networks implementing WPA3, OFDMA, MU-MIMO, and Target Wake Time (TWT) security features.

## Overview

WiFi 6 (802.11ax) introduced significant security and performance improvements:

- **WPA3 Security**: Enhanced encryption and protection
- **OFDMA**: Orthogonal Frequency Division Multiple Access
- **MU-MIMO**: Multi-user, multiple input, multiple output (up to 8 users)
- **Target Wake Time (TWT)**: Power-efficient scheduling
- **BSS Coloring**: Interference mitigation
- **1024-QAM**: Higher data rates

## Authorization Scenarios

This policy covers:

1. **Device Onboarding**: WPA3-SAE handshake validation
2. **Access Control**: Device type, security posture, and credentials
3. **Data Transmission**: Bandwidth allocation, QoS, OFDMA resource units
4. **Resource Management**: Channel access, TWT schedules, MU-MIMO streams
5. **Roaming**: Fast BSS transition (802.11r) authorization

## Security Features

### WPA3 Security

- **SAE (Simultaneous Authentication of Equals)**: Replaces PSK
- **Forward Secrecy**: Even if password compromised, past sessions secure
- **Protected Management Frames**: Mandatory
- **192-bit Security Suite**: For enterprise networks

### WiFi 6 Specific

- **Enhanced Open**: OWE (Opportunistic Wireless Encryption)
- **Easy Connect**: DPP (Device Provisioning Protocol)
- **Multi-AP Coordination**: For mesh networks

## Policy Rules

### 1. Device Authentication

```rego
# Devices must pass WPA3-SAE authentication
allow {
    input.action == "authenticate"
    input.device.security_protocol == "WPA3-SAE"
    valid_sae_credentials(input.device)
    device_supports_pmf(input.device)  # Protected Management Frames
}
```

### 2. Connection Authorization

```rego
# Authorized devices can connect to WiFi 6 AP
allow {
    input.action == "connect"
    device_authenticated(input.device.mac)
    network_capacity_available(input.network)
    device_wifi6_compatible(input.device)
}
```

### 3. OFDMA Resource Unit Allocation

```rego
# Allocate Resource Units for OFDMA
allow {
    input.action == "allocate_ru"
    device_connected(input.device.mac)
    ru_available(input.requested_ru_size)
    device_qos_level(input.device) >= required_qos(input.requested_ru_size)
}
```

### 4. MU-MIMO Stream Assignment

```rego
# Assign spatial streams for downlink MU-MIMO
allow {
    input.action == "assign_mimo_stream"
    count(input.devices) <= 8  # WiFi 6 supports up to 8 users
    all_devices_connected(input.devices)
    sufficient_spatial_streams(input.ap, input.devices)
}
```

### 5. Target Wake Time (TWT) Scheduling

```rego
# Schedule TWT for power-efficient operation
allow {
    input.action == "schedule_twt"
    device_supports_twt(input.device)
    twt_slot_available(input.requested_time)
    device_power_save_mode(input.device) == true
}
```

## Quick Start

### Start OPA Server

```bash
# Start OPA with WiFi 6 policy
make up

# Or manually
docker-compose up -d
```

### Load Policy and Data

```bash
# Load policy
make load-policy

# Load test data (APs, devices, networks)
make load-data
```

### Test Authorization

```bash
# Run all tests
make test

# Test specific scenario
make test-authentication
make test-ofdma
make test-mumimo
```

## Usage Examples

### Example 1: Device Authentication

```bash
curl -X POST http://localhost:8181/v1/data/wifi6/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "action": "authenticate",
      "device": {
        "mac": "AA:BB:CC:DD:EE:FF",
        "type": "smartphone",
        "security_protocol": "WPA3-SAE",
        "pmf_capable": true,
        "wifi6_capable": true
      },
      "network": {
        "ssid": "Enterprise-WiFi6",
        "security": "WPA3-Enterprise-192bit"
      }
    }
  }'
```

### Example 2: OFDMA Resource Allocation

```bash
curl -X POST http://localhost:8181/v1/data/wifi6/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "action": "allocate_ru",
      "device": {
        "mac": "AA:BB:CC:DD:EE:FF",
        "qos_level": 5
      },
      "requested_ru_size": 106,
      "channel": 36
    }
  }'
```

### Example 3: TWT Scheduling

```bash
curl -X POST http://localhost:8181/v1/data/wifi6/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "action": "schedule_twt",
      "device": {
        "mac": "AA:BB:CC:DD:EE:FF",
        "twt_capable": true,
        "power_save": true
      },
      "requested_time": "2025-11-18T10:00:00Z",
      "duration_ms": 100
    }
  }'
```

## Test Data

### Access Points

```json
{
  "ap_001": {
    "ssid": "Enterprise-WiFi6",
    "bssid": "00:11:22:33:44:55",
    "channel": 36,
    "bandwidth": "80MHz",
    "security": "WPA3-Enterprise-192bit",
    "max_clients": 50,
    "spatial_streams": 8,
    "ofdma_enabled": true,
    "mu_mimo_enabled": true
  }
}
```

### Authorized Devices

```json
{
  "AA:BB:CC:DD:EE:FF": {
    "mac": "AA:BB:CC:DD:EE:FF",
    "type": "smartphone",
    "manufacturer": "Apple",
    "model": "iPhone 14",
    "wifi6_capable": true,
    "security_protocols": ["WPA3-SAE", "WPA3-Enterprise"],
    "pmf_capable": true,
    "twt_capable": true,
    "qos_level": 7,
    "max_bandwidth_mbps": 1200
  }
}
```

## WiFi 6 Technical Specifications

### Frequency Bands

- **2.4 GHz**: Channels 1-13
- **5 GHz**: Channels 36-165
- **6 GHz**: (WiFi 6E) Channels 1-233

### Channel Widths

- 20 MHz
- 40 MHz
- 80 MHz
- 160 MHz

### OFDMA Resource Units (RUs)

| RU Size | Subcarriers | Use Case |
|---------|-------------|----------|
| 26 | 26 | IoT devices, sensors |
| 52 | 52 | Low bandwidth devices |
| 106 | 106 | Medium bandwidth |
| 242 | 242 | High bandwidth |
| 484 | 484 | Very high bandwidth |
| 996 | 996 | Maximum throughput |

### MU-MIMO Capabilities

- **Downlink**: Up to 8 simultaneous users
- **Uplink**: Up to 8 simultaneous users (UL OFDMA)
- **Spatial Streams**: 8x8 MIMO

## Security Considerations

### WPA3 Requirements

1. ✅ **SAE Authentication**: More secure than WPA2-PSK
2. ✅ **Protected Management Frames**: Mandatory
3. ✅ **Perfect Forward Secrecy**: Session keys not compromised
4. ✅ **Enhanced Encryption**: 192-bit security for enterprise

### Additional Security

- **Device Fingerprinting**: Validate device capabilities
- **Rate Limiting**: Prevent DoS attacks
- **Anomaly Detection**: Unusual traffic patterns
- **Client Isolation**: Prevent peer-to-peer attacks

## Performance Optimization

### QoS Mapping

| Traffic Type | QoS Level | Priority |
|--------------|-----------|----------|
| Voice | 7-6 | High |
| Video | 5-4 | Medium-High |
| Best Effort | 3-2 | Medium |
| Background | 1-0 | Low |

### Resource Allocation Strategy

```rego
# Prioritize high QoS devices for larger RUs
allocate_ru_size(device) = 996 if {
    device.qos_level >= 6
}

allocate_ru_size(device) = 242 if {
    device.qos_level >= 4
    device.qos_level < 6
}

allocate_ru_size(device) = 52 if {
    device.qos_level < 4
}
```

## Troubleshooting

### Common Issues

**Authentication Fails**
- Verify WPA3-SAE support on device
- Check PMF capability
- Ensure proper credentials

**Low Throughput**
- Check OFDMA/MU-MIMO allocation
- Verify channel congestion
- Review QoS settings

**Connection Drops**
- Check TWT schedule conflicts
- Verify AP capacity
- Review roaming policies

## Advanced Features

### Fast BSS Transition (802.11r)

```rego
allow {
    input.action == "fast_roaming"
    device_authenticated(input.device.mac)
    target_ap_in_mobility_domain(input.target_ap)
    pmk_r1_available(input.device, input.target_ap)
}
```

### BSS Coloring

```rego
allow {
    input.action == "set_bss_color"
    user_has_role(input.user, "network_admin")
    bss_color_not_in_use(input.color, input.vicinity)
}
```

## Integration

### RADIUS Integration

```python
# Authenticate against RADIUS server
def validate_enterprise_auth(device, credentials):
    radius_response = radius_client.authenticate(
        username=credentials['username'],
        password=credentials['password']
    )
    return radius_response.code == RADIUS_ACCESS_ACCEPT
```

### Network Controller Integration

```python
# Query OPA from WiFi controller
def authorize_device(device_mac, action):
    response = requests.post(
        'http://opa:8181/v1/data/wifi6/allow',
        json={'input': {
            'action': action,
            'device': get_device_info(device_mac)
        }}
    )
    return response.json()['result']
```

## Monitoring

### Metrics to Track

- Authentication attempts (success/failure)
- Active connections
- OFDMA RU utilization
- MU-MIMO spatial stream usage
- TWT session count
- Bandwidth per device
- QoS violations

### Alerts

- Failed authentication threshold exceeded
- Unusual traffic patterns
- Capacity approaching limit
- Security protocol downgrade attempts

## Next Steps

- Explore [WiFi 7 (802.11be)](../wifi7/) for multi-link operation
- Check [WiFi Enterprise](../wifi-enterprise/) for RADIUS/802.1X
- Review [Continuous Monitoring](../../monitoring/wifi-monitoring/)

## References

- [IEEE 802.11ax Standard](https://standards.ieee.org/standard/802_11ax-2021.html)
- [WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)
- [WiFi Alliance Certification](https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-6)

## License

MIT
