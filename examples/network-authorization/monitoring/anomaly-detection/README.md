# Continuous Monitoring & Anomaly Detection

Comprehensive OPA-based authorization policies for network monitoring nodes that sniff WiFi, BLE, Bluetooth, Zigbee, and LoRa networks. Validates monitoring data and authorizes security actions.

## Overview

This monitoring module acts as an authorization layer between network sniffing nodes and the security response system. It ensures:

1. **Monitoring Node Validation**: Only authorized sniffers can report data
2. **Data Integrity Verification**: Reported metrics are authentic and unmodified
3. **Action Authorization**: Security responses (alerts, blocks, database writes) are justified
4. **Anomaly Detection**: ML-based and rule-based anomaly identification

## Architecture

```
┌─────────────────────────────────────────┐
│     Network Sniffing Nodes              │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │
│  │ WiFi │ │ BLE  │ │ BT   │ │Zigbee│   │
│  └───┬──┘ └───┬──┘ └───┬──┘ └───┬──┘   │
└──────┼────────┼────────┼────────┼───────┘
       │        │        │        │
       ▼        ▼        ▼        ▼
┌──────────────────────────────────────────┐
│   Monitoring Authorization (OPA)         │
│   - Validate node identity               │
│   - Verify data signature                │
│   - Authorize actions                    │
└────────┬─────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│       Security Response System           │
│   - Database updates                     │
│   - Admin alerts                         │
│   - Device blocking                      │
│   - Warning markers                      │
└──────────────────────────────────────────┘
```

## Monitored Networks

| Network Type | Sniffed Data | Anomalies Detected |
|--------------|--------------|---------------------|
| **WiFi** | Deauth attacks, rogue APs, weak encryption | Unusual signal patterns, Evil Twin APs |
| **BLE** | Pairing attempts, advertising floods | Spoofed beacons, replay attacks |
| **Bluetooth** | Connection attempts, service discovery | Bluejacking, bluesnarfing |
| **Zigbee** | Join requests, command injection | Unauthorized coordinators, key compromise |
| **LoRa** | Join-accept tampering, replay | ABP attacks, downlink injection |

## Authorization Scenarios

### 1. Monitoring Node Registration

Sniffing nodes must register before sending data:

```rego
# Why: Prevents rogue nodes from injecting false monitoring data
allow {
    input.action == "register_node"
    input.node.certificate != null
    certificate_valid(input.node.certificate)
    node_location_verified(input.node)
}
```

### 2. Report Metrics

Nodes report network metrics (signal strength, device counts, errors):

```rego
# Why: Ensures monitoring data comes from legitimate, authenticated sources
allow {
    input.action == "report_metrics"
    registered_node(input.node_id)
    data_signature_valid(input.data, input.signature)
    metrics_within_expected_range(input.data)
}
```

### 3. Report Anomaly

Nodes detect and report suspicious activity:

```rego
# Why: Validates that anomaly reports are genuine before triggering responses
allow {
    input.action == "report_anomaly"
    registered_node(input.node_id)
    anomaly_severity_justified(input.anomaly)
    not false_positive_pattern(input.anomaly)
}
```

### 4. Database Write Authorization

Store monitoring data in database:

```rego
# Why: Prevents unauthorized database modifications or data corruption
allow {
    input.action == "write_database"
    registered_node(input.node_id)
    input.operation in ["insert", "update"]
    data_schema_valid(input.data)
    not exceeds_rate_limit(input.node_id)
}
```

### 5. Send Admin Alert

Trigger alerts for critical events:

```rego
# Why: Prevents alert fatigue by ensuring only serious anomalies generate alerts
allow {
    input.action == "send_alert"
    registered_node(input.node_id)
    input.alert.severity in ["high", "critical"]
    anomaly_confidence_high(input.alert)
    not alert_recently_sent(input.alert.type)
}
```

### 6. Mark Warning

Add warning markers to devices:

```rego
# Why: Tracks suspicious but not yet confirmed malicious devices
allow {
    input.action == "mark_warning"
    registered_node(input.node_id)
    device_exists(input.device_id)
    warning_justified(input.warning)
}
```

### 7. Block Device

Permanently or temporarily block devices:

```rego
# Why: Serious action requiring strong justification to prevent DoS
allow {
    input.action == "block_device"
    registered_node(input.node_id)
    input.block.severity == "critical"
    anomaly_confirmed(input.device_id, input.anomaly)
    admin_notified(input.block)
}
```

## Anomaly Types

### WiFi Anomalies

```json
{
  "deauth_flood": {
    "description": "Excessive deauthentication frames",
    "threshold": "100 deauths/minute",
    "severity": "high",
    "action": "block_device"
  },
  "rogue_ap": {
    "description": "Unauthorized access point detected",
    "indicators": ["SSID spoofing", "Evil Twin", "Karma attack"],
    "severity": "critical",
    "action": "send_alert + block_device"
  },
  "weak_encryption": {
    "description": "WEP or unencrypted network",
    "severity": "medium",
    "action": "mark_warning"
  }
}
```

### BLE Anomalies

```json
{
  "advertising_flood": {
    "description": "Excessive BLE advertisements",
    "threshold": "1000 adverts/second",
    "severity": "medium",
    "action": "mark_warning"
  },
  "spoofed_beacon": {
    "description": "Fake iBeacon or Eddystone",
    "indicators": ["UUID spoofing", "RSSI manipulation"],
    "severity": "high",
    "action": "send_alert"
  }
}
```

### Bluetooth Anomalies

```json
{
  "bluejacking": {
    "description": "Unsolicited message sending",
    "severity": "low",
    "action": "mark_warning"
  },
  "bluesnarfing": {
    "description": "Unauthorized data access attempt",
    "severity": "critical",
    "action": "block_device + send_alert"
  }
}
```

### Zigbee Anomalies

```json
{
  "unauthorized_coordinator": {
    "description": "Rogue Zigbee coordinator",
    "severity": "critical",
    "action": "block_device + send_alert"
  },
  "key_compromise": {
    "description": "Network key possibly compromised",
    "indicators": ["Replay attacks", "Invalid MACs"],
    "severity": "critical",
    "action": "send_alert + regenerate_keys"
  }
}
```

### LoRa Anomalies

```json
{
  "join_replay": {
    "description": "Replayed join-request messages",
    "severity": "high",
    "action": "block_device"
  },
  "abp_attack": {
    "description": "ABP device key compromise",
    "severity": "critical",
    "action": "block_device + send_alert"
  }
}
```

## Quick Start

### Start Monitoring Authorization

```bash
# Start OPA server
make up

# Register a monitoring node
make register-node NODE_ID=wifi-sniffer-01

# Test anomaly report
make test-anomaly
```

### Example: WiFi Deauth Attack Detection

```bash
curl -X POST http://localhost:8181/v1/data/monitoring/allow \
  -d '{
    "input": {
      "action": "report_anomaly",
      "node_id": "wifi-sniffer-01",
      "anomaly": {
        "type": "deauth_flood",
        "device": "AA:BB:CC:DD:EE:FF",
        "count": 250,
        "duration_sec": 60,
        "severity": "high",
        "confidence": 0.95
      },
      "signature": "node_signature_here"
    }
  }'
```

### Example: Block Malicious Device

```bash
curl -X POST http://localhost:8181/v1/data/monitoring/allow \
  -d '{
    "input": {
      "action": "block_device",
      "node_id": "ble-sniffer-02",
      "device_id": "11:22:33:44:55:66",
      "block": {
        "type": "permanent",
        "severity": "critical",
        "reason": "bluesnarfing_detected",
        "evidence": {
          "anomaly_type": "bluesnarfing",
          "confidence": 0.98,
          "attempts": 15
        }
      },
      "admin_notification": "sent"
    }
  }'
```

## Monitoring Node Requirements

### Node Registration

Monitoring nodes must provide:

1. **Certificate**: X.509 certificate from trusted CA
2. **Location**: Physical location for correlation
3. **Capabilities**: Which protocols can be monitored
4. **Public Key**: For signature verification

```json
{
  "node_id": "wifi-sniffer-01",
  "certificate": {
    "subject": "CN=WiFi-Sniffer-01,O=Security-Org",
    "issuer": "CN=Monitoring-CA",
    "expiry": "2026-12-31",
    "fingerprint": "SHA256:abc123..."
  },
  "location": {
    "building": "HQ",
    "floor": 3,
    "room": "Network-Closet-3A"
  },
  "capabilities": ["wifi", "ble", "bluetooth"],
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

### Data Signature

All monitoring data must be signed:

```python
# Sign monitoring data
signature = sign_data(
    data=monitoring_metrics,
    private_key=node_private_key
)

# Send to OPA for authorization
response = requests.post(opa_url, json={
    'input': {
        'action': 'report_metrics',
        'node_id': node_id,
        'data': monitoring_metrics,
        'signature': signature
    }
})
```

## Security Actions

### Database Operations

Authorized database operations:

```sql
-- Insert anomaly record
INSERT INTO anomalies (device_id, type, severity, timestamp, node_id)
VALUES ('AA:BB:CC:DD:EE:FF', 'deauth_flood', 'high', NOW(), 'wifi-sniffer-01');

-- Update device trust score
UPDATE devices SET trust_score = trust_score - 10
WHERE mac = 'AA:BB:CC:DD:EE:FF';

-- Mark device with warning
INSERT INTO device_warnings (device_id, warning_type, expires_at)
VALUES ('AA:BB:CC:DD:EE:FF', 'suspicious_activity', NOW() + INTERVAL '7 days');
```

### Alert Channels

Alerts can be sent via:

- **Email**: Security team inbox
- **SMS**: For critical alerts
- **Slack/Teams**: Real-time notifications
- **SIEM Integration**: Splunk, ELK, etc.
- **Dashboard**: Real-time monitoring UI

### Device Blocking

Block mechanisms:

```python
# Temporary block (auto-expire)
block_device(
    device_id='AA:BB:CC:DD:EE:FF',
    duration_hours=24,
    reason='anomaly_detected'
)

# Permanent block (manual review required)
block_device(
    device_id='AA:BB:CC:DD:EE:FF',
    permanent=True,
    reason='confirmed_attack',
    approval_ticket='SEC-2025-001'
)
```

## Machine Learning Integration

### Anomaly Detection Models

```python
# Train model on normal traffic patterns
model = train_anomaly_detector(
    training_data=historical_metrics,
    algorithm='isolation_forest'
)

# Detect anomalies
anomaly_score = model.predict(current_metrics)

if anomaly_score > threshold:
    # Request authorization to report anomaly
    authorized = check_opa_permission(
        action='report_anomaly',
        confidence=anomaly_score
    )
```

### Behavioral Analysis

Tracks device behavior over time:

- Connection patterns
- Data transfer rates
- Roaming frequency
- Protocol usage

## Performance Metrics

### Monitoring Node Health

- **Uptime**: Node availability percentage
- **Latency**: Time from detection to report
- **Accuracy**: True positive/false positive ratio
- **Coverage**: Network area monitored

### Response Metrics

- **MTTD**: Mean Time To Detect anomaly
- **MTTR**: Mean Time To Respond
- **False Positive Rate**: % of incorrect alerts
- **Block Effectiveness**: % of threats neutralized

## Troubleshooting

**Node registration fails**
- Check certificate validity
- Verify CA is trusted
- Ensure node_id is unique

**Data signature invalid**
- Verify private/public key pair
- Check clock synchronization
- Ensure signature algorithm matches

**Alerts not sent**
- Check severity threshold
- Verify rate limiting not exceeded
- Ensure alert channel configured

## Integration Examples

### SIEM Integration

```python
# Forward to Splunk
def forward_to_siem(anomaly):
    if opa_authorize('forward_to_siem', anomaly):
        splunk.send_event({
            'sourcetype': 'network:anomaly',
            'event': anomaly
        })
```

### Firewall Integration

```python
# Block device at firewall
def firewall_block(device_id):
    if opa_authorize('block_device', device_id):
        firewall.add_rule(
            action='deny',
            source_mac=device_id
        )
```

## Next Steps

- Configure monitoring nodes for each network type
- Set up alert channels
- Tune anomaly detection thresholds
- Integrate with SIEM and firewall
- Review and adjust policies based on false positives

## License

MIT
