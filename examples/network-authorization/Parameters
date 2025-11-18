# OPA Server Parameters - Complete Reference
## Authorization Framework for IoT & Wireless Protocols

---

## 1. INPUT PARAMETERS
*Sent with each authorization request to OPA (via input.* namespace)*

### 1.1 Device Identity Parameters
**Purpose:** Identify and authenticate the device making the request

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.device.mac_address` | string | "AA:BB:CC:DD:EE:FF" | ✅ Required | Device MAC address for identification |
| `input.device.spiffe_id` | string | "spiffe://example.org/workload/iot-device" | ✅ Required | SPIRE workload identity |
| `input.device.authenticated` | boolean | true | ✅ Required | Whether device has been authenticated |
| `input.device.device_type` | string | "enddevice", "gateway" | ⚠️ Context-dependent | Type of device (enddevice/gateway) |
| `input.device.authorized` | boolean | true | ⚠️ Context-dependent | Whether device is authorized |
| `input.device.current_state` | string | "authorized", "AUTHORIZED" | ⚠️ Context-dependent | Current authorization state |
| `input.device.mode` | string | "read", "write", "read/write" | 🔵 Optional | Device capability mode |
| `input.device.temporary_access` | boolean | true | 🔵 Optional | Whether device has temporary access |
| `input.device.auth_time` | string (RFC3339) | "2025-11-18T10:30:00Z" | 🔵 Optional | Authentication timestamp for session management |

### 1.2 Request Parameters
**Purpose:** Define what action/resource is being requested

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.request.resource` | string | "home", "iot", "gateway" | ✅ Required | Resource being accessed |
| `input.request.action` | string | "read", "write", "control", "admin" | ⚠️ Context-dependent | Action being performed |
| `input.request.timestamp` | string (RFC3339) | "2025-11-18T10:30:00Z" | 🔵 Optional | Request timestamp |

### 1.3 Context Parameters
**Purpose:** Provide environmental and situational context for authorization decisions

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.context.source_ip` | string | "192.168.1.100" | 🔵 Optional | Source IP address of request |
| `input.context.session_active` | boolean | true | 🔵 Optional | Whether session is currently active |
| `input.context.development_mode` | boolean | false | 🔵 Optional | Development mode flag (allows bypass) |
| `input.context.emergency_access` | boolean | false | 🔵 Optional | Emergency access override flag |
| `input.context.admin_override_token` | string | "token-xyz123" | ⚠️ Context-dependent | Admin override token (required if emergency_access=true) |
| `input.context.failed_attempts` | integer | 2 | 🔵 Optional | Number of failed authentication attempts |
| `input.context.location_anomaly` | boolean | false | 🔵 Optional | Whether location is anomalous |

---

## 2. WiFi PROTOCOL PARAMETERS

### 2.1 WiFi Normal/Standard (802.11)
**Purpose:** Basic WiFi connectivity authorization

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11" | ✅ Required | WiFi standard version |
| `input.wifi.ssid` | string | "MyNetwork" | ✅ Required | Network SSID |
| `input.wifi.encryption` | string | "WPA2", "WPA3" | ✅ Required | Encryption protocol |
| `input.wifi.authentication_method` | string | "PSK", "EAP" | ✅ Required | Authentication method |
| `input.wifi.channel` | integer | 6 | 🔵 Optional | WiFi channel number |
| `input.wifi.frequency_band` | string | "2.4GHz", "5GHz" | 🔵 Optional | Frequency band |

### 2.2 WiFi 4 (802.11n)
**Purpose:** WiFi 4 specific features and capabilities

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11n" | ✅ Required | WiFi 4 standard |
| `input.wifi.mimo_enabled` | boolean | true | 🔵 Optional | MIMO technology support |
| `input.wifi.channel_width` | integer | 40 | 🔵 Optional | Channel width in MHz (20/40) |
| `input.wifi.max_speed_mbps` | integer | 600 | 🔵 Optional | Maximum speed capability |

### 2.3 WiFi 5 (802.11ac)
**Purpose:** WiFi 5 specific features and authorization

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11ac" | ✅ Required | WiFi 5 standard |
| `input.wifi.mu_mimo_enabled` | boolean | true | 🔵 Optional | MU-MIMO support |
| `input.wifi.beamforming` | boolean | true | 🔵 Optional | Beamforming capability |
| `input.wifi.channel_width` | integer | 80 | 🔵 Optional | Channel width (20/40/80/160) |

### 2.4 WiFi 6 (802.11ax)
**Purpose:** WiFi 6 features including OFDMA and TWT

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11ax" | ✅ Required | WiFi 6 standard |
| `input.wifi.ofdma_enabled` | boolean | true | 🔵 Optional | OFDMA support |
| `input.wifi.twt_enabled` | boolean | true | 🔵 Optional | Target Wake Time support |
| `input.wifi.bss_coloring` | boolean | true | 🔵 Optional | BSS coloring for interference management |

### 2.5 WiFi 6E (802.11ax 6GHz)
**Purpose:** WiFi 6E with 6GHz band support

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11ax-6e" | ✅ Required | WiFi 6E standard |
| `input.wifi.frequency_band` | string | "6GHz" | ✅ Required | Must be 6GHz band |
| `input.wifi.afc_enabled` | boolean | true | 🔵 Optional | Automated Frequency Coordination |

### 2.6 WiFi 7 (802.11be)
**Purpose:** Next-gen WiFi 7 features and multi-link operation

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.standard` | string | "802.11be" | ✅ Required | WiFi 7 standard |
| `input.wifi.mlo_enabled` | boolean | true | 🔵 Optional | Multi-Link Operation |
| `input.wifi.channel_width` | integer | 320 | 🔵 Optional | Up to 320 MHz channels |
| `input.wifi.4k_qam` | boolean | true | 🔵 Optional | 4096-QAM support |

### 2.7 WiFi Ad-hoc (IBSS)
**Purpose:** Peer-to-peer WiFi connections without AP

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.mode` | string | "ad-hoc", "IBSS" | ✅ Required | Ad-hoc/IBSS mode |
| `input.wifi.peer_mac` | string | "AA:BB:CC:DD:EE:FF" | ✅ Required | Peer device MAC address |
| `input.wifi.bssid` | string | "00:11:22:33:44:55" | ✅ Required | BSSID for ad-hoc network |

### 2.8 WiFi Enterprise (802.1X/EAP)
**Purpose:** Enterprise authentication with RADIUS server

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.wifi.enterprise_mode` | boolean | true | ✅ Required | Enterprise authentication flag |
| `input.wifi.eap_method` | string | "EAP-TLS", "PEAP", "EAP-TTLS" | ✅ Required | EAP authentication method |
| `input.wifi.radius_server` | string | "radius.example.com" | ✅ Required | RADIUS server address |
| `input.wifi.certificate_cn` | string | "device-cert-001" | ⚠️ Context-dependent | Certificate Common Name (for EAP-TLS) |
| `input.wifi.username` | string | "user@example.com" | ⚠️ Context-dependent | Username (for PEAP/TTLS) |
| `input.wifi.vlan_id` | integer | 100 | 🔵 Optional | VLAN assignment |

---

## 3. BLUETOOTH LOW ENERGY (BLE) PARAMETERS

### 3.1 BLE 4.0
**Purpose:** First generation BLE authorization

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "4.0" | ✅ Required | BLE version |
| `input.ble.address` | string | "AA:BB:CC:DD:EE:FF" | ✅ Required | BLE device address |
| `input.ble.address_type` | string | "public", "random" | ✅ Required | Address type |
| `input.ble.advertising_interval_ms` | integer | 100 | 🔵 Optional | Advertising interval |
| `input.ble.connection_interval_ms` | integer | 50 | 🔵 Optional | Connection interval |

### 3.2 BLE 4.1
**Purpose:** BLE 4.1 with dual-mode topology

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "4.1" | ✅ Required | BLE version |
| `input.ble.role` | string | "central", "peripheral", "both" | ✅ Required | Device role |
| `input.ble.concurrent_connections` | integer | 4 | 🔵 Optional | Number of concurrent connections |

### 3.3 BLE 4.2
**Purpose:** BLE 4.2 with enhanced security and data length

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "4.2" | ✅ Required | BLE version |
| `input.ble.le_secure_connections` | boolean | true | ✅ Required | Secure connections support |
| `input.ble.data_length_extension` | boolean | true | 🔵 Optional | Extended data length support |
| `input.ble.privacy_enabled` | boolean | true | 🔵 Optional | Privacy feature enabled |

### 3.4 BLE 5.0
**Purpose:** BLE 5.0 with extended range and speed

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "5.0" | ✅ Required | BLE version |
| `input.ble.phy_mode` | string | "1M", "2M", "coded" | ✅ Required | PHY mode |
| `input.ble.extended_advertising` | boolean | true | 🔵 Optional | Extended advertising support |
| `input.ble.periodic_advertising` | boolean | true | 🔵 Optional | Periodic advertising |
| `input.ble.max_tx_power_dbm` | integer | 10 | 🔵 Optional | Maximum transmission power |

### 3.5 BLE 5.1
**Purpose:** Direction finding and antenna arrays

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "5.1" | ✅ Required | BLE version |
| `input.ble.direction_finding` | boolean | true | 🔵 Optional | Direction finding support |
| `input.ble.aoa_enabled` | boolean | true | 🔵 Optional | Angle of Arrival |
| `input.ble.aod_enabled` | boolean | true | 🔵 Optional | Angle of Departure |

### 3.6 BLE 5.2
**Purpose:** LE Audio and isochronous channels

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "5.2" | ✅ Required | BLE version |
| `input.ble.le_audio_enabled` | boolean | true | 🔵 Optional | LE Audio support |
| `input.ble.isochronous_channels` | boolean | true | 🔵 Optional | Isochronous channels |
| `input.ble.eatt_enabled` | boolean | true | 🔵 Optional | Enhanced ATT |

### 3.7 BLE 5.3
**Purpose:** Connection subrating and channel classification

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "5.3" | ✅ Required | BLE version |
| `input.ble.connection_subrating` | boolean | true | 🔵 Optional | Connection subrating support |
| `input.ble.periodic_advertising_adi` | boolean | true | 🔵 Optional | Periodic advertising with ADI |

### 3.8 BLE 5.4
**Purpose:** Latest BLE features and improvements

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.ble.version` | string | "5.4" | ✅ Required | BLE version |
| `input.ble.pawr_enabled` | boolean | true | 🔵 Optional | Periodic Advertising with Responses |
| `input.ble.encrypted_advertising` | boolean | true | 🔵 Optional | Encrypted advertising data |

---

## 4. BLUETOOTH CLASSIC PARAMETERS

### 4.1 Bluetooth 2.0 + EDR
**Purpose:** Classic Bluetooth with Enhanced Data Rate

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.bluetooth.version` | string | "2.0+EDR" | ✅ Required | Bluetooth version |
| `input.bluetooth.address` | string | "AA:BB:CC:DD:EE:FF" | ✅ Required | Bluetooth device address |
| `input.bluetooth.device_class` | string | "0x1F00" | ✅ Required | Device class |
| `input.bluetooth.edr_enabled` | boolean | true | 🔵 Optional | Enhanced Data Rate |
| `input.bluetooth.max_speed_mbps` | integer | 3 | 🔵 Optional | Maximum speed |

### 4.2 Bluetooth 3.0 + HS
**Purpose:** High-Speed Bluetooth with WiFi co-location

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.bluetooth.version` | string | "3.0+HS" | ✅ Required | Bluetooth version |
| `input.bluetooth.hs_enabled` | boolean | true | 🔵 Optional | High-Speed support |
| `input.bluetooth.wifi_coexistence` | boolean | true | 🔵 Optional | WiFi co-location |

### 4.3 Bluetooth 4.0 (Classic)
**Purpose:** Bluetooth 4.0 classic mode

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.bluetooth.version` | string | "4.0" | ✅ Required | Bluetooth version |
| `input.bluetooth.low_energy_support` | boolean | true | 🔵 Optional | BLE support in dual-mode |
| `input.bluetooth.secure_simple_pairing` | boolean | true | ✅ Required | SSP support |

### 4.4 Bluetooth 5.0 (Classic)
**Purpose:** Latest classic Bluetooth features

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.bluetooth.version` | string | "5.0" | ✅ Required | Bluetooth version |
| `input.bluetooth.slot_availability_mask` | boolean | true | 🔵 Optional | SAM support |
| `input.bluetooth.higher_tx_power` | boolean | true | 🔵 Optional | Increased transmit power |

---

## 5. ZIGBEE PARAMETERS

### 5.1 Zigbee 3.0
**Purpose:** Unified Zigbee standard for IoT

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.zigbee.version` | string | "3.0" | ✅ Required | Zigbee version |
| `input.zigbee.eui64` | string | "00:11:22:33:44:55:66:77" | ✅ Required | Extended Unique Identifier |
| `input.zigbee.node_type` | string | "coordinator", "router", "end_device" | ✅ Required | Node type in network |
| `input.zigbee.pan_id` | string | "0x1234" | ✅ Required | Personal Area Network ID |
| `input.zigbee.network_key` | string | "encrypted_key_hash" | ✅ Required | Network encryption key (hashed) |
| `input.zigbee.channel` | integer | 15 | ✅ Required | Zigbee channel (11-26) |
| `input.zigbee.security_level` | integer | 5 | ✅ Required | Security level (0-7) |
| `input.zigbee.trust_center_address` | string | "0x0000" | ⚠️ Context-dependent | Trust center address |

### 5.2 Zigbee PRO
**Purpose:** Professional Zigbee with advanced features

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.zigbee.version` | string | "PRO" | ✅ Required | Zigbee PRO version |
| `input.zigbee.green_power_enabled` | boolean | true | 🔵 Optional | Green Power feature |
| `input.zigbee.frequency_agility` | boolean | true | 🔵 Optional | Dynamic channel switching |
| `input.zigbee.fragmentation_enabled` | boolean | true | 🔵 Optional | Packet fragmentation |
| `input.zigbee.max_children` | integer | 20 | 🔵 Optional | Maximum child nodes |

---

## 6. LoRa/LoRaWAN PARAMETERS

### 6.1 LoRa Class A
**Purpose:** Basic bi-directional end-device

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.protocol` | string | "LoRaWAN" | ✅ Required | Protocol type |
| `input.lora.class` | string | "A" | ✅ Required | Device class |
| `input.lora.dev_eui` | string | "0011223344556677" | ✅ Required | Device EUI |
| `input.lora.app_eui` | string | "7766554433221100" | ✅ Required | Application EUI |
| `input.lora.dev_addr` | string | "12345678" | ✅ Required | Device address |
| `input.lora.spreading_factor` | integer | 7 | ✅ Required | Spreading factor (7-12) |
| `input.lora.frequency_mhz` | float | 868.1 | ✅ Required | Frequency in MHz |
| `input.lora.bandwidth_khz` | integer | 125 | ✅ Required | Bandwidth (125/250/500) |

### 6.2 LoRa Class B
**Purpose:** Scheduled receive windows

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.class` | string | "B" | ✅ Required | Device class |
| `input.lora.beacon_enabled` | boolean | true | ✅ Required | Beacon reception |
| `input.lora.ping_slot_periodicity` | integer | 4 | ✅ Required | Ping slot period |

### 6.3 LoRa Class C
**Purpose:** Continuously listening end-device

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.class` | string | "C" | ✅ Required | Device class |
| `input.lora.continuous_rx` | boolean | true | ✅ Required | Continuous receive mode |

### 6.4 LoRaWAN 1.0
**Purpose:** Original LoRaWAN specification

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.version` | string | "1.0" | ✅ Required | LoRaWAN version |
| `input.lora.activation_method` | string | "OTAA", "ABP" | ✅ Required | Activation method |
| `input.lora.nwk_skey` | string | "encrypted_key" | ⚠️ Context-dependent | Network session key (for ABP) |
| `input.lora.app_skey` | string | "encrypted_key" | ⚠️ Context-dependent | Application session key (for ABP) |

### 6.5 LoRaWAN 1.0.3
**Purpose:** Enhanced LoRaWAN 1.0

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.version` | string | "1.0.3" | ✅ Required | LoRaWAN version |
| `input.lora.rx_delay` | integer | 1 | 🔵 Optional | Receive delay in seconds |
| `input.lora.confirmed_uplink` | boolean | false | 🔵 Optional | Confirmed uplink messages |

### 6.6 LoRaWAN 1.1
**Purpose:** Latest LoRaWAN with improved security

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.lora.version` | string | "1.1" | ✅ Required | LoRaWAN version |
| `input.lora.join_eui` | string | "0011223344556677" | ✅ Required | Join EUI (replaces AppEUI) |
| `input.lora.fnwk_s_int_key` | string | "encrypted_key" | ⚠️ Context-dependent | Forwarding network session integrity key |
| `input.lora.snwk_s_int_key` | string | "encrypted_key" | ⚠️ Context-dependent | Serving network session integrity key |
| `input.lora.nwk_s_enc_key` | string | "encrypted_key" | ⚠️ Context-dependent | Network session encryption key |
| `input.lora.roaming_enabled` | boolean | false | 🔵 Optional | Roaming support |

---

## 7. SPIRE INTEGRATION PARAMETERS

### 7.1 SPIRE Workload Identity
**Purpose:** Service mesh authentication with SPIFFE

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.spire.spiffe_id` | string | "spiffe://example.org/workload/gateway" | ✅ Required | SPIFFE ID of workload |
| `input.spire.trust_domain` | string | "example.org" | ✅ Required | Trust domain |
| `input.spire.svid_serial` | string | "123456789" | ✅ Required | SVID serial number |
| `input.spire.svid_expiry` | string (RFC3339) | "2025-11-19T10:30:00Z" | ✅ Required | SVID expiration time |
| `input.spire.workload_path` | string | "/workload/gateway" | ✅ Required | Workload path |
| `input.spire.parent_id` | string | "spiffe://example.org/node" | 🔵 Optional | Parent SPIFFE ID |
| `input.spire.selectors` | array[string] | ["k8s:namespace:default"] | 🔵 Optional | Workload selectors |
| `input.spire.federated` | boolean | false | 🔵 Optional | Federated identity |
| `input.spire.federation_bundle` | string | "trust-bundle-hash" | ⚠️ Context-dependent | Federation trust bundle |

### 7.2 SPIRE Node Attestation
**Purpose:** Node-level attestation and registration

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.spire.node_id` | string | "node-001" | ✅ Required | Node identifier |
| `input.spire.attestation_type` | string | "k8s_psat", "x509pop", "aws_iid" | ✅ Required | Attestation method |
| `input.spire.node_selectors` | array[string] | ["k8s:node-name:worker-1"] | ✅ Required | Node selectors |

---

## 8. OPENZITI PARAMETERS

### 8.1 OpenZiti Service Authorization
**Purpose:** Zero-trust network overlay authorization

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.openziti.identity_id` | string | "identity-abc123" | ✅ Required | OpenZiti identity ID |
| `input.openziti.service_id` | string | "service-xyz789" | ✅ Required | Service ID being accessed |
| `input.openziti.service_name` | string | "iot-gateway-api" | ✅ Required | Service name |
| `input.openziti.edge_router_id` | string | "router-001" | ✅ Required | Edge router handling connection |
| `input.openziti.posture_checks` | array[string] | ["os-check", "domain-check"] | ✅ Required | Posture check results |
| `input.openziti.policy_type` | string | "dial", "bind" | ✅ Required | Policy type (dial/bind) |
| `input.openziti.encryption_required` | boolean | true | ✅ Required | End-to-end encryption requirement |
| `input.openziti.app_wan_enabled` | boolean | true | 🔵 Optional | Application WAN feature |

### 8.2 OpenZiti Identity Attributes
**Purpose:** Identity-based access control attributes

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.openziti.identity_type` | string | "device", "user", "service" | ✅ Required | Type of identity |
| `input.openziti.role_attributes` | array[string] | ["#iot-devices", "#admin"] | 🔵 Optional | Role attributes |
| `input.openziti.authentication_method` | string | "updb", "cert", "oidc" | ✅ Required | Authentication method used |
| `input.openziti.enrollment_method` | string | "ott", "ottca", "ca" | 🔵 Optional | Enrollment method |

---

## 9. ZERO TRUST PARAMETERS

### 9.1 Device Trust Score
**Purpose:** Continuous device trust evaluation

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.zero_trust.trust_score` | integer | 85 | ✅ Required | Device trust score (0-100) |
| `input.zero_trust.last_verified` | string (RFC3339) | "2025-11-18T10:00:00Z" | ✅ Required | Last verification timestamp |
| `input.zero_trust.verification_method` | string | "tpm", "secure_boot", "attestation" | ✅ Required | Verification method |
| `input.zero_trust.firmware_version` | string | "v2.3.1" | ✅ Required | Device firmware version |
| `input.zero_trust.hardware_id` | string | "hw-12345" | ✅ Required | Hardware identifier |
| `input.zero_trust.compliance_status` | string | "compliant", "non-compliant", "unknown" | ✅ Required | Compliance status |

### 9.2 Continuous Validation
**Purpose:** Real-time security posture validation

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.zero_trust.patch_level` | string | "2025-11" | ✅ Required | Security patch level |
| `input.zero_trust.threat_detected` | boolean | false | ✅ Required | Active threat detection flag |
| `input.zero_trust.last_scan_time` | string (RFC3339) | "2025-11-18T09:00:00Z" | 🔵 Optional | Last security scan |
| `input.zero_trust.risk_factors` | array[string] | ["outdated_firmware"] | 🔵 Optional | Identified risk factors |

---

## 10. CONTINUOUS MONITORING PARAMETERS

### 10.1 Anomaly Detection
**Purpose:** Behavioral anomaly detection and response

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.monitoring.anomaly_detected` | boolean | false | ✅ Required | Anomaly detection flag |
| `input.monitoring.anomaly_type` | string | "traffic", "behavior", "location" | ⚠️ Context-dependent | Type of anomaly |
| `input.monitoring.anomaly_severity` | string | "low", "medium", "high", "critical" | ⚠️ Context-dependent | Severity level |
| `input.monitoring.baseline_deviation` | float | 2.5 | 🔵 Optional | Standard deviations from baseline |
| `input.monitoring.traffic_pattern` | string | "normal", "suspicious", "malicious" | 🔵 Optional | Traffic pattern classification |

### 10.2 Security Events
**Purpose:** Security event tracking and correlation

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.monitoring.event_id` | string | "evt-123456" | 🔵 Optional | Event identifier |
| `input.monitoring.event_type` | string | "failed_auth", "privilege_escalation" | 🔵 Optional | Type of security event |
| `input.monitoring.event_timestamp` | string (RFC3339) | "2025-11-18T10:30:00Z" | 🔵 Optional | Event occurrence time |
| `input.monitoring.correlation_id` | string | "corr-789" | 🔵 Optional | Event correlation ID |

### 10.3 Performance Metrics
**Purpose:** Device and network performance monitoring

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `input.monitoring.cpu_usage_percent` | integer | 45 | 🔵 Optional | CPU usage percentage |
| `input.monitoring.memory_usage_percent` | integer | 60 | 🔵 Optional | Memory usage percentage |
| `input.monitoring.network_latency_ms` | integer | 25 | 🔵 Optional | Network latency |
| `input.monitoring.packet_loss_percent` | float | 0.5 | 🔵 Optional | Packet loss percentage |
| `input.monitoring.uptime_hours` | integer | 168 | 🔵 Optional | Device uptime in hours |

---

## 11. DATA PARAMETERS
*Stored in OPA's data store (via data.* namespace) - loaded at startup or via bundles*

### 11.1 Device Registry Data
**Purpose:** Maintain registry of authorized devices

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.registered_enddevices` | set[string] | {"aabbccddeeff", "112233445566"} | ✅ Required | Set of registered end device MAC addresses (lowercase, no colons) |
| `data.registered_gateways` | set[string] | {"ffeeddccbbaa", "665544332211"} | ✅ Required | Set of registered gateway MAC addresses |

### 11.2 Device Capabilities Data
**Purpose:** Define device-specific capabilities and permissions

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.device_capabilities[mac].device_type` | string | "enddevice", "gateway" | ✅ Required | Device type classification |
| `data.device_capabilities[mac].mode` | string | "read", "write", "read/write" | ✅ Required | Device access mode |
| `data.device_capabilities[mac].capabilities.read` | boolean | true | ✅ Required | Read capability flag |
| `data.device_capabilities[mac].capabilities.write` | boolean | true | ✅ Required | Write capability flag |
| `data.device_capabilities[mac].capabilities.control` | boolean | false | ✅ Required | Control capability flag (typically gateway-only) |
| `data.device_capabilities[mac].capabilities.monitor` | boolean | true | 🔵 Optional | Monitoring capability |

### 11.3 WiFi Network Registry
**Purpose:** Authorized WiFi networks and configurations

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.wifi_networks[ssid].encryption` | string | "WPA3", "WPA2-Enterprise" | ✅ Required | Network encryption type |
| `data.wifi_networks[ssid].allowed_devices` | array[string] | ["aabbccddeeff"] | ✅ Required | Allowed device MAC addresses |
| `data.wifi_networks[ssid].vlan_id` | integer | 100 | 🔵 Optional | VLAN assignment |
| `data.wifi_networks[ssid].bandwidth_limit_mbps` | integer | 50 | 🔵 Optional | Bandwidth limit |

### 11.4 BLE Device Pairings
**Purpose:** Authorized BLE device pairings

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.ble_pairings[device_address].paired_devices` | array[string] | ["AA:BB:CC:DD:EE:FF"] | ✅ Required | List of paired device addresses |
| `data.ble_pairings[device_address].bond_status` | string | "bonded", "not_bonded" | ✅ Required | Bonding status |
| `data.ble_pairings[device_address].ltk` | string | "encrypted_long_term_key" | ⚠️ Context-dependent | Long-term key (encrypted) |

### 11.5 Zigbee Network Topology
**Purpose:** Zigbee network structure and relationships

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.zigbee_network.coordinator` | string | "00:11:22:33:44:55:66:77" | ✅ Required | Coordinator EUI-64 |
| `data.zigbee_network.pan_id` | string | "0x1234" | ✅ Required | Network PAN ID |
| `data.zigbee_network.routers` | array[string] | ["00:11:22:33:44:55:66:78"] | ✅ Required | List of router EUI-64s |
| `data.zigbee_network.end_devices` | array[string] | ["00:11:22:33:44:55:66:79"] | ✅ Required | List of end device EUI-64s |
| `data.zigbee_network.link_keys[eui64]` | string | "encrypted_key" | ⚠️ Context-dependent | Device link keys |

### 11.6 LoRaWAN Application Registry
**Purpose:** LoRaWAN application and device registrations

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.lorawan_apps[app_eui].name` | string | "IoT Sensors App" | ✅ Required | Application name |
| `data.lorawan_apps[app_eui].devices[dev_eui].dev_addr` | string | "12345678" | ✅ Required | Device address |
| `data.lorawan_apps[app_eui].devices[dev_eui].class` | string | "A", "B", "C" | ✅ Required | Device class |
| `data.lorawan_apps[app_eui].devices[dev_eui].keys.nwk_skey` | string | "encrypted_key" | ⚠️ Context-dependent | Network session key |
| `data.lorawan_apps[app_eui].devices[dev_eui].keys.app_skey` | string | "encrypted_key" | ⚠️ Context-dependent | Application session key |

### 11.7 SPIRE Workload Registry
**Purpose:** Registered SPIRE workloads and attestation policies

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.spire_workloads[spiffe_id].trust_domain` | string | "example.org" | ✅ Required | Trust domain |
| `data.spire_workloads[spiffe_id].selectors` | array[string] | ["k8s:namespace:default"] | ✅ Required | Workload selectors |
| `data.spire_workloads[spiffe_id].parent_id` | string | "spiffe://example.org/node" | ✅ Required | Parent SPIFFE ID |
| `data.spire_workloads[spiffe_id].ttl_seconds` | integer | 3600 | ✅ Required | SVID TTL |
| `data.spire_workloads[spiffe_id].federated_bundles` | array[string] | ["other-domain.org"] | 🔵 Optional | Federated trust domains |

### 11.8 OpenZiti Services and Policies
**Purpose:** OpenZiti service definitions and access policies

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.openziti_services[service_id].name` | string | "iot-gateway-api" | ✅ Required | Service name |
| `data.openziti_services[service_id].endpoint_address` | string | "tcp:gateway.local:8080" | ✅ Required | Service endpoint |
| `data.openziti_services[service_id].encryption_required` | boolean | true | ✅ Required | Encryption requirement |
| `data.openziti_services[service_id].role_attributes` | array[string] | ["#iot-devices"] | 🔵 Optional | Service role attributes |
| `data.openziti_policies[policy_id].type` | string | "dial", "bind" | ✅ Required | Policy type |
| `data.openziti_policies[policy_id].identity_roles` | array[string] | ["#iot-devices"] | ✅ Required | Allowed identity roles |
| `data.openziti_policies[policy_id].service_roles` | array[string] | ["#gateway-services"] | ✅ Required | Allowed service roles |

### 11.9 Zero Trust Baselines
**Purpose:** Security baselines and compliance requirements

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.zero_trust_baselines.min_trust_score` | integer | 70 | ✅ Required | Minimum required trust score |
| `data.zero_trust_baselines.required_firmware_versions[device_type]` | string | "v2.3.0" | ✅ Required | Minimum firmware version |
| `data.zero_trust_baselines.max_verification_age_hours` | integer | 24 | ✅ Required | Maximum time since last verification |
| `data.zero_trust_baselines.mandatory_checks` | array[string] | ["tpm", "secure_boot"] | ✅ Required | Required verification checks |

### 11.10 Threat Intelligence Data
**Purpose:** Known threats, indicators of compromise

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.threat_intel.blocked_ips` | set[string] | {"192.168.1.100", "10.0.0.50"} | ✅ Required | Blocked IP addresses |
| `data.threat_intel.blocked_mac_addresses` | set[string] | {"aabbccddeeff"} | ✅ Required | Blocked MAC addresses |
| `data.threat_intel.malicious_signatures` | array[string] | ["signature-123"] | 🔵 Optional | Known malicious signatures |
| `data.threat_intel.geo_restrictions` | array[string] | ["CN", "RU"] | 🔵 Optional | Geo-location restrictions |

### 11.11 Rate Limiting Data
**Purpose:** Rate limiting and quota management

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `data.rate_limits[device_mac].requests_per_hour` | integer | 1000 | ✅ Required | Maximum requests per hour |
| `data.rate_limits[device_mac].burst_size` | integer | 50 | ✅ Required | Burst size allowance |
| `data.rate_limits[device_mac].current_count` | integer | 245 | ⚠️ Context-dependent | Current request count (updated externally) |

---

## 12. OPA SERVER CONFIGURATION PARAMETERS
*Server setup and runtime configuration*

### 12.1 Server Configuration
**Purpose:** OPA server deployment configuration

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `--addr` | string | "0.0.0.0:8181" | ✅ Required | HTTP server address |
| `--diagnostic-addr` | string | "0.0.0.0:8282" | 🔵 Optional | Diagnostic/health check address |
| `--config-file` | string | "/etc/opa/config.yaml" | ⚠️ Context-dependent | Configuration file path |
| `--bundle` | string | "https://bundle-server/bundle.tar.gz" | ⚠️ Context-dependent | Bundle URL (if using bundles) |
| `--log-level` | string | "info", "debug", "error" | 🔵 Optional | Logging level |
| `--log-format` | string | "json", "text" | 🔵 Optional | Log output format |

### 12.2 Bundle Configuration
**Purpose:** Policy and data bundle management

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `services[].url` | string | "https://bundle-server.example.com" | ⚠️ Context-dependent | Bundle service URL |
| `bundles[].resource` | string | "/bundles/iot-policies" | ⚠️ Context-dependent | Bundle resource path |
| `bundles[].polling.min_delay_seconds` | integer | 60 | 🔵 Optional | Minimum polling delay |
| `bundles[].polling.max_delay_seconds` | integer | 120 | 🔵 Optional | Maximum polling delay |

### 12.3 Decision Logging
**Purpose:** Audit logging configuration

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `decision_logs.console` | boolean | true | 🔵 Optional | Log decisions to console |
| `decision_logs.service` | string | "decision-log-server" | 🔵 Optional | Remote logging service |
| `decision_logs.reporting.max_decisions_per_second` | integer | 10 | 🔵 Optional | Rate limit for decision logs |

### 12.4 Discovery Configuration
**Purpose:** OPA management and discovery service

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `discovery.resource` | string | "/discovery" | ⚠️ Context-dependent | Discovery resource path |
| `discovery.service` | string | "control-plane" | ⚠️ Context-dependent | Discovery service name |
| `discovery.polling.min_delay_seconds` | integer | 60 | 🔵 Optional | Discovery polling interval |

### 12.5 Status Reporting
**Purpose:** OPA status reporting to management plane

| Parameter | Type | Example | Required | Description |
|-----------|------|---------|----------|-------------|
| `status.console` | boolean | false | 🔵 Optional | Log status to console |
| `status.service` | string | "status-service" | 🔵 Optional | Remote status service |
| `status.partition_name` | string | "iot-policies" | 🔵 Optional | Status partition identifier |

---

## LEGEND

- ✅ **Required**: Must always be provided for the policy to function
- ⚠️ **Context-dependent**: Required only in specific scenarios (e.g., emergency access, ABP activation)
- 🔵 **Optional**: Enhances functionality but not strictly required

---

## NOTES

1. **MAC Address Format**: All MAC addresses should be cleaned (lowercase, no colons) when used as keys in data structures
2. **Timestamps**: Use RFC3339 format for all timestamp fields (e.g., "2025-11-18T10:30:00Z")
3. **Encryption Keys**: Never store plaintext keys; always use encrypted/hashed representations
4. **IP Addresses**: Support both IPv4 and IPv6 formats
5. **Array vs Set**: Sets are used for unique collections (e.g., registered devices), arrays for ordered lists
6. **Bundle Updates**: Data parameters can be updated dynamically via OPA bundles without server restart
7. **Session Management**: Temporal parameters (auth_time, expiry times) are critical for session security
8. **Zero Trust**: Trust scores and verification states should be continuously updated
9. **Protocol-Specific**: Each wireless protocol has unique parameters; only relevant ones need to be provided per request

---

**Generated for:** fmfalgun/autherization repository  
**Policy Version:** V3 Authorization Framework  
**Last Updated:** 2025-11-18
