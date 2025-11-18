# 1. INPUT PARAMETERS

## 1.1 Device Identity Parameters
- input.device.mac_address
- input.device.spiffe_id
- input.device.authenticated
- input.device.device_type
- input.device.authorized
- input.device.current_state
- input.device.mode
- input.device.temporary_access
- input.device.auth_time

## 1.2 Request Parameters
- input.request.resource
- input.request.action
- input.request.timestamp

## 1.3 Context Parameters
- input.context.source_ip
- input.context.session_active
- input.context.development_mode
- input.context.emergency_access
- input.context.admin_override_token
- input.context.failed_attempts
- input.context.location_anomaly

---

# 2. WIFI PROTOCOL PARAMETERS

## 2.1 WiFi Normal/Standard (802.11)
- input.wifi.standard
- input.wifi.ssid
- input.wifi.encryption
- input.wifi.authentication_method
- input.wifi.channel
- input.wifi.frequency_band

## 2.2 WiFi 4 (802.11n)
- input.wifi.standard
- input.wifi.mimo_enabled
- input.wifi.channel_width
- input.wifi.max_speed_mbps

## 2.3 WiFi 5 (802.11ac)
- input.wifi.standard
- input.wifi.mu_mimo_enabled
- input.wifi.beamforming
- input.wifi.channel_width

## 2.4 WiFi 6 (802.11ax)
- input.wifi.standard
- input.wifi.ofdma_enabled
- input.wifi.twt_enabled
- input.wifi.bss_coloring

## 2.5 WiFi 6E (802.11ax 6GHz)
- input.wifi.standard
- input.wifi.frequency_band
- input.wifi.afc_enabled

## 2.6 WiFi 7 (802.11be)
- input.wifi.standard
- input.wifi.mlo_enabled
- input.wifi.channel_width
- input.wifi.4k_qam

## 2.7 WiFi Ad-hoc (IBSS)
- input.wifi.mode
- input.wifi.peer_mac
- input.wifi.bssid

## 2.8 WiFi Enterprise (802.1X/EAP)
- input.wifi.enterprise_mode
- input.wifi.eap_method
- input.wifi.radius_server
- input.wifi.certificate_cn
- input.wifi.username
- input.wifi.vlan_id

---

# 3. BLUETOOTH LOW ENERGY (BLE) PARAMETERS

## 3.1 BLE 4.0
- input.ble.version
- input.ble.address
- input.ble.address_type
- input.ble.advertising_interval_ms
- input.ble.connection_interval_ms

## 3.2 BLE 4.1
- input.ble.version
- input.ble.role
- input.ble.concurrent_connections

## 3.3 BLE 4.2
- input.ble.version
- input.ble.le_secure_connections
- input.ble.data_length_extension
- input.ble.privacy_enabled

## 3.4 BLE 5.0
- input.ble.version
- input.ble.phy_mode
- input.ble.extended_advertising
- input.ble.periodic_advertising
- input.ble.max_tx_power_dbm

## 3.5 BLE 5.1
- input.ble.version
- input.ble.direction_finding
- input.ble.aoa_enabled
- input.ble.aod_enabled

## 3.6 BLE 5.2
- input.ble.version
- input.ble.le_audio_enabled
- input.ble.isochronous_channels
- input.ble.eatt_enabled

## 3.7 BLE 5.3
- input.ble.version
- input.ble.connection_subrating
- input.ble.periodic_advertising_adi

## 3.8 BLE 5.4
- input.ble.version
- input.ble.pawr_enabled
- input.ble.encrypted_advertising

---

# 4. BLUETOOTH CLASSIC PARAMETERS

## 4.1 Bluetooth 2.0 + EDR
- input.bluetooth.version
- input.bluetooth.address
- input.bluetooth.device_class
- input.bluetooth.edr_enabled
- input.bluetooth.max_speed_mbps

## 4.2 Bluetooth 3.0 + HS
- input.bluetooth.version
- input.bluetooth.hs_enabled
- input.bluetooth.wifi_coexistence

## 4.3 Bluetooth 4.0 (Classic)
- input.bluetooth.version
- input.bluetooth.low_energy_support
- input.bluetooth.secure_simple_pairing

## 4.4 Bluetooth 5.0 (Classic)
- input.bluetooth.version
- input.bluetooth.slot_availability_mask
- input.bluetooth.higher_tx_power

---

# 5. ZIGBEE PARAMETERS

## 5.1 Zigbee 3.0
- input.zigbee.version
- input.zigbee.eui64
- input.zigbee.node_type
- input.zigbee.pan_id
- input.zigbee.network_key
- input.zigbee.channel
- input.zigbee.security_level
- input.zigbee.trust_center_address

## 5.2 Zigbee PRO
- input.zigbee.version
- input.zigbee.green_power_enabled
- input.zigbee.frequency_agility
- input.zigbee.fragmentation_enabled
- input.zigbee.max_children

---

# 6. LORA/LORAWAN PARAMETERS

## 6.1 LoRa Class A
- input.lora.protocol
- input.lora.class
- input.lora.dev_eui
- input.lora.app_eui
- input.lora.dev_addr
- input.lora.spreading_factor
- input.lora.frequency_mhz
- input.lora.bandwidth_khz

## 6.2 LoRa Class B
- input.lora.class
- input.lora.beacon_enabled
- input.lora.ping_slot_periodicity

## 6.3 LoRa Class C
- input.lora.class
- input.lora.continuous_rx

## 6.4 LoRaWAN 1.0
- input.lora.version
- input.lora.activation_method
- input.lora.nwk_skey
- input.lora.app_skey

## 6.5 LoRaWAN 1.0.3
- input.lora.version
- input.lora.rx_delay
- input.lora.confirmed_uplink

## 6.6 LoRaWAN 1.1
- input.lora.version
- input.lora.join_eui
- input.lora.fnwk_s_int_key
- input.lora.snwk_s_int_key
- input.lora.nwk_s_enc_key
- input.lora.roaming_enabled

---

# 7. SPIRE INTEGRATION PARAMETERS

## 7.1 SPIRE Workload Identity
- input.spire.spiffe_id
- input.spire.trust_domain
- input.spire.svid_serial
- input.spire.svid_expiry
- input.spire.workload_path
- input.spire.parent_id
- input.spire.selectors
- input.spire.federated
- input.spire.federation_bundle

## 7.2 SPIRE Node Attestation
- input.spire.node_id
- input.spire.attestation_type
- input.spire.node_selectors

---

# 8. OPENZITI PARAMETERS

## 8.1 OpenZiti Service Authorization
- input.openziti.identity_id
- input.openziti.service_id
- input.openziti.service_name
- input.openziti.edge_router_id
- input.openziti.posture_checks
- input.openziti.policy_type
- input.openziti.encryption_required
- input.openziti.app_wan_enabled

## 8.2 OpenZiti Identity Attributes
- input.openziti.identity_type
- input.openziti.role_attributes
- input.openziti.authentication_method
- input.openziti.enrollment_method

---

# 9. ZERO TRUST PARAMETERS

## 9.1 Device Trust Score
- input.zero_trust.trust_score
- input.zero_trust.last_verified
- input.zero_trust.verification_method
- input.zero_trust.firmware_version
- input.zero_trust.hardware_id
- input.zero_trust.compliance_status

## 9.2 Continuous Validation
- input.zero_trust.patch_level
- input.zero_trust.threat_detected
- input.zero_trust.last_scan_time
- input.zero_trust.risk_factors

---

# 10. CONTINUOUS MONITORING PARAMETERS

## 10.1 Anomaly Detection
- input.monitoring.anomaly_detected
- input.monitoring.anomaly_type
- input.monitoring.anomaly_severity
- input.monitoring.baseline_deviation
- input.monitoring.traffic_pattern

## 10.2 Security Events
- input.monitoring.event_id
- input.monitoring.event_type
- input.monitoring.event_timestamp
- input.monitoring.correlation_id

## 10.3 Performance Metrics
- input.monitoring.cpu_usage_percent
- input.monitoring.memory_usage_percent
- input.monitoring.network_latency_ms
- input.monitoring.packet_loss_percent
- input.monitoring.uptime_hours

---

# 11. DATA PARAMETERS

## 11.1 Device Registry Data
- data.registered_enddevices
- data.registered_gateways

## 11.2 Device Capabilities Data
- data.device_capabilities[mac].device_type
- data.device_capabilities[mac].mode
- data.device_capabilities[mac].capabilities.read
- data.device_capabilities[mac].capabilities.write
- data.device_capabilities[mac].capabilities.control
- data.device_capabilities[mac].capabilities.monitor

## 11.3 WiFi Network Registry
- data.wifi_networks[ssid].encryption
- data.wifi_networks[ssid].allowed_devices
- data.wifi_networks[ssid].vlan_id
- data.wifi_networks[ssid].bandwidth_limit_mbps

## 11.4 BLE Device Pairings
- data.ble_pairings[device_address].paired_devices
- data.ble_pairings[device_address].bond_status
- data.ble_pairings[device_address].ltk

## 11.5 Zigbee Network Topology
- data.zigbee_network.coordinator
- data.zigbee_network.pan_id
- data.zigbee_network.routers
- data.zigbee_network.end_devices
- data.zigbee_network.link_keys[eui64]

## 11.6 LoRaWAN Application Registry
- data.lorawan_apps[app_eui].name
- data.lorawan_apps[app_eui].devices[dev_eui].dev_addr
- data.lorawan_apps[app_eui].devices[dev_eui].class
- data.lorawan_apps[app_eui].devices[dev_eui].keys.nwk_skey
- data.lorawan_apps[app_eui].devices[dev_eui].keys.app_skey

## 11.7 SPIRE Workload Registry
- data.spire_workloads[spiffe_id].trust_domain
- data.spire_workloads[spiffe_id].selectors
- data.spire_workloads[spiffe_id].parent_id
- data.spire_workloads[spiffe_id].ttl_seconds
- data.spire_workloads[spiffe_id].federated_bundles

## 11.8 OpenZiti Services and Policies
- data.openziti_services[service_id].name
- data.openziti_services[service_id].endpoint_address
- data.openziti_services[service_id].encryption_required
- data.openziti_services[service_id].role_attributes
- data.openziti_policies[policy_id].type
- data.openziti_policies[policy_id].identity_roles
- data.openziti_policies[policy_id].service_roles

## 11.9 Zero Trust Baselines
- data.zero_trust_baselines.min_trust_score
- data.zero_trust_baselines.required_firmware_versions[device_type]
- data.zero_trust_baselines.max_verification_age_hours
- data.zero_trust_baselines.mandatory_checks

## 11.10 Threat Intelligence Data
- data.threat_intel.blocked_ips
- data.threat_intel.blocked_mac_addresses
- data.threat_intel.malicious_signatures
- data.threat_intel.geo_restrictions

## 11.11 Rate Limiting Data
- data.rate_limits[device_mac].requests_per_hour
- data.rate_limits[device_mac].burst_size
- data.rate_limits[device_mac].current_count

---

# 12. OPA SERVER CONFIGURATION PARAMETERS

## 12.1 Server Configuration
- --addr
- --diagnostic-addr
- --config-file
- --bundle
- --log-level
- --log-format

## 12.2 Bundle Configuration
- services[].url
- bundles[].resource
- bundles[].polling.min_delay_seconds
- bundles[].polling.max_delay_seconds

## 12.3 Decision Logging
- decision_logs.console
- decision_logs.service
- decision_logs.reporting.max_decisions_per_second

## 12.4 Discovery Configuration
- discovery.resource
- discovery.service
- discovery.polling.min_delay_seconds

## 12.5 Status Reporting
- status.console
- status.service
- status.partition_name
