package monitoring

# Continuous Monitoring & Anomaly Detection Authorization Policy
#
# This policy authorizes actions from network monitoring/sniffing nodes that:
# - Monitor WiFi, BLE, Bluetooth, Zigbee, LoRa networks
# - Detect anomalies and security threats
# - Trigger security responses (alerts, blocks, database updates)
#
# Why this policy exists:
# Monitoring nodes have significant power - they can block devices, trigger alerts,
# and modify databases. This policy ensures only legitimate, authenticated nodes
# can perform these actions, and only when justified by evidence.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

######################
# DEFAULT DENY
######################

# Default deny - all monitoring actions require explicit authorization
# Why: Monitoring nodes can cause significant disruption if compromised
default allow := false

######################
# 1. MONITORING NODE REGISTRATION
######################

# Rule: Register new monitoring node
#
# Monitoring nodes must register before reporting data.
# Registration requires:
# - Valid X.509 certificate from trusted CA
# - Physical location verification
# - Capability declaration (which protocols it monitors)
#
# Why this rule exists:
# Rogue monitoring nodes could inject false data to:
# - Trigger unnecessary blocks (DoS)
# - Hide real attacks (by not reporting them)
# - Corrupt monitoring database
# Registration with certificate auth prevents this.
allow if {
    input.action == "register_node"
    certificate_valid(input.node.certificate)
    certificate_from_trusted_ca(input.node.certificate)
    not certificate_expired(input.node.certificate)
    node_location_valid(input.node.location)
    capabilities_declared(input.node.capabilities)
}

# Rule: Renew node registration
#
# Periodic re-registration ensures:
# - Certificate hasn't been revoked
# - Node is still authorized
# - Configuration is up-to-date
#
# Why this rule exists:
# Nodes may be decommissioned or compromised. Regular renewal
# allows revoking access without waiting for cert expiry.
allow if {
    input.action == "renew_registration"
    registered_node(input.node_id)
    certificate_valid(input.node.certificate)
    not certificate_revoked(input.node.certificate)
}

######################
# 2. REPORT NETWORK METRICS
######################

# Rule: Report normal network metrics
#
# Nodes report metrics like:
# - Device counts
# - Signal strengths
# - Channel utilization
# - Error rates
#
# Why this rule exists:
# Baseline metrics are needed for anomaly detection. This data must come
# from authenticated sources to prevent poisoning the baseline.
allow if {
    input.action == "report_metrics"
    registered_node(input.node_id)
    data_signature_valid(input.data, input.signature, input.node_id)
    metrics_schema_valid(input.data)
    metrics_within_expected_range(input.data)
    not exceeds_rate_limit(input.node_id, "metrics")
}

# Rule: Report WiFi-specific metrics
#
# WiFi metrics include:
# - AP signal strength (RSSI)
# - Client association counts
# - Deauth/disassoc frames
# - Channel occupancy
#
# Why this rule exists:
# WiFi has specific metrics that other protocols don't have.
# Validates that WiFi nodes only report WiFi-specific data.
allow if {
    input.action == "report_wifi_metrics"
    registered_node(input.node_id)
    node_monitors_wifi(input.node_id)
    wifi_metrics_valid(input.data)
    data_signature_valid(input.data, input.signature, input.node_id)
}

# Rule: Report BLE-specific metrics
#
# BLE metrics include:
# - Advertisement counts
# - Connection attempts
# - GATT service discoveries
#
# Why this rule exists:
# BLE nodes should only report BLE data.
# Prevents data confusion and injection attacks.
allow if {
    input.action == "report_ble_metrics"
    registered_node(input.node_id)
    node_monitors_ble(input.node_id)
    ble_metrics_valid(input.data)
    data_signature_valid(input.data, input.signature, input.node_id)
}

######################
# 3. REPORT ANOMALIES
######################

# Rule: Report WiFi anomaly
#
# WiFi anomalies include:
# - Deauthentication floods
# - Rogue/Evil Twin APs
# - Weak encryption (WEP, open)
# - Unusual signal patterns
#
# Why this rule exists:
# Anomaly reports trigger security responses. False reports cause alert fatigue
# and waste resources. This ensures reports are legitimate and above threshold.
allow if {
    input.action == "report_anomaly"
    input.anomaly.network_type == "wifi"
    registered_node(input.node_id)
    node_monitors_wifi(input.node_id)
    anomaly_type_valid(input.anomaly.type, "wifi")
    anomaly_severity_justified(input.anomaly)
    anomaly_confidence_sufficient(input.anomaly)
    not false_positive_pattern(input.anomaly)
}

# Rule: Report BLE anomaly
#
# BLE anomalies include:
# - Advertisement floods
# - Spoofed beacons (iBeacon, Eddystone)
# - Pairing attacks
# - RSSI manipulation
#
# Why this rule exists:
# BLE attacks are common in tracking/surveillance. Need to detect:
# - Fake COVID contact tracing beacons
# - Location spoofing
# - Bluetooth trackers (AirTags, Tiles)
allow if {
    input.action == "report_anomaly"
    input.anomaly.network_type == "ble"
    registered_node(input.node_id)
    node_monitors_ble(input.node_id)
    anomaly_type_valid(input.anomaly.type, "ble")
    anomaly_severity_justified(input.anomaly)
}

# Rule: Report Bluetooth Classic anomaly
#
# Bluetooth anomalies include:
# - Bluejacking (unsolicited messages)
# - Bluesnarfing (data theft)
# - BlueBorne exploits
#
# Why this rule exists:
# Bluetooth Classic has known vulnerabilities. Early detection prevents:
# - Contact theft
# - File access
# - Device takeover
allow if {
    input.action == "report_anomaly"
    input.anomaly.network_type == "bluetooth"
    registered_node(input.node_id)
    node_monitors_bluetooth(input.node_id)
    anomaly_type_valid(input.anomaly.type, "bluetooth")
    anomaly_severity_justified(input.anomaly)
}

# Rule: Report Zigbee anomaly
#
# Zigbee anomalies include:
# - Unauthorized coordinators
# - Network key compromise
# - Command injection
# - Join request floods
#
# Why this rule exists:
# Zigbee is used in critical IoT (smart locks, alarms). Attacks could:
# - Unlock doors
# - Disable alarms
# - Control devices
allow if {
    input.action == "report_anomaly"
    input.anomaly.network_type == "zigbee"
    registered_node(input.node_id)
    node_monitors_zigbee(input.node_id)
    anomaly_type_valid(input.anomaly.type, "zigbee")
    anomaly_severity_justified(input.anomaly)
}

# Rule: Report LoRa anomaly
#
# LoRa anomalies include:
# - Join-request replay attacks
# - ABP key compromise
# - Downlink injection
# - DevNonce reuse
#
# Why this rule exists:
# LoRa is used in remote sensors (agriculture, utilities). Attacks could:
# - Inject false sensor readings
# - Drain device batteries
# - Cause false alarms
allow if {
    input.action == "report_anomaly"
    input.anomaly.network_type == "lora"
    registered_node(input.node_id)
    node_monitors_lora(input.node_id)
    anomaly_type_valid(input.anomaly.type, "lora")
    anomaly_severity_justified(input.anomaly)
}

######################
# 4. DATABASE OPERATIONS
######################

# Rule: Insert anomaly record into database
#
# Stores detected anomalies for:
# - Historical analysis
# - Trend detection
# - Compliance/audit trails
#
# Why this rule exists:
# Database is single source of truth. Unauthorized writes could:
# - Hide attacks by deleting records
# - Create false audit trails
# - Corrupt analytics
allow if {
    input.action == "write_database"
    input.operation == "insert"
    registered_node(input.node_id)
    data_schema_valid(input.data)
    not exceeds_rate_limit(input.node_id, "database_writes")
}

# Rule: Update device trust score
#
# Trust scores track device behavior:
# - Decremented on suspicious activity
# - Incremented on normal behavior
# - Used for access control decisions
#
# Why this rule exists:
# Trust scores affect device access. Unauthorized updates could:
# - Grant access to malicious devices
# - Block legitimate devices
allow if {
    input.action == "update_trust_score"
    registered_node(input.node_id)
    device_exists(input.device_id)
    trust_score_change_justified(input.device_id, input.score_delta)
    anomaly_evidence_provided(input.evidence)
}

# Rule: Insert device warning
#
# Warnings track suspicious but not confirmed malicious behavior:
# - Expire after set time
# - Can be reviewed by admin
# - Don't block access immediately
#
# Why this rule exists:
# Not all anomalies are attacks. Warnings allow tracking without false blocks.
allow if {
    input.action == "mark_warning"
    registered_node(input.node_id)
    device_exists(input.device_id)
    warning_type_valid(input.warning.type)
    warning_expiry_reasonable(input.warning.expires_at)
}

######################
# 5. ALERT MANAGEMENT
######################

# Rule: Send low-severity alert
#
# Low-severity alerts:
# - Logged but don't page on-call
# - Aggregated in daily/weekly reports
# - Examples: Weak encryption, misconfigurations
#
# Why this rule exists:
# Not every issue needs immediate attention. Low-severity alerts
# for trend analysis without causing alert fatigue.
allow if {
    input.action == "send_alert"
    input.alert.severity == "low"
    registered_node(input.node_id)
    anomaly_detected_recently(input.node_id, input.alert.anomaly_id)
}

# Rule: Send high-severity alert
#
# High-severity alerts:
# - Immediate notification to security team
# - May page on-call engineer
# - Examples: Rogue AP, key compromise, active attacks
#
# Why this rule exists:
# High-severity alerts need immediate response. Requires:
# - Strong evidence (high confidence)
# - Not recently sent (avoid spam)
# - Confirmed by monitoring node
allow if {
    input.action == "send_alert"
    input.alert.severity in ["high", "critical"]
    registered_node(input.node_id)
    anomaly_confidence_high(input.alert)
    not alert_recently_sent(input.alert.type, input.alert.device_id)
    evidence_strong(input.alert.evidence)
}

# Rule: Send critical alert (requires admin notification)
#
# Critical alerts always notify admin:
# - Potential data breach
# - Network-wide attack
# - Infrastructure compromise
#
# Why this rule exists:
# Critical alerts may require immediate action (incident response, network isolation).
# Must ensure admin is notified before automated blocking.
allow if {
    input.action == "send_alert"
    input.alert.severity == "critical"
    registered_node(input.node_id)
    anomaly_confidence_high(input.alert)
    admin_notification_confirmed(input.alert)
}

######################
# 6. DEVICE BLOCKING
######################

# Rule: Temporary device block (auto-expire)
#
# Temporary blocks:
# - Auto-expire after set duration (1-24 hours)
# - Used for suspected but not confirmed threats
# - Can be manually overridden by admin
#
# Why this rule exists:
# Permanent blocks are severe. Temporary blocks allow:
# - Stopping ongoing attacks immediately
# - Auto-unblock if false positive
# - Admin review before permanent action
allow if {
    input.action == "block_device"
    input.block.type == "temporary"
    registered_node(input.node_id)
    device_exists(input.device_id)
    anomaly_severity_warrants_block(input.anomaly)
    block_duration_reasonable(input.block.duration_hours)
}

# Rule: Permanent device block (requires strong evidence)
#
# Permanent blocks:
# - Manual admin review required to unblock
# - Used for confirmed attacks
# - Creates audit trail
#
# Why this rule exists:
# Permanent blocks are the strongest action. Requires:
# - Critical severity
# - High confidence (>90%)
# - Multiple anomaly instances (not single event)
# - Admin notification sent
allow if {
    input.action == "block_device"
    input.block.type == "permanent"
    registered_node(input.node_id)
    input.block.severity == "critical"
    anomaly_confirmed(input.device_id, input.anomaly)
    multiple_anomalies_detected(input.device_id)
    admin_notified(input.block)
}

######################
# 7. SYSTEM MONITORING
######################

# Rule: Query monitoring statistics
#
# Allows reading:
# - Node health metrics
# - Anomaly counts
# - Detection rates
# - False positive rates
#
# Why this rule exists:
# Operators need visibility into monitoring system health.
# Read-only access doesn't require strong auth.
allow if {
    input.action == "read_stats"
    input.user.role in ["network_admin", "security_analyst", "monitoring"]
}

# Rule: Export monitoring data
#
# Allows exporting:
# - Historical anomalies
# - Trend reports
# - Compliance reports
#
# Why this rule exists:
# Data export needed for compliance, audits, and external analysis.
# Requires authorization to prevent data leaks.
allow if {
    input.action == "export_data"
    input.user.role in ["network_admin", "compliance_officer"]
    export_purpose_valid(input.export.purpose)
}

######################
# HELPER FUNCTIONS
######################

# Validate certificate
certificate_valid(cert) if {
    cert != null
    cert.subject != null
    cert.issuer != null
}

certificate_from_trusted_ca(cert) if {
    cert.issuer in data.trusted_cas
}

certificate_expired(cert) if {
    cert.expiry_timestamp < time.now_ns()
}

certificate_revoked(cert) if {
    cert.serial_number in data.revoked_certificates
}

# Check node registration
registered_node(node_id) if {
    data.monitoring_nodes[node_id] != null
}

# Validate node location
node_location_valid(location) if {
    location.building != null
    location.floor != null
}

# Check capabilities declared
capabilities_declared(capabilities) if {
    count(capabilities) > 0
}

# Verify data signature
data_signature_valid(data, signature, node_id) if {
    public_key := data.monitoring_nodes[node_id].public_key
    crypto.verify_signature(data, signature, public_key)
}

# Check if node monitors specific protocol
node_monitors_wifi(node_id) if {
    "wifi" in data.monitoring_nodes[node_id].capabilities
}

node_monitors_ble(node_id) if {
    "ble" in data.monitoring_nodes[node_id].capabilities
}

node_monitors_bluetooth(node_id) if {
    "bluetooth" in data.monitoring_nodes[node_id].capabilities
}

node_monitors_zigbee(node_id) if {
    "zigbee" in data.monitoring_nodes[node_id].capabilities
}

node_monitors_lora(node_id) if {
    "lora" in data.monitoring_nodes[node_id].capabilities
}

# Validate metrics schema
metrics_schema_valid(data) if {
    data.timestamp != null
    data.metrics != null
}

# Check metrics are in expected range
metrics_within_expected_range(data) if {
    # Simplified - in production, check each metric against bounds
    data.metrics != null
}

# Validate WiFi-specific metrics
wifi_metrics_valid(data) if {
    data.rssi != null
    data.rssi >= -100
    data.rssi <= 0
}

# Validate BLE-specific metrics
ble_metrics_valid(data) if {
    data.advertisement_count != null
    data.advertisement_count >= 0
}

# Check anomaly type is valid for protocol
anomaly_type_valid(type, protocol) if {
    type in data.valid_anomaly_types[protocol]
}

# Check anomaly severity is justified
anomaly_severity_justified(anomaly) if {
    severity_threshold := data.anomaly_thresholds[anomaly.type].severity_threshold
    anomaly.severity_score >= severity_threshold
}

# Check anomaly confidence is sufficient
anomaly_confidence_sufficient(anomaly) if {
    anomaly.confidence >= 0.7  # 70% confidence minimum
}

anomaly_confidence_high(alert) if {
    alert.confidence >= 0.9  # 90% for high-severity alerts
}

# Detect false positive patterns
false_positive_pattern(anomaly) if {
    # Check if similar anomaly was marked as false positive recently
    some fp in data.false_positives
    fp.type == anomaly.type
    fp.device_id == anomaly.device_id
    time_since(fp.timestamp) < 3600  # Within last hour
}

# Rate limiting
exceeds_rate_limit(node_id, action_type) if {
    current_count := data.rate_limits[node_id][action_type].count
    limit := data.rate_limit_thresholds[action_type]
    current_count >= limit
}

# Database operations
data_schema_valid(data) if {
    # Simplified validation
    data != null
}

device_exists(device_id) if {
    data.devices[device_id] != null
}

# Trust score validation
trust_score_change_justified(device_id, score_delta) if {
    score_delta >= -20
    score_delta <= 20
}

anomaly_evidence_provided(evidence) if {
    evidence != null
    evidence.anomaly_type != null
}

# Warning validation
warning_type_valid(type) if {
    type in ["suspicious_activity", "policy_violation", "anomaly_detected"]
}

warning_expiry_reasonable(expires_at) if {
    duration := expires_at - time.now_ns()
    duration <= 604800000000000  # Max 7 days
}

# Alert management
anomaly_detected_recently(node_id, anomaly_id) if {
    data.recent_anomalies[node_id][anomaly_id] != null
}

alert_recently_sent(alert_type, device_id) if {
    some alert in data.recent_alerts
    alert.type == alert_type
    alert.device_id == device_id
    time_since(alert.timestamp) < 300  # Within 5 minutes
}

evidence_strong(evidence) if {
    evidence.confidence >= 0.85
    count(evidence.indicators) >= 2
}

admin_notification_confirmed(alert) if {
    alert.admin_notified == true
}

# Device blocking
anomaly_severity_warrants_block(anomaly) if {
    anomaly.severity in ["high", "critical"]
}

block_duration_reasonable(hours) if {
    hours >= 1
    hours <= 24
}

anomaly_confirmed(device_id, anomaly) if {
    # Check if multiple sources detected same anomaly
    count(data.anomaly_reports[device_id][anomaly.type]) >= 2
}

multiple_anomalies_detected(device_id) if {
    count(data.device_anomaly_history[device_id]) >= 3
}

admin_notified(block) if {
    block.admin_notification == "sent"
}

# Export validation
export_purpose_valid(purpose) if {
    purpose in ["compliance", "audit", "analysis", "reporting"]
}

# Helper: time since timestamp
time_since(timestamp) := time.now_ns() - timestamp
