package wifi6

# WiFi 6 (802.11ax) Authorization Policy
#
# This policy implements authorization for WiFi 6 networks with:
# - WPA3-SAE authentication
# - OFDMA resource unit allocation
# - MU-MIMO spatial stream management
# - Target Wake Time (TWT) scheduling
# - Fast BSS transition (roaming)
# - QoS-based access control
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

######################
# DEFAULT DENY
######################

# Default deny - all actions are denied unless explicitly allowed
# This follows the security principle of "deny by default"
default allow := false

######################
# 1. DEVICE AUTHENTICATION
######################

# Rule: Allow WPA3-SAE authentication for compatible devices
#
# WiFi 6 mandates WPA3 for enhanced security:
# - SAE (Simultaneous Authentication of Equals) replaces PSK
# - Provides forward secrecy and protection against dictionary attacks
# - Protected Management Frames (PMF) are mandatory
#
# Why this rule exists:
# WPA3-SAE is more secure than WPA2-PSK and prevents offline dictionary attacks.
# PMF protects management frames from spoofing and eavesdropping.
allow if {
    input.action == "authenticate"
    input.device.security_protocol == "WPA3-SAE"
    device_supports_pmf(input.device)
    device_wifi6_compatible(input.device)
    valid_sae_credentials(input.device)
}

# Rule: Allow WPA3-Enterprise authentication for enterprise networks
#
# WPA3-Enterprise provides:
# - 192-bit security suite for high-security environments
# - Authenticated encryption
# - ECDHE and ECDSA cryptography
#
# Why this rule exists:
# Enterprise environments require stronger encryption and centralized authentication.
# RADIUS integration allows for certificate-based and username/password auth.
allow if {
    input.action == "authenticate"
    input.device.security_protocol == "WPA3-Enterprise"
    input.network.security in ["WPA3-Enterprise", "WPA3-Enterprise-192bit"]
    device_has_valid_certificate(input.device)
    device_supports_pmf(input.device)
}

# Rule: Allow Enhanced Open (OWE) for guest networks
#
# OWE provides encryption without authentication:
# - Protects data in transit on open networks
# - No password required but traffic is encrypted
# - Uses Diffie-Hellman key exchange
#
# Why this rule exists:
# Public WiFi should still encrypt traffic even without authentication.
# Prevents passive eavesdropping on guest networks.
allow if {
    input.action == "authenticate"
    input.device.security_protocol == "OWE"
    input.network.type == "guest"
    device_wifi6_compatible(input.device)
}

######################
# 2. CONNECTION AUTHORIZATION
######################

# Rule: Allow authenticated devices to connect
#
# After successful authentication, devices can connect to the AP.
# This checks:
# - Device has completed authentication
# - AP has capacity for new clients
# - Device is not blacklisted
#
# Why this rule exists:
# Separates authentication from connection to allow for multi-stage validation.
# Prevents network overload by checking capacity.
allow if {
    input.action == "connect"
    device_authenticated(input.device.mac)
    network_has_capacity(input.network)
    not device_blacklisted(input.device.mac)
    device_wifi6_compatible(input.device)
}

# Rule: Allow roaming via Fast BSS Transition (802.11r)
#
# Fast BSS Transition enables seamless handoff between APs:
# - Pre-authentication with target AP
# - Minimal disruption for latency-sensitive apps (VoIP, video)
# - Uses PMK-R1 key hierarchy
#
# Why this rule exists:
# Enterprise WiFi requires seamless roaming for mobile devices.
# Reduces handoff time from 100ms+ to <50ms.
allow if {
    input.action == "fast_roaming"
    device_authenticated(input.device.mac)
    target_ap_in_mobility_domain(input.target_ap, input.current_ap)
    pmk_r1_available(input.device.mac, input.target_ap)
}

######################
# 3. OFDMA RESOURCE ALLOCATION
######################

# Rule: Allocate OFDMA Resource Units based on QoS
#
# OFDMA divides channels into Resource Units (RUs):
# - 26, 52, 106, 242, 484, 996 tone RUs
# - Allows simultaneous transmission to multiple devices
# - More efficient than CSMA/CA for high-density environments
#
# Why this rule exists:
# High QoS devices (voice, video) need larger RUs for guaranteed throughput.
# IoT devices can use smaller RUs, improving overall network efficiency.
allow if {
    input.action == "allocate_ru"
    device_connected(input.device.mac)
    ru_size := calculate_ru_size(input.device, input.requested_ru_size)
    ru_available(input.channel, ru_size)
    device_qos_sufficient(input.device, ru_size)
}

# Rule: Dynamic RU allocation for adaptive QoS
#
# Adjusts RU size based on:
# - Current network load
# - Device requirements
# - Traffic priority
#
# Why this rule exists:
# Network conditions change dynamically. Allocating fixed RU sizes wastes resources.
# Adaptive allocation maximizes network utilization.
allow if {
    input.action == "reallocate_ru"
    input.user.role in ["network_admin", "qos_manager"]
    device_connected(input.device.mac)
    network_load_acceptable(input.channel)
}

######################
# 4. MU-MIMO MANAGEMENT
######################

# Rule: Assign spatial streams for downlink MU-MIMO
#
# WiFi 6 supports up to 8 simultaneous users in DL MU-MIMO:
# - Spatial multiplexing sends different data streams
# - Requires sufficient spatial streams on AP
# - Devices must support MU-MIMO reception
#
# Why this rule exists:
# MU-MIMO increases network capacity by serving multiple devices simultaneously.
# Prevents over-subscription of spatial streams which would degrade performance.
allow if {
    input.action == "assign_mimo_stream"
    count(input.devices) <= 8
    all_devices_connected(input.devices)
    all_devices_mimo_capable(input.devices)
    sufficient_spatial_streams(input.ap, input.devices)
}

# Rule: Configure uplink MU-MIMO and OFDMA
#
# WiFi 6 adds UL MU-MIMO and OFDMA:
# - Multiple devices can transmit simultaneously
# - Triggered by AP's trigger frame
# - Improves uplink efficiency
#
# Why this rule exists:
# Traditional WiFi only had DL MU-MIMO. UL MU-MIMO/OFDMA is new in WiFi 6.
# Requires coordination by AP to avoid collisions.
allow if {
    input.action == "configure_ul_mu"
    input.user.role == "network_admin"
    input.ap.wifi6_capable == true
    count(input.target_devices) <= 8
}

######################
# 5. TARGET WAKE TIME (TWT)
######################

# Rule: Schedule TWT for power-efficient operation
#
# TWT allows devices to negotiate sleep schedules:
# - Device sleeps until its designated wake time
# - Reduces power consumption for IoT and mobile devices
# - AP buffers data for sleeping devices
#
# Why this rule exists:
# IoT devices often run on battery and need power efficiency.
# TWT can extend battery life by 3-4x compared to always-on WiFi.
allow if {
    input.action == "schedule_twt"
    device_supports_twt(input.device)
    twt_slot_available(input.requested_time, input.duration_ms)
    device_power_save_enabled(input.device)
}

# Rule: Modify TWT schedule
#
# Devices can request TWT changes based on traffic patterns:
# - More frequent wake times for active periods
# - Longer sleep for idle periods
#
# Why this rule exists:
# Device traffic patterns change. Adaptive TWT improves both power and performance.
allow if {
    input.action == "modify_twt"
    device_has_active_twt(input.device.mac)
    new_schedule_valid(input.new_schedule)
    not twt_conflicts(input.device.mac, input.new_schedule)
}

######################
# 6. DATA TRANSMISSION
######################

# Rule: Allow data transmission within bandwidth quota
#
# Prevents bandwidth exhaustion:
# - Per-device bandwidth limits
# - QoS-based prioritization
# - Fair queuing for best-effort traffic
#
# Why this rule exists:
# Without limits, one device could monopolize the network.
# QoS ensures critical traffic (voice, video) gets priority.
allow if {
    input.action == "transmit"
    device_connected(input.device.mac)
    data_within_quota(input.device.mac, input.data_size)
    destination_allowed(input.destination)
}

# Rule: Prioritize high-QoS traffic
#
# WiFi 6 enhanced QoS with:
# - Better EDCA parameters
# - RU-based prioritization
# - Latency-sensitive traffic handling
#
# Why this rule exists:
# Voice and video calls fail with >150ms latency or >1% packet loss.
# High QoS traffic must bypass best-effort queues.
allow if {
    input.action == "transmit_priority"
    device_connected(input.device.mac)
    input.traffic.qos_level >= 5
    priority_queue_available(input.traffic.qos_level)
}

######################
# 7. BSS COLORING
######################

# Rule: Configure BSS Color for interference mitigation
#
# BSS Coloring assigns each BSS a color (0-63):
# - Devices can ignore frames from other BSSs with different colors
# - Improves spatial reuse in dense deployments
# - Reduces CCA threshold for inter-BSS frames
#
# Why this rule exists:
# In dense deployments (apartments, offices), overlapping BSSs cause collisions.
# BSS Coloring allows aggressive spatial reuse, increasing capacity.
allow if {
    input.action == "set_bss_color"
    input.user.role in ["network_admin", "rf_engineer"]
    bss_color_valid(input.color)
    not bss_color_conflict(input.color, input.vicinity_aps)
}

######################
# 8. NETWORK MANAGEMENT
######################

# Rule: Admin can configure WiFi 6 features
#
# Network administrators can:
# - Enable/disable OFDMA, MU-MIMO
# - Configure TWT parameters
# - Set channel width and BSS color
#
# Why this rule exists:
# WiFi 6 features need tuning based on environment and use case.
# Only authorized admins should modify network-wide settings.
allow if {
    input.action in ["configure_ofdma", "configure_mu_mimo", "set_channel_width"]
    input.user.role == "network_admin"
    configuration_valid(input.config)
}

# Rule: Monitor and report WiFi 6 statistics
#
# Monitoring allows for:
# - Performance analysis
# - Troubleshooting
# - Capacity planning
#
# Why this rule exists:
# Network operators need visibility into WiFi 6 feature utilization.
# Helps identify issues and optimize configurations.
allow if {
    input.action in ["read_stats", "export_metrics"]
    input.user.role in ["network_admin", "network_operator", "monitoring"]
}

######################
# HELPER FUNCTIONS
######################

# Check if device supports Protected Management Frames
device_supports_pmf(device) if {
    device.pmf_capable == true
}

# Check if device is WiFi 6 compatible
device_wifi6_compatible(device) if {
    device.wifi6_capable == true
}

# Validate SAE credentials (simplified - in production, verify cryptographic exchange)
valid_sae_credentials(device) if {
    device.mac in data.authorized_devices
    data.authorized_devices[device.mac].security_protocols[_] == "WPA3-SAE"
}

# Check if device has valid certificate for Enterprise auth
device_has_valid_certificate(device) if {
    device.certificate != null
    certificate_not_expired(device.certificate)
    certificate_trusted(device.certificate)
}

# Check if device completed authentication
device_authenticated(mac) if {
    data.authenticated_sessions[mac] != null
    session_not_expired(data.authenticated_sessions[mac])
}

# Check if network has capacity for new connection
network_has_capacity(network) if {
    current_clients := count(data.connected_devices[network.ssid])
    max_clients := data.access_points[network.bssid].max_clients
    current_clients < max_clients
}

# Check if device is blacklisted
device_blacklisted(mac) if {
    mac in data.blacklisted_devices
}

# Check if device is currently connected
device_connected(mac) if {
    some ssid
    data.connected_devices[ssid][mac] != null
}

# Check if target AP is in same mobility domain (for fast roaming)
target_ap_in_mobility_domain(target_ap, current_ap) if {
    data.access_points[target_ap].mobility_domain == data.access_points[current_ap].mobility_domain
}

# Check if PMK-R1 key is available for fast roaming
pmk_r1_available(mac, target_ap) if {
    data.roaming_keys[mac][target_ap] != null
}

# Calculate appropriate RU size based on device QoS and requirements
calculate_ru_size(device, requested) := requested if {
    device_qos := data.authorized_devices[device.mac].qos_level
    device_qos >= 6
    requested <= 996
}

calculate_ru_size(device, requested) := 242 if {
    device_qos := data.authorized_devices[device.mac].qos_level
    device_qos >= 4
    device_qos < 6
}

calculate_ru_size(device, _) := 52 if {
    device_qos := data.authorized_devices[device.mac].qos_level
    device_qos < 4
}

# Check if RU is available on channel
ru_available(channel, ru_size) if {
    allocated := data.ofdma_allocations[channel]
    total_capacity := 996  # Total tones in 20MHz channel
    sum([ru | allocated[_].ru_size == ru], total)
    total + ru_size <= total_capacity
}

# Check if device QoS level is sufficient for requested RU size
device_qos_sufficient(device, ru_size) if {
    device_qos := data.authorized_devices[device.mac].qos_level
    min_qos := ru_to_min_qos[ru_size]
    device_qos >= min_qos
}

# Mapping of RU size to minimum required QoS level
ru_to_min_qos := {
    26: 0,
    52: 2,
    106: 3,
    242: 4,
    484: 5,
    996: 6
}

# Check if all devices are connected
all_devices_connected(devices) if {
    every device in devices {
        device_connected(device.mac)
    }
}

# Check if all devices support MU-MIMO
all_devices_mimo_capable(devices) if {
    every device in devices {
        data.authorized_devices[device.mac].mu_mimo_capable == true
    }
}

# Check if AP has sufficient spatial streams for all devices
sufficient_spatial_streams(ap, devices) if {
    ap_streams := data.access_points[ap.bssid].spatial_streams
    required_streams := count(devices)
    required_streams <= ap_streams
}

# Check if device supports TWT
device_supports_twt(device) if {
    data.authorized_devices[device.mac].twt_capable == true
}

# Check if TWT time slot is available
twt_slot_available(requested_time, duration_ms) if {
    # Simplified - in production, check for conflicts with existing TWT schedules
    not twt_slot_occupied(requested_time, duration_ms)
}

twt_slot_occupied(time, duration) if {
    some mac
    some schedule in data.twt_schedules[mac]
    schedules_overlap(schedule, time, duration)
}

# Check if device has power save enabled
device_power_save_enabled(device) if {
    data.authorized_devices[device.mac].power_save == true
}

# Check if device has an active TWT agreement
device_has_active_twt(mac) if {
    data.twt_schedules[mac] != null
}

# Validate new TWT schedule
new_schedule_valid(schedule) if {
    schedule.interval_ms > 0
    schedule.duration_ms > 0
    schedule.duration_ms <= schedule.interval_ms
}

# Check for TWT schedule conflicts
twt_conflicts(mac, new_schedule) if {
    some other_mac
    other_mac != mac
    some existing_schedule in data.twt_schedules[other_mac]
    schedules_overlap(existing_schedule, new_schedule.start_time, new_schedule.duration_ms)
}

# Check if data is within device's bandwidth quota
data_within_quota(mac, data_size) if {
    device := data.authorized_devices[mac]
    current_usage := data.bandwidth_usage[mac]
    quota := device.max_bandwidth_mbps * 1000000  # Convert to bytes
    current_usage + data_size <= quota
}

# Check if destination is allowed
destination_allowed(destination) if {
    # Allow local network and internet, block malicious IPs
    not destination in data.blocked_destinations
}

# Check if priority queue is available for QoS level
priority_queue_available(qos_level) if {
    qos_level >= 0
    qos_level <= 7
}

# Validate BSS color (0-63)
bss_color_valid(color) if {
    color >= 0
    color <= 63
}

# Check for BSS color conflicts in vicinity
bss_color_conflict(color, vicinity_aps) if {
    some ap in vicinity_aps
    data.access_points[ap].bss_color == color
}

# Validate configuration
configuration_valid(config) if {
    # Simplified validation - in production, validate all config parameters
    config != null
}

# Check if certificate is not expired
certificate_not_expired(cert) if {
    # Simplified - in production, parse and validate X.509 certificate
    cert.expiry_date > time.now_ns()
}

# Check if certificate is from trusted CA
certificate_trusted(cert) if {
    cert.issuer in data.trusted_cas
}

# Check if session is not expired
session_not_expired(session) if {
    session.expiry > time.now_ns()
}

# Check if schedules overlap
schedules_overlap(schedule1, start_time2, duration2) if {
    # Simplified overlap detection
    start1 := schedule1.start_time
    end1 := start1 + schedule1.duration_ms
    end2 := start_time2 + duration2
    start1 < end2
    start_time2 < end1
}

# Check network load
network_load_acceptable(channel) if {
    load := data.channel_utilization[channel]
    load < 80  # Less than 80% utilization
}
