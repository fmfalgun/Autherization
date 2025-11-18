package bluetooth_classic_2.0

# Bluetooth 2.0 + EDR - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Bluetooth 2.0 + EDR specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. EDR (ENHANCED DATA RATE)
######################

# Rule: EDR (Enhanced Data Rate)
#
# Why: EDR provides 2-3 Mbps (vs 1 Mbps basic rate). Uses 8DPSK modulation.
allow if {
    input.action == "use_edr"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_edr")
    not exceeds_rate_limit(input.device.id, "use_edr")
}

######################
# 2. SCO (SYNCHRONOUS CONNECTION-ORIENTED)
######################

# Rule: SCO (Synchronous Connection-Oriented)
#
# Why: SCO for voice with guaranteed latency. 64 kbps, used in headsets.
allow if {
    input.action == "create_sco"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "create_sco")
    not exceeds_rate_limit(input.device.id, "create_sco")
}

######################
# 3. ESCO (EXTENDED SCO)
######################

# Rule: eSCO (Extended SCO)
#
# Why: eSCO adds retransmission to SCO. Better audio quality with error recovery.
allow if {
    input.action == "create_esco"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "create_esco")
    not exceeds_rate_limit(input.device.id, "create_esco")
}

######################
# 4. SNIFF MODE
######################

# Rule: Sniff Mode
#
# Why: Sniff mode reduces power by periodic listening. Duty cycle from 0.625ms to 40.9s.
allow if {
    input.action == "enable_sniff"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_sniff")
    not exceeds_rate_limit(input.device.id, "enable_sniff")
}

######################
# STANDARD AUTHENTICATION & CONNECTION
######################

allow if {
    input.action == "authenticate"
    device_credentials_valid(input.device)
    device_not_blacklisted(input.device.id)
}

allow if {
    input.action == "connect"
    device_authenticated(input.device.id)
    network_has_capacity(input.network)
}

allow if {
    input.action == "transmit"
    device_connected(input.device.id)
    data_within_quota(input.device.id, input.data_size)
}

######################
# HELPER FUNCTIONS
######################

device_authenticated(device_id) if {
    data.active_sessions[device_id] != null
}

device_supports_feature(device, feature) if {
    feature in data.authorized_devices[device.id].supported_features
}

exceeds_rate_limit(device_id, action) if {
    count := data.rate_counters[device_id][action]
    limit := data.rate_limits[action]
    count >= limit
}

device_credentials_valid(device) if {
    device.id in data.authorized_devices
}

device_not_blacklisted(device_id) if {
    not device_id in data.blacklisted_devices
}

network_has_capacity(network) if {
    current := count(data.connected_devices[network.id])
    max := data.networks[network.id].max_devices
    current < max
}

device_connected(device_id) if {
    some network_id
    data.connected_devices[network_id][device_id] != null
}

data_within_quota(device_id, data_size) if {
    current := data.bandwidth_usage[device_id]
    quota := data.authorized_devices[device_id].quota
    current + data_size <= quota
}
