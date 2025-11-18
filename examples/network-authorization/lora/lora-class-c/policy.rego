package lora_class_c

# LoRa Class C (Continuous RX) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for LoRa Class C (Continuous RX) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. CONTINUOUS RECEIVE
######################

# Rule: Continuous Receive
#
# Why: Always listening except when transmitting. Lowest latency, highest power.
allow if {
    input.action == "enable_continuous_rx"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_continuous_rx")
    not exceeds_rate_limit(input.device.id, "enable_continuous_rx")
}

######################
# 2. IMMEDIATE DOWNLINK
######################

# Rule: Immediate Downlink
#
# Why: Downlink possible anytime. No waiting for uplink or ping slot.
allow if {
    input.action == "send_immediate_downlink"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "send_immediate_downlink")
    not exceeds_rate_limit(input.device.id, "send_immediate_downlink")
}

######################
# 3. MAINS-POWERED OPERATION
######################

# Rule: Mains-Powered Operation
#
# Why: Class C typically for mains-powered devices. Battery would drain quickly.
allow if {
    input.action == "verify_mains_powered"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "verify_mains_powered")
    not exceeds_rate_limit(input.device.id, "verify_mains_powered")
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
