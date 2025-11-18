package ble_5.3

# BLE 5.3 (Connection & Efficiency) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 5.3 (Connection & Efficiency) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. CONNECTION SUBRATING
######################

# Rule: Connection Subrating
#
# Why: Reduces connection events for low-data applications. Saves power while maintaining connection.
allow if {
    input.action == "use_conn_subrating"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_conn_subrating")
    not exceeds_rate_limit(input.device.id, "use_conn_subrating")
}

######################
# 2. CHANNEL CLASSIFICATION ENHANCEMENT
######################

# Rule: Channel Classification Enhancement
#
# Why: Better WiFi coexistence through improved channel classification. Avoids busy channels.
allow if {
    input.action == "enhance_channel_class"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enhance_channel_class")
    not exceeds_rate_limit(input.device.id, "enhance_channel_class")
}

######################
# 3. PERIODIC ADVERTISING ENHANCEMENTS
######################

# Rule: Periodic Advertising Enhancements
#
# Why: ADI (Advertising Data Info) enables filtering. Receiver processes only new data.
allow if {
    input.action == "enhance_periodic_adv"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enhance_periodic_adv")
    not exceeds_rate_limit(input.device.id, "enhance_periodic_adv")
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
