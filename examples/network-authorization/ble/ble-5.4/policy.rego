package ble_5.4

# BLE 5.4 (PAwR & Advertising) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 5.4 (PAwR & Advertising) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. PAWR (PERIODIC ADVERTISING WITH RESPONSES)
######################

# Rule: PAwR (Periodic Advertising with Responses)
#
# Why: Bidirectional communication in advertising mode. ESL (Electronic Shelf Labels) use case.
allow if {
    input.action == "use_pawr"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_pawr")
    not exceeds_rate_limit(input.device.id, "use_pawr")
}

######################
# 2. ADVERTISING CODING SELECTION
######################

# Rule: Advertising Coding Selection
#
# Why: Choose S=2 or S=8 coding per advertising set. Optimize range vs power per use case.
allow if {
    input.action == "select_adv_coding"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "select_adv_coding")
    not exceeds_rate_limit(input.device.id, "select_adv_coding")
}

######################
# 3. LE GATT SECURITY LEVELS
######################

# Rule: LE GATT Security Levels
#
# Why: Enhanced security levels for GATT characteristics. Fine-grained access control.
allow if {
    input.action == "enforce_gatt_security"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enforce_gatt_security")
    not exceeds_rate_limit(input.device.id, "enforce_gatt_security")
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
