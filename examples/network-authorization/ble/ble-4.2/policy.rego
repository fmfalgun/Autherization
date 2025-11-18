package ble_4.2

# BLE 4.2 (Privacy & Security) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 4.2 (Privacy & Security) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. LE PRIVACY 1.2
######################

# Rule: LE Privacy 1.2
#
# Why: Resolvable Private Addresses prevent tracking. Address rotates every 15 minutes.
allow if {
    input.action == "enable_privacy"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_privacy")
    not exceeds_rate_limit(input.device.id, "enable_privacy")
}

######################
# 2. LE SECURE CONNECTIONS
######################

# Rule: LE Secure Connections
#
# Why: ECDH key exchange replaces legacy pairing. Protects against passive eavesdropping.
allow if {
    input.action == "use_secure_connections"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_secure_connections")
    not exceeds_rate_limit(input.device.id, "use_secure_connections")
}

######################
# 3. DATA LENGTH EXTENSION
######################

# Rule: Data Length Extension
#
# Why: DLE increases packet size from 27 to 251 bytes. 10x faster data transfer.
allow if {
    input.action == "extend_data_length"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "extend_data_length")
    not exceeds_rate_limit(input.device.id, "extend_data_length")
}

######################
# 4. LINK LAYER PRIVACY
######################

# Rule: Link Layer Privacy
#
# Why: Privacy at link layer with IRK (Identity Resolving Key). Controller resolves addresses.
allow if {
    input.action == "enable_ll_privacy"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_ll_privacy")
    not exceeds_rate_limit(input.device.id, "enable_ll_privacy")
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
