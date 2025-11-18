package ble_4.0

# BLE 4.0 (Bluetooth Low Energy) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 4.0 (Bluetooth Low Energy) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. LE ADVERTISING
######################

# Rule: LE Advertising
#
# Why: Connectable/non-connectable advertising on 3 channels (37,38,39). Interval 20ms-10.24s.
allow if {
    input.action == "advertise_le"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "advertise_le")
    not exceeds_rate_limit(input.device.id, "advertise_le")
}

######################
# 2. GATT SERVICES
######################

# Rule: GATT Services
#
# Why: Generic Attribute Profile defines services and characteristics. Read/write/notify operations.
allow if {
    input.action == "access_gatt_service"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "access_gatt_service")
    not exceeds_rate_limit(input.device.id, "access_gatt_service")
}

######################
# 3. CONNECTION PARAMETERS
######################

# Rule: Connection Parameters
#
# Why: Interval, latency, timeout affect power and throughput. Must balance based on use case.
allow if {
    input.action == "negotiate_conn_params"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "negotiate_conn_params")
    not exceeds_rate_limit(input.device.id, "negotiate_conn_params")
}

######################
# 4. LE ENCRYPTION
######################

# Rule: LE Encryption
#
# Why: AES-CCM encryption with 128-bit key. Protects data but not metadata (timing, length).
allow if {
    input.action == "enable_le_encryption"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_le_encryption")
    not exceeds_rate_limit(input.device.id, "enable_le_encryption")
}

######################
# 5. ATT PROTOCOL
######################

# Rule: ATT Protocol
#
# Why: Attribute Protocol for GATT. MTU typically 23 bytes, can negotiate up to 517.
allow if {
    input.action == "use_att"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_att")
    not exceeds_rate_limit(input.device.id, "use_att")
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
