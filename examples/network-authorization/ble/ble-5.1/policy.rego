package ble_5.1

# BLE 5.1 (Direction Finding) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 5.1 (Direction Finding) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. ANGLE OF ARRIVAL (AOA)
######################

# Rule: Angle of Arrival (AoA)
#
# Why: AoA determines direction using antenna array at receiver. For asset tracking, <1m accuracy.
allow if {
    input.action == "use_aoa"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_aoa")
    not exceeds_rate_limit(input.device.id, "use_aoa")
}

######################
# 2. ANGLE OF DEPARTURE (AOD)
######################

# Rule: Angle of Departure (AoD)
#
# Why: AoD uses antenna array at transmitter. Simpler receiver, good for indoor positioning.
allow if {
    input.action == "use_aod"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_aod")
    not exceeds_rate_limit(input.device.id, "use_aod")
}

######################
# 3. GATT CACHING
######################

# Rule: GATT Caching
#
# Why: Caching avoids service discovery on reconnection. Faster connection, lower power.
allow if {
    input.action == "enable_gatt_caching"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_gatt_caching")
    not exceeds_rate_limit(input.device.id, "enable_gatt_caching")
}

######################
# 4. PERIODIC ADVERTISING SYNC TRANSFER
######################

# Rule: Periodic Advertising Sync Transfer
#
# Why: Transfer periodic advertising sync between devices. Efficient broadcast reception.
allow if {
    input.action == "sync_periodic_adv"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "sync_periodic_adv")
    not exceeds_rate_limit(input.device.id, "sync_periodic_adv")
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
