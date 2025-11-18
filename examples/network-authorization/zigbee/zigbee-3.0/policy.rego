package zigbee_3.0

# Zigbee 3.0 (Unified Standard) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Zigbee 3.0 (Unified Standard) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. GREEN POWER COMMISSIONING
######################

# Rule: Green Power Commissioning
#
# Why: Green Power devices have no battery (energy harvesting). Proxy/sink commissioning.
allow if {
    input.action == "commission_green_power"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "commission_green_power")
    not exceeds_rate_limit(input.device.id, "commission_green_power")
}

######################
# 2. TOUCHLINK COMMISSIONING
######################

# Rule: Touchlink Commissioning
#
# Why: Touchlink adds device by physical proximity. No need for install code.
allow if {
    input.action == "commission_touchlink"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "commission_touchlink")
    not exceeds_rate_limit(input.device.id, "commission_touchlink")
}

######################
# 3. INSTALL CODE VALIDATION
######################

# Rule: Install Code Validation
#
# Why: Install code provides out-of-band key. Prevents unauthorized joining.
allow if {
    input.action == "validate_install_code"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_install_code")
    not exceeds_rate_limit(input.device.id, "validate_install_code")
}

######################
# 4. BDB COMMISSIONING
######################

# Rule: BDB Commissioning
#
# Why: Base Device Behavior standardizes commissioning. Network steering, formation, finding.
allow if {
    input.action == "use_bdb"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_bdb")
    not exceeds_rate_limit(input.device.id, "use_bdb")
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
