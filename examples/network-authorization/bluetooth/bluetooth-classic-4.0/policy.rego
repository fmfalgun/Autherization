package bluetooth_classic_4.0

# Bluetooth 4.0 (Dual Mode) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Bluetooth 4.0 (Dual Mode) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. DUAL MODE OPERATION
######################

# Rule: Dual Mode Operation
#
# Why: Both Classic and LE in same device. Share antenna and baseband.
allow if {
    input.action == "enable_dual_mode"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_dual_mode")
    not exceeds_rate_limit(input.device.id, "enable_dual_mode")
}

######################
# 2. LOW ENERGY SUPPORT
######################

# Rule: Low Energy Support
#
# Why: LE uses different PHY and protocols. Coexistence with Classic requires coordination.
allow if {
    input.action == "support_le"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "support_le")
    not exceeds_rate_limit(input.device.id, "support_le")
}

######################
# 3. AMP (ALTERNATE MAC/PHY)
######################

# Rule: AMP (Alternate MAC/PHY)
#
# Why: Generic mechanism for HS. Can use WiFi or other radios for data.
allow if {
    input.action == "use_amp"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_amp")
    not exceeds_rate_limit(input.device.id, "use_amp")
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
