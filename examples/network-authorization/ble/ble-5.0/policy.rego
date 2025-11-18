package ble_5.0

# BLE 5.0 (Long Range & Speed) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 5.0 (Long Range & Speed) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. 2MBPS PHY
######################

# Rule: 2Mbps PHY
#
# Why: 2Mbps PHY doubles data rate for short range. Trades range for speed.
allow if {
    input.action == "use_2m_phy"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_2m_phy")
    not exceeds_rate_limit(input.device.id, "use_2m_phy")
}

######################
# 2. LONG RANGE (CODED PHY)
######################

# Rule: Long Range (Coded PHY)
#
# Why: Coded PHY (S=2 or S=8) extends range 4x. For IoT sensors in large buildings.
allow if {
    input.action == "use_long_range"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_long_range")
    not exceeds_rate_limit(input.device.id, "use_long_range")
}

######################
# 3. ADVERTISING EXTENSIONS
######################

# Rule: Advertising Extensions
#
# Why: Extended advertising up to 255 bytes (vs 31). Secondary channels reduce interference.
allow if {
    input.action == "use_extended_adv"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_extended_adv")
    not exceeds_rate_limit(input.device.id, "use_extended_adv")
}

######################
# 4. TX POWER CONTROL
######################

# Rule: TX Power Control
#
# Why: Dynamic power control optimizes range vs power consumption. Range from -20dBm to +10dBm.
allow if {
    input.action == "control_tx_power"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "control_tx_power")
    not exceeds_rate_limit(input.device.id, "control_tx_power")
}

######################
# 5. CHANNEL SELECTION ALGORITHM #2
######################

# Rule: Channel Selection Algorithm #2
#
# Why: CSA#2 improves coexistence with WiFi and other BLE devices. Better channel distribution.
allow if {
    input.action == "use_csa2"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_csa2")
    not exceeds_rate_limit(input.device.id, "use_csa2")
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
