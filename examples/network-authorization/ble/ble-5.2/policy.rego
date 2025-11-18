package ble_5.2

# BLE 5.2 (LE Audio & EATT) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for BLE 5.2 (LE Audio & EATT) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. LE AUDIO (LC3 CODEC)
######################

# Rule: LE Audio (LC3 Codec)
#
# Why: LC3 codec provides better quality at lower bitrates. Enables hearing aids, earbuds.
allow if {
    input.action == "use_lc3_audio"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_lc3_audio")
    not exceeds_rate_limit(input.device.id, "use_lc3_audio")
}

######################
# 2. EATT (ENHANCED ATT)
######################

# Rule: EATT (Enhanced ATT)
#
# Why: Enhanced ATT multiplexes multiple transactions. Eliminates HOL blocking, better throughput.
allow if {
    input.action == "use_eatt"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_eatt")
    not exceeds_rate_limit(input.device.id, "use_eatt")
}

######################
# 3. LE POWER CONTROL
######################

# Rule: LE Power Control
#
# Why: Dynamic power adjustment for optimal link quality. RSSI-based feedback loop.
allow if {
    input.action == "use_power_control"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_power_control")
    not exceeds_rate_limit(input.device.id, "use_power_control")
}

######################
# 4. ISOCHRONOUS CHANNELS
######################

# Rule: Isochronous Channels
#
# Why: Isochronous channels for time-sensitive data (audio). Guaranteed latency, sync multiple streams.
allow if {
    input.action == "create_iso_channel"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "create_iso_channel")
    not exceeds_rate_limit(input.device.id, "create_iso_channel")
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
