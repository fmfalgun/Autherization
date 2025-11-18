package lorawan_1.0.4

# LoRaWAN 1.0.4 - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for LoRaWAN 1.0.4 specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. REJOIN REQUEST TYPE 0/2
######################

# Rule: Rejoin Request Type 0/2
#
# Why: Rejoin for key renewal and roaming. Type 0 for roaming, Type 2 for rekey.
allow if {
    input.action == "send_rejoin"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "send_rejoin")
    not exceeds_rate_limit(input.device.id, "send_rejoin")
}

######################
# 2. IMPROVED OTAA
######################

# Rule: Improved OTAA
#
# Why: Enhanced OTAA with RejoinReq. Better security and reliability.
allow if {
    input.action == "use_improved_otaa"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_improved_otaa")
    not exceeds_rate_limit(input.device.id, "use_improved_otaa")
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
