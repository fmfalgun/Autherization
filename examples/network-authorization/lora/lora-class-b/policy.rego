package lora_class_b

# LoRa Class B (Scheduled RX) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for LoRa Class B (Scheduled RX) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. BEACON SYNCHRONIZATION
######################

# Rule: Beacon Synchronization
#
# Why: Gateway sends periodic beacons. Devices synchronize for ping slots.
allow if {
    input.action == "sync_to_beacon"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "sync_to_beacon")
    not exceeds_rate_limit(input.device.id, "sync_to_beacon")
}

######################
# 2. PING SLOTS
######################

# Rule: Ping Slots
#
# Why: Scheduled receive slots for downlink. Predictable latency for actuators.
allow if {
    input.action == "configure_ping_slots"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "configure_ping_slots")
    not exceeds_rate_limit(input.device.id, "configure_ping_slots")
}

######################
# 3. TIME SYNCHRONIZATION
######################

# Rule: Time Synchronization
#
# Why: Devices maintain sync between beacons. GPS or network time.
allow if {
    input.action == "maintain_time_sync"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "maintain_time_sync")
    not exceeds_rate_limit(input.device.id, "maintain_time_sync")
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
