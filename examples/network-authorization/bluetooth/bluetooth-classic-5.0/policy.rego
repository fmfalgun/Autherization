package bluetooth_classic_5.0

# Bluetooth 5.0 (Long Range & Mesh) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Bluetooth 5.0 (Long Range & Mesh) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. BLUETOOTH MESH
######################

# Rule: Bluetooth Mesh
#
# Why: Many-to-many communication for IoT. Publish/subscribe and flooding-based.
allow if {
    input.action == "enable_mesh"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_mesh")
    not exceeds_rate_limit(input.device.id, "enable_mesh")
}

######################
# 2. SLOT AVAILABILITY MASK
######################

# Rule: Slot Availability Mask
#
# Why: SAM indicates available slots for better coexistence. Especially with LTE.
allow if {
    input.action == "use_sam"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_sam")
    not exceeds_rate_limit(input.device.id, "use_sam")
}

######################
# 3. LE FEATURES IN CLASSIC
######################

# Rule: LE Features in Classic
#
# Why: BT 5.0 Classic benefits from LE enhancements. Better coexistence, lower power.
allow if {
    input.action == "support_le_features"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "support_le_features")
    not exceeds_rate_limit(input.device.id, "support_le_features")
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
