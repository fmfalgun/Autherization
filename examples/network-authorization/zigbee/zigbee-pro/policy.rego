package zigbee_pro

# Zigbee PRO (Professional Features) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Zigbee PRO (Professional Features) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. GROUP ADDRESSING
######################

# Rule: Group Addressing
#
# Why: Multicast to group of devices with single transmission. Efficient for lighting control.
allow if {
    input.action == "use_group_addressing"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_group_addressing")
    not exceeds_rate_limit(input.device.id, "use_group_addressing")
}

######################
# 2. FRAGMENTATION
######################

# Rule: Fragmentation
#
# Why: Fragment large packets up to 1500 bytes. APS-level fragmentation with reassembly.
allow if {
    input.action == "fragment_packet"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "fragment_packet")
    not exceeds_rate_limit(input.device.id, "fragment_packet")
}

######################
# 3. FREQUENCY AGILITY
######################

# Rule: Frequency Agility
#
# Why: Frequency Agility changes channel if interference detected. Network manager coordinates.
allow if {
    input.action == "change_channel"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "change_channel")
    not exceeds_rate_limit(input.device.id, "change_channel")
}

######################
# 4. SOURCE ROUTING
######################

# Rule: Source Routing
#
# Why: Source specifies full route to destination. Deterministic latency for industrial.
allow if {
    input.action == "use_source_routing"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_source_routing")
    not exceeds_rate_limit(input.device.id, "use_source_routing")
}

######################
# 5. MANY-TO-ONE ROUTING
######################

# Rule: Many-to-One Routing
#
# Why: Many devices route to central concentrator. Efficient for sensor networks.
allow if {
    input.action == "configure_many_to_one"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "configure_many_to_one")
    not exceeds_rate_limit(input.device.id, "configure_many_to_one")
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
