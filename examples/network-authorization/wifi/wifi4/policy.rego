package wifi4

# WiFi 4 (802.11n - High Throughput) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for WiFi 4 (802.11n - High Throughput) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. 40MHZ CHANNEL BONDING
######################

# Rule: 40MHz Channel Bonding
#
# Why: Bonds two 20MHz channels for 2x throughput. Must check for interference on secondary channel.
allow if {
    input.action == "use_40mhz_bonding"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_40mhz_bonding")
    not exceeds_rate_limit(input.device.id, "use_40mhz_bonding")
}

######################
# 2. 4X4 MIMO SPATIAL STREAMS
######################

# Rule: 4x4 MIMO Spatial Streams
#
# Why: Up to 4 spatial streams enable 600 Mbps. Each stream needs separate antenna chain.
allow if {
    input.action == "allocate_mimo_streams"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "allocate_mimo_streams")
    not exceeds_rate_limit(input.device.id, "allocate_mimo_streams")
}

######################
# 3. A-MPDU AGGREGATION
######################

# Rule: A-MPDU Aggregation
#
# Why: A-MPDU aggregates multiple frames into one transmission. Reduces overhead significantly.
allow if {
    input.action == "use_ampdu"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_ampdu")
    not exceeds_rate_limit(input.device.id, "use_ampdu")
}

######################
# 4. A-MSDU AGGREGATION
######################

# Rule: A-MSDU Aggregation
#
# Why: A-MSDU combines multiple packets into single frame. Lower overhead than A-MPDU but less robust.
allow if {
    input.action == "use_amsdu"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_amsdu")
    not exceeds_rate_limit(input.device.id, "use_amsdu")
}

######################
# 5. SHORT GUARD INTERVAL
######################

# Rule: Short Guard Interval
#
# Why: Short GI (400ns vs 800ns) provides 11% speed boost. Only works with good signal quality.
allow if {
    input.action == "use_short_gi"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_short_gi")
    not exceeds_rate_limit(input.device.id, "use_short_gi")
}

######################
# 6. GREENFIELD MODE
######################

# Rule: Greenfield Mode
#
# Why: Greenfield mode disables legacy 802.11a/b/g support for efficiency. WiFi 4-only network.
allow if {
    input.action == "use_greenfield"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_greenfield")
    not exceeds_rate_limit(input.device.id, "use_greenfield")
}

######################
# 7. STBC (SPACE-TIME BLOCK CODING)
######################

# Rule: STBC (Space-Time Block Coding)
#
# Why: STBC improves reliability by transmitting redundant data. Better range at cost of throughput.
allow if {
    input.action == "enable_stbc"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_stbc")
    not exceeds_rate_limit(input.device.id, "enable_stbc")
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
