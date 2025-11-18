package lorawan_1.1

# LoRaWAN 1.1 (Security Enhanced) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for LoRaWAN 1.1 (Security Enhanced) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. JOIN SERVER
######################

# Rule: Join Server
#
# Why: Separate Join Server handles OTAA. Better key management and roaming.
allow if {
    input.action == "query_join_server"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "query_join_server")
    not exceeds_rate_limit(input.device.id, "query_join_server")
}

######################
# 2. ROAMING SUPPORT
######################

# Rule: Roaming Support
#
# Why: Passive/handover roaming between networks. Join Server coordinates.
allow if {
    input.action == "enable_roaming"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_roaming")
    not exceeds_rate_limit(input.device.id, "enable_roaming")
}

######################
# 3. SEPARATE NWKSKEY/APPSKEY
######################

# Rule: Separate NwkSKey/AppSKey
#
# Why: LoRaWAN 1.1 separates network and application keys. Better security isolation.
allow if {
    input.action == "use_separate_keys"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_separate_keys")
    not exceeds_rate_limit(input.device.id, "use_separate_keys")
}

######################
# 4. 32-BIT FRAME COUNTERS
######################

# Rule: 32-bit Frame Counters
#
# Why: 32-bit counters prevent rollover. Separate uplink/downlink.
allow if {
    input.action == "use_32bit_counters"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_32bit_counters")
    not exceeds_rate_limit(input.device.id, "use_32bit_counters")
}

######################
# 5. PORT 0 SECURITY
######################

# Rule: Port 0 Security
#
# Why: Port 0 (MAC commands) encrypted with NwkSKey. Prevents MAC command injection.
allow if {
    input.action == "secure_port_0"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "secure_port_0")
    not exceeds_rate_limit(input.device.id, "secure_port_0")
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
