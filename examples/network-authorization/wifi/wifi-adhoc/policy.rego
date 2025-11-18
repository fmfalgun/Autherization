package wifi_adhoc

# WiFi Ad-hoc (IBSS/Mesh) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for WiFi Ad-hoc (IBSS/Mesh) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. IBSS FORMATION
######################

# Rule: IBSS Formation
#
# Why: Independent BSS allows peer-to-peer without AP. Devices elect BSS initiator.
allow if {
    input.action == "form_ibss"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "form_ibss")
    not exceeds_rate_limit(input.device.id, "form_ibss")
}

######################
# 2. PEER DISCOVERY
######################

# Rule: Peer Discovery
#
# Why: Active/passive scanning finds other ad-hoc devices. Beacon interval typically 100 TU.
allow if {
    input.action == "discover_peer"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "discover_peer")
    not exceeds_rate_limit(input.device.id, "discover_peer")
}

######################
# 3. MESH ROUTING (HWMP)
######################

# Rule: Mesh Routing (HWMP)
#
# Why: Hybrid Wireless Mesh Protocol routes through intermediate nodes. Path selection via RREQ/RREP.
allow if {
    input.action == "configure_hwmp"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "configure_hwmp")
    not exceeds_rate_limit(input.device.id, "configure_hwmp")
}

######################
# 4. DIRECT LINK SETUP (DLS)
######################

# Rule: Direct Link Setup (DLS)
#
# Why: DLS creates direct link between two clients on same BSS. Bypasses AP for efficiency.
allow if {
    input.action == "setup_dls"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "setup_dls")
    not exceeds_rate_limit(input.device.id, "setup_dls")
}

######################
# 5. TDLS AUTHORIZATION
######################

# Rule: TDLS Authorization
#
# Why: Tunnel Direct Link Setup for client-to-client communication. Common in WiFi Direct.
allow if {
    input.action == "authorize_tdls"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "authorize_tdls")
    not exceeds_rate_limit(input.device.id, "authorize_tdls")
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
