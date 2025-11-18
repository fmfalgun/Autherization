package bluetooth_classic_3.0

# Bluetooth 3.0 + HS (High Speed) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Bluetooth 3.0 + HS (High Speed) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. HIGH SPEED (WIFI PAL)
######################

# Rule: High Speed (WiFi PAL)
#
# Why: High Speed over WiFi (802.11) for 24+ Mbps. Negotiated via BT, data over WiFi.
allow if {
    input.action == "use_hs"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_hs")
    not exceeds_rate_limit(input.device.id, "use_hs")
}

######################
# 2. L2CAP ENHANCED RETRANSMISSION
######################

# Rule: L2CAP Enhanced Retransmission
#
# Why: Enhanced Retransmission Mode for reliable data transfer. Alternative to RFCOMM.
allow if {
    input.action == "use_ertm"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_ertm")
    not exceeds_rate_limit(input.device.id, "use_ertm")
}

######################
# 3. UNICAST CONNECTIONLESS DATA
######################

# Rule: Unicast Connectionless Data
#
# Why: Connectionless data for low-latency applications. No connection setup overhead.
allow if {
    input.action == "send_ucd"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "send_ucd")
    not exceeds_rate_limit(input.device.id, "send_ucd")
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
