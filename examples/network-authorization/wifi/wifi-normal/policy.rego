package wifi_normal

# WiFi Normal (802.11b/g) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for WiFi Normal (802.11b/g) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. CSMA/CA COLLISION AVOIDANCE
######################

# Rule: CSMA/CA Collision Avoidance
#
# Why: CSMA/CA prevents collisions by listening before transmit. Mandatory for all 802.11.
allow if {
    input.action == "use_csma_ca"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_csma_ca")
    not exceeds_rate_limit(input.device.id, "use_csma_ca")
}

######################
# 2. RTS/CTS HANDSHAKE
######################

# Rule: RTS/CTS Handshake
#
# Why: RTS/CTS solves hidden node problem. Threshold typically 2347 bytes.
allow if {
    input.action == "use_rts_cts"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_rts_cts")
    not exceeds_rate_limit(input.device.id, "use_rts_cts")
}

######################
# 3. FRAME FRAGMENTATION
######################

# Rule: Frame Fragmentation
#
# Why: Fragmentation splits large frames for reliability. Threshold usually 2346 bytes.
allow if {
    input.action == "fragment_frame"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "fragment_frame")
    not exceeds_rate_limit(input.device.id, "fragment_frame")
}

######################
# 4. ACK MECHANISM
######################

# Rule: ACK Mechanism
#
# Why: ACK confirms frame delivery. Missing ACK triggers retransmission.
allow if {
    input.action == "require_ack"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "require_ack")
    not exceeds_rate_limit(input.device.id, "require_ack")
}

######################
# 5. POWER SAVE MODE
######################

# Rule: Power Save Mode
#
# Why: PS mode conserves battery by sleeping between beacons. Critical for mobile devices.
allow if {
    input.action == "enable_power_save"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enable_power_save")
    not exceeds_rate_limit(input.device.id, "enable_power_save")
}

######################
# 6. SHORT/LONG PREAMBLE
######################

# Rule: Short/Long Preamble
#
# Why: Short preamble reduces overhead by 50%. Not compatible with 802.11 (original).
allow if {
    input.action == "use_short_preamble"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_short_preamble")
    not exceeds_rate_limit(input.device.id, "use_short_preamble")
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
