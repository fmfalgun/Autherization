package lora_class_a

# LoRa Class A (Lowest Power) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for LoRa Class A (Lowest Power) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. UPLINK-TRIGGERED RX WINDOWS
######################

# Rule: Uplink-Triggered RX Windows
#
# Why: Two receive windows after each uplink. RX1 after 1s, RX2 after 2s. Minimizes listening.
allow if {
    input.action == "open_rx_windows"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "open_rx_windows")
    not exceeds_rate_limit(input.device.id, "open_rx_windows")
}

######################
# 2. ADAPTIVE DATA RATE (ADR)
######################

# Rule: Adaptive Data Rate (ADR)
#
# Why: Network server optimizes SF and power for each device. Balances range, airtime, battery.
allow if {
    input.action == "use_adr"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_adr")
    not exceeds_rate_limit(input.device.id, "use_adr")
}

######################
# 3. DUTY CYCLE LIMITS
######################

# Rule: Duty Cycle Limits
#
# Why: EU: 1% duty cycle on most channels. Prevents network saturation.
allow if {
    input.action == "enforce_duty_cycle"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enforce_duty_cycle")
    not exceeds_rate_limit(input.device.id, "enforce_duty_cycle")
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
