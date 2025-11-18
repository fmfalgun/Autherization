package zero_trust_device_trust

# Zero Trust Device Trust - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Zero Trust Device Trust specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. DEVICE POSTURE VALIDATION
######################

# Rule: Device Posture Validation
#
# Why: Check OS version, patches, firewall, AV status.
allow if {
    input.action == "validate_device_posture"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_device_posture")
    not exceeds_rate_limit(input.device.id, "validate_device_posture")
}

######################
# 2. CONTINUOUS COMPLIANCE
######################

# Rule: Continuous Compliance
#
# Why: Ongoing compliance verification, not just at connection time.
allow if {
    input.action == "check_compliance"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "check_compliance")
    not exceeds_rate_limit(input.device.id, "check_compliance")
}

######################
# 3. DEVICE FINGERPRINTING
######################

# Rule: Device Fingerprinting
#
# Why: Unique device identifier prevents impersonation.
allow if {
    input.action == "fingerprint_device"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "fingerprint_device")
    not exceeds_rate_limit(input.device.id, "fingerprint_device")
}

######################
# 4. TRUST SCORE CALCULATION
######################

# Rule: Trust Score Calculation
#
# Why: Dynamic trust score based on behavior, location, time.
allow if {
    input.action == "calculate_trust_score"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "calculate_trust_score")
    not exceeds_rate_limit(input.device.id, "calculate_trust_score")
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
