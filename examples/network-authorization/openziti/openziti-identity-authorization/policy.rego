package openziti_identity_authorization

# OpenZiti Identity Authorization - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for OpenZiti Identity Authorization specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. IDENTITY VERIFICATION
######################

# Rule: Identity Verification
#
# Why: Verify identity using certificate or enrollment token.
allow if {
    input.action == "verify_identity"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "verify_identity")
    not exceeds_rate_limit(input.device.id, "verify_identity")
}

######################
# 2. ENROLLMENT
######################

# Rule: Enrollment
#
# Why: One-time enrollment creates identity certificate.
allow if {
    input.action == "enroll_identity"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enroll_identity")
    not exceeds_rate_limit(input.device.id, "enroll_identity")
}

######################
# 3. CERTIFICATE ROTATION
######################

# Rule: Certificate Rotation
#
# Why: Automatic certificate rotation before expiry.
allow if {
    input.action == "rotate_certificate"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "rotate_certificate")
    not exceeds_rate_limit(input.device.id, "rotate_certificate")
}

######################
# 4. MFA ENFORCEMENT
######################

# Rule: MFA Enforcement
#
# Why: Multi-factor authentication for sensitive services.
allow if {
    input.action == "enforce_mfa"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enforce_mfa")
    not exceeds_rate_limit(input.device.id, "enforce_mfa")
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
