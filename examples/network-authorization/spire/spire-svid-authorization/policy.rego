package spire_svid_authorization

# SPIRE SVID Authorization - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for SPIRE SVID Authorization specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. X.509-SVID VALIDATION
######################

# Rule: X.509-SVID Validation
#
# Why: Validate X.509-SVID certificate chain, expiry, revocation.
allow if {
    input.action == "validate_x509_svid"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_x509_svid")
    not exceeds_rate_limit(input.device.id, "validate_x509_svid")
}

######################
# 2. JWT-SVID VALIDATION
######################

# Rule: JWT-SVID Validation
#
# Why: Validate JWT-SVID signature, claims, expiry.
allow if {
    input.action == "validate_jwt_svid"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_jwt_svid")
    not exceeds_rate_limit(input.device.id, "validate_jwt_svid")
}

######################
# 3. SPIFFE ID MATCHING
######################

# Rule: SPIFFE ID Matching
#
# Why: Match SPIFFE ID against authorization policy.
allow if {
    input.action == "match_spiffe_id"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "match_spiffe_id")
    not exceeds_rate_limit(input.device.id, "match_spiffe_id")
}

######################
# 4. FEDERATION
######################

# Rule: Federation
#
# Why: Cross trust domain authorization via federation.
allow if {
    input.action == "authorize_federation"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "authorize_federation")
    not exceeds_rate_limit(input.device.id, "authorize_federation")
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
