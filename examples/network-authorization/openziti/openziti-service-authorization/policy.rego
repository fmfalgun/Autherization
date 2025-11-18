package openziti_service_authorization

# OpenZiti Service Authorization - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for OpenZiti Service Authorization specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. SERVICE POLICIES
######################

# Rule: Service Policies
#
# Why: Policies grant identity access to services. Dial/Bind permissions.
allow if {
    input.action == "evaluate_service_policy"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "evaluate_service_policy")
    not exceeds_rate_limit(input.device.id, "evaluate_service_policy")
}

######################
# 2. POSTURE CHECKS
######################

# Rule: Posture Checks
#
# Why: Verify device posture (OS, patches, AV) before access.
allow if {
    input.action == "verify_posture"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "verify_posture")
    not exceeds_rate_limit(input.device.id, "verify_posture")
}

######################
# 3. EDGE ROUTER SELECTION
######################

# Rule: Edge Router Selection
#
# Why: Choose edge router based on cost, load, geo-location.
allow if {
    input.action == "select_edge_router"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "select_edge_router")
    not exceeds_rate_limit(input.device.id, "select_edge_router")
}

######################
# 4. ZERO TRUST SEGMENTATION
######################

# Rule: Zero Trust Segmentation
#
# Why: Services only accessible to authorized identities.
allow if {
    input.action == "enforce_segmentation"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "enforce_segmentation")
    not exceeds_rate_limit(input.device.id, "enforce_segmentation")
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
