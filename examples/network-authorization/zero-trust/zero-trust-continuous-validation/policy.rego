package zero_trust_continuous_validation

# Zero Trust Continuous Validation - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for Zero Trust Continuous Validation specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. CONTINUOUS AUTHENTICATION
######################

# Rule: Continuous Authentication
#
# Why: Ongoing authentication, not just initial. Detect session hijacking.
allow if {
    input.action == "continuous_auth"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "continuous_auth")
    not exceeds_rate_limit(input.device.id, "continuous_auth")
}

######################
# 2. BEHAVIORAL ANALYSIS
######################

# Rule: Behavioral Analysis
#
# Why: Detect anomalous behavior (unusual access patterns, times, locations).
allow if {
    input.action == "analyze_behavior"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "analyze_behavior")
    not exceeds_rate_limit(input.device.id, "analyze_behavior")
}

######################
# 3. RISK-BASED ACCESS
######################

# Rule: Risk-Based Access
#
# Why: Adjust access level based on current risk score.
allow if {
    input.action == "risk_based_access"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "risk_based_access")
    not exceeds_rate_limit(input.device.id, "risk_based_access")
}

######################
# 4. JUST-IN-TIME ACCESS
######################

# Rule: Just-In-Time Access
#
# Why: Temporary access grants that auto-revoke. Minimize exposure window.
allow if {
    input.action == "grant_jit_access"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "grant_jit_access")
    not exceeds_rate_limit(input.device.id, "grant_jit_access")
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
