package spire_workload_attestation

# SPIRE Workload Attestation - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for SPIRE Workload Attestation specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. NODE ATTESTATION
######################

# Rule: Node Attestation
#
# Why: Verify node identity using platform attestor (AWS, GCP, Kubernetes).
allow if {
    input.action == "attest_node"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "attest_node")
    not exceeds_rate_limit(input.device.id, "attest_node")
}

######################
# 2. WORKLOAD ATTESTATION
######################

# Rule: Workload Attestation
#
# Why: Verify workload identity using selectors (Unix, Kubernetes, Docker).
allow if {
    input.action == "attest_workload"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "attest_workload")
    not exceeds_rate_limit(input.device.id, "attest_workload")
}

######################
# 3. SVID ISSUANCE
######################

# Rule: SVID Issuance
#
# Why: Issue X.509-SVID or JWT-SVID based on successful attestation.
allow if {
    input.action == "issue_svid"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "issue_svid")
    not exceeds_rate_limit(input.device.id, "issue_svid")
}

######################
# 4. TRUST DOMAIN VALIDATION
######################

# Rule: Trust Domain Validation
#
# Why: Ensure workload belongs to correct trust domain.
allow if {
    input.action == "validate_trust_domain"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_trust_domain")
    not exceeds_rate_limit(input.device.id, "validate_trust_domain")
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
