package wifi_enterprise

# WiFi Enterprise (WPA2/WPA3-Enterprise) - Protocol-Specific Authorization Policy
#
# This policy implements detailed authorization for WiFi Enterprise (WPA2/WPA3-Enterprise) specific features.
# Each rule is tailored to the unique capabilities and requirements of this protocol version.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false


######################
# 1. RADIUS AUTHENTICATION
######################

# Rule: RADIUS Authentication
#
# Why: RADIUS server validates credentials centrally. Supports username/password and certificates.
allow if {
    input.action == "authenticate_radius"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "authenticate_radius")
    not exceeds_rate_limit(input.device.id, "authenticate_radius")
}

######################
# 2. 802.1X EAP-TLS
######################

# Rule: 802.1X EAP-TLS
#
# Why: EAP-TLS uses certificates for strong authentication. Most secure but requires PKI.
allow if {
    input.action == "use_eap_tls"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_eap_tls")
    not exceeds_rate_limit(input.device.id, "use_eap_tls")
}

######################
# 3. 802.1X EAP-TTLS/PEAP
######################

# Rule: 802.1X EAP-TTLS/PEAP
#
# Why: EAP-TTLS/PEAP tunnel credentials securely. Simpler than EAP-TLS, only server cert needed.
allow if {
    input.action == "use_eap_ttls"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "use_eap_ttls")
    not exceeds_rate_limit(input.device.id, "use_eap_ttls")
}

######################
# 4. DYNAMIC VLAN ASSIGNMENT
######################

# Rule: Dynamic VLAN Assignment
#
# Why: RADIUS assigns VLAN based on user/group. Network segmentation without manual config.
allow if {
    input.action == "assign_dynamic_vlan"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "assign_dynamic_vlan")
    not exceeds_rate_limit(input.device.id, "assign_dynamic_vlan")
}

######################
# 5. CERTIFICATE VALIDATION
######################

# Rule: Certificate Validation
#
# Why: X.509 certificate validation prevents MITM. Check expiry, revocation, trust chain.
allow if {
    input.action == "validate_certificate"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "validate_certificate")
    not exceeds_rate_limit(input.device.id, "validate_certificate")
}

######################
# 6. COA (CHANGE OF AUTHORIZATION)
######################

# Rule: CoA (Change of Authorization)
#
# Why: RADIUS CoA updates client authorization dynamically. Disconnect or change VLAN without reassociation.
allow if {
    input.action == "process_coa"
    device_authenticated(input.device.id)
    device_supports_feature(input.device, "process_coa")
    not exceeds_rate_limit(input.device.id, "process_coa")
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
