package bluetooth_classic_3.0

# Bluetooth 3.0 + HS Authorization Policy
#
# This policy implements authorization for Bluetooth 3.0 + HS
#
# Why this policy exists:
# Bluetooth 3.0 + HS requires specific security controls to ensure:
# - Device authentication and validation
# - Access control based on device capabilities
# - Resource allocation and management
# - Anomaly detection and prevention
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

######################
# DEFAULT DENY
######################

# Default deny - all actions denied unless explicitly allowed
default allow := false

######################
# DEVICE AUTHENTICATION
######################

# Rule: Authenticate device
#
# Why: Ensures only authorized devices can connect
allow if {
    input.action == "authenticate"
    device_credentials_valid(input.device)
    device_not_blacklisted(input.device.id)
}

######################
# CONNECTION AUTHORIZATION
######################

# Rule: Allow device connection
#
# Why: Validates device after authentication
allow if {
    input.action == "connect"
    device_authenticated(input.device.id)
    network_has_capacity(input.network)
}

######################
# DATA TRANSMISSION
######################

# Rule: Allow data transmission
#
# Why: Ensures data transfer is authorized and within quotas
allow if {
    input.action == "transmit"
    device_connected(input.device.id)
    data_within_quota(input.device.id, input.data_size)
}

######################
# RESOURCE MANAGEMENT
######################

# Rule: Allocate network resources
#
# Why: Prevents resource exhaustion
allow if {
    input.action == "allocate_resources"
    input.user.role == "network_admin"
    resources_available(input.requested_resources)
}

######################
# HELPER FUNCTIONS
######################

device_credentials_valid(device) if {
    device.id in data.authorized_devices
}

device_not_blacklisted(device_id) if {
    not device_id in data.blacklisted_devices
}

device_authenticated(device_id) if {
    data.active_sessions[device_id] != null
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

resources_available(requested) if {
    requested > 0
}
