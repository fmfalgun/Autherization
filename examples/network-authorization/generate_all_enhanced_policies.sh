#!/bin/bash
# Generate all enhanced protocol-specific policies
# This script creates detailed policies for every protocol variant

echo "🚀 Generating enhanced protocol-specific policies for ALL wireless protocols..."
echo ""

cd /home/user/Autherization/examples/network-authorization

# Create Python script to generate all policies
python3 << 'PYTHON_SCRIPT'
import os

protocols_data = {
    # WiFi protocols with specific features
    "wifi/wifi-normal": {
        "features": ["CSMA/CA collision avoidance", "RTS/CTS handshake", "Frame fragmentation", "ACK mechanism", "Power save mode"],
        "rules": ["rts_cts_threshold", "fragmentation_threshold", "retry_limits", "power_save_authorization"]
    },
    "wifi/wifi4": {
        "features": ["40MHz channel bonding", "4x4 MIMO", "A-MPDU aggregation", "A-MSDU aggregation", "Short Guard Interval", "Greenfield mode"],
        "rules": ["channel_bonding_auth", "mimo_stream_allocation", "ampdu_configuration", "short_gi_usage"]
    },
    "wifi/wifi5": {
        "features": ["80/160MHz VHT channels", "Downlink MU-MIMO (4 users)", "Beamforming", "256-QAM", "Dynamic bandwidth management"],
        "rules": ["vht_channel_authorization", "mu_mimo_dl_assignment", "beamforming_steering", "dynamic_bandwidth"]
    },
    "wifi/wifi-adhoc": {
        "features": ["IBSS formation", "Peer discovery", "Mesh routing", "Direct Link Setup (DLS)", "TDLS authorization"],
        "rules": ["ibss_join_authorization", "peer_authentication", "mesh_route_authorization", "dls_setup"]
    },
    "wifi/wifi-enterprise": {
        "features": ["RADIUS authentication", "802.1X EAP methods", "Dynamic VLAN assignment", "Certificate validation", "CoA handling"],
        "rules": ["radius_server_auth", "eap_method_selection", "vlan_assignment", "certificate_validation", "coa_processing"]
    },

    # BLE protocols
    "ble/ble-4.0": {
        "features": ["LE advertising", "GATT services", "Connection parameters", "LE encryption", "Attribute protocol"],
        "rules": ["advertising_authorization", "gatt_access_control", "connection_params", "le_encryption_check"]
    },
    "ble/ble-4.2": {
        "features": ["LE Privacy 1.2", "LE Secure Connections", "Data Length Extension", "Link Layer Privacy"],
        "rules": ["privacy_mode_enforcement", "secure_connections_auth", "data_length_negotiation"]
    },
    "ble/ble-5.0": {
        "features": ["2Mbps PHY", "Long Range (Coded PHY)", "Advertising Extensions", "Channel Selection Algorithm #2"],
        "rules": ["phy_selection_auth", "long_range_authorization", "extended_advertising", "tx_power_control"]
    },
    "ble/ble-5.1": {
        "features": ["Direction Finding (AoA/AoD)", "GATT caching", "Advertising Sync Transfer", "Periodic Advertising"],
        "rules": ["direction_finding_auth", "gatt_cache_management", "periodic_adv_authorization"]
    },
    "ble/ble-5.2": {
        "features": ["LE Audio (LC3 codec)", "EATT (Enhanced ATT)", "LE Power Control", "Isochronous Channels"],
        "rules": ["le_audio_authorization", "eatt_channel_allocation", "power_control_enforcement", "isochronous_stream_auth"]
    },
    "ble/ble-5.4": {
        "features": ["PAwR (Periodic Advertising with Responses)", "Advertising Coding Selection", "Enhanced Connection"],
        "rules": ["pawr_authorization", "coding_selection", "connection_enhancement"]
    },

    # Zigbee protocols
    "zigbee/zigbee-3.0": {
        "features": ["Green Power commissioning", "Touchlink commissioning", "Install code validation", "Network steering", "BDB commissioning"],
        "rules": ["green_power_auth", "touchlink_authorization", "install_code_validation", "network_join_auth"]
    },
    "zigbee/zigbee-pro": {
        "features": ["Group addressing", "Fragmentation", "Frequency Agility", "Source routing", "Many-to-one routing"],
        "rules": ["group_address_auth", "fragmentation_policy", "channel_change_auth", "source_route_setup"]
    },

    # LoRaWAN protocols
    "lorawan/lorawan-1.1": {
        "features": ["Join Server", "Roaming support", "Separate NwkSKey/AppSKey", "Frame counter separation", "Handover"],
        "rules": ["join_server_auth", "roaming_authorization", "key_derivation", "handover_processing"]
    },
}

def generate_enhanced_policy(protocol_path, data):
    package_name = protocol_path.split('/')[-1].replace('-', '_')
    features_str = "\\n# - ".join(data['features'])

    policy = f'''package {package_name}_enhanced

# Enhanced {protocol_path.split('/')[-1].upper()} Authorization Policy
#
# Protocol-Specific Features:
# - {features_str}
#
# This policy implements detailed authorization for protocol-specific features
# ensuring secure and efficient operation.

import future.keywords

default allow := false

'''

    # Generate rules for each feature
    for i, (feature, rule) in enumerate(zip(data['features'], data['rules'])):
        policy += f'''
######################
# {i+1}. {feature.upper()}
######################

# Rule: Authorize {feature}
#
# Why this exists: {feature} is critical for {protocol_path.split('/')[-1]} operation
# Proper authorization prevents misuse and ensures network efficiency
allow if {{
    input.action == "{rule}"
    device_authenticated(input.device.id)
    feature_supported(input.device, "{rule}")
    not exceeds_rate_limit(input.device.id, "{rule}")
}}
'''

    # Add helper functions
    policy += '''
######################
# HELPER FUNCTIONS
######################

device_authenticated(device_id) if {
    data.active_sessions[device_id] != null
}

feature_supported(device, feature) if {
    feature in data.authorized_devices[device.id].supported_features
}

exceeds_rate_limit(device_id, action) if {
    count := data.rate_counters[device_id][action]
    limit := data.rate_limits[action]
    count >= limit
}

device_connected(device_id) if {
    some network
    data.connected_devices[network][device_id] != null
}
'''

    # Write to file
    policy_file = f"/home/user/Autherization/examples/network-authorization/{protocol_path}/policy_enhanced.rego"
    with open(policy_file, "w") as f:
        f.write(policy)

    print(f"  ✅ {protocol_path}")

print("Generating enhanced policies...")
for protocol, data in protocols_data.items():
    generate_enhanced_policy(protocol, data)

print("\\n✅ All enhanced policies generated!")
PYTHON_SCRIPT

echo ""
echo "✅ Complete! All protocol-specific policies have been enhanced."
