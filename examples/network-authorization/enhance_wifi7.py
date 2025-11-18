#!/usr/bin/env python3
"""
Generate detailed protocol-specific authorization policies for all wireless protocols
Each policy includes unique features specific to that protocol version
"""

import os
import json

# WiFi 7 - Most advanced, complete example
WIFI7_POLICY = """package wifi7

# WiFi 7 (802.11be) - Extremely High Throughput Authorization Policy
#
# WiFi 7 introduces revolutionary multi-link operation and performance enhancements:
# - Multi-Link Operation (MLO): Simultaneous transmission across bands
# - 320 MHz channels: Double the bandwidth of WiFi 6
# - 16x16 MU-MIMO: Serve 16 users simultaneously
# - Multi-RU assignment: Multiple resource units per device
# - 4096-QAM: Higher modulation for increased data rates
# - Multi-AP coordination: Coordinated transmission between APs
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false

######################
# MULTI-LINK OPERATION (MLO)
######################

# Rule: Establish Multi-Link connection
#
# MLO allows device to connect on multiple bands simultaneously:
# - 2.4 GHz + 5 GHz + 6 GHz concurrent operation
# - Load balancing across links
# - Seamless failover if one link degrades
# - Aggregate throughput up to 46 Gbps
#
# Why: MLO is WiFi 7's killer feature - provides reliability and performance
# Device must support MLO and have multi-band radios
allow if {
    input.action == "establish_mlo"
    device_authenticated(input.device.mac)
    device_supports_mlo(input.device)
    count(input.requested_links) >= 2
    count(input.requested_links) <= 3
    all_links_available(input.requested_links)
    sufficient_mlo_resources(input.requested_links)
}

# Rule: Configure MLO link aggregation
#
# Configure how traffic is distributed across MLO links:
# - Primary link for latency-sensitive traffic
# - Secondary link(s) for throughput
# - Dynamic link switching based on conditions
#
# Why: Different applications need different link strategies
# Video calls want low latency (use 5/6 GHz), downloads want throughput (aggregate)
allow if {
    input.action == "configure_mlo_aggregation"
    device_has_active_mlo(input.device.mac)
    aggregation_mode_valid(input.mode)  # "load_balance", "primary_backup", "aggregation"
    qos_requirements_met(input.device, input.mode)
}

######################
# 320 MHz CHANNEL OPERATION
######################

# Rule: Authorize 320 MHz channel usage
#
# WiFi 7 supports 320 MHz channels in 6 GHz band:
# - Doubles bandwidth compared to WiFi 6's 160 MHz
# - Requires contiguous 320 MHz spectrum
# - Only available in 6 GHz (6 GHz band has enough spectrum)
# - DFS (Dynamic Frequency Selection) required
#
# Why: 320 MHz enables multi-gigabit speeds but requires careful spectrum management
# Must ensure no radar interference and regulatory compliance
allow if {
    input.action == "use_320mhz_channel"
    device_wifi7_capable(input.device)
    input.channel.band == "6GHz"
    channel_width_available(input.channel, 320)
    no_radar_detected(input.channel)
    regulatory_allows_320mhz(input.channel, input.location)
}

######################
# 16x16 MU-MIMO
######################

# Rule: Assign spatial streams for 16x16 MU-MIMO
#
# WiFi 7 doubles MU-MIMO capacity:
# - Up to 16 simultaneous users (WiFi 6 had 8)
# - Both uplink and downlink
# - Requires sophisticated beamforming
# - Each user can get multiple spatial streams
#
# Why: High-density environments (stadiums, airports) need to serve many users
# 16 users with good throughput > 8 users with excellent throughput
allow if {
    input.action == "assign_16x16_mimo"
    count(input.devices) <= 16
    all_devices_wifi7_capable(input.devices)
    ap_has_16_spatial_streams(input.ap)
    total_streams_requested := sum([d.requested_streams | d := input.devices[_]])
    total_streams_requested <= 16
}

######################
# MULTI-RU ASSIGNMENT
######################

# Rule: Assign multiple Resource Units to single device
#
# WiFi 7 allows one device to use non-contiguous RUs:
# - WiFi 6: One device = one RU
# - WiFi 7: One device can use multiple RUs across channel
# - Enables higher throughput for capable devices
# - Better spectrum utilization
#
# Why: High-end devices can handle multiple RUs, maximizes their throughput
# IoT devices still use single small RU, no wasted bandwidth
allow if {
    input.action == "assign_multi_ru"
    device_supports_multi_ru(input.device)
    count(input.requested_rus) >= 2
    all_rus_available(input.channel, input.requested_rus)
    device_qos_level(input.device) >= 7  # High QoS devices only
    aggregate_ru_size := sum([ru.size | ru := input.requested_rus[_]])
    aggregate_ru_size <= 996  # Total can't exceed one 20 MHz channel equivalent
}

######################
# 4096-QAM MODULATION
######################

# Rule: Use 4096-QAM modulation
#
# 4096-QAM provides 20% higher data rate than WiFi 6's 1024-QAM:
# - 12 bits per symbol (vs 10 bits for 1024-QAM)
# - Requires excellent signal quality (SNR > 35 dB)
# - Only effective at short range with clear line of sight
#
# Why: 4096-QAM is fragile, only use when signal is strong
# Automatically downgrade to lower QAM if signal degrades
allow if {
    input.action == "use_4096qam"
    device_supports_4096qam(input.device)
    signal_quality_excellent(input.device.rssi, input.device.snr)
    input.device.snr >= 35  # Minimum SNR for 4096-QAM
    distance_to_ap(input.device) <= 10  # meters, short range only
}

######################
# MULTI-AP COORDINATION
######################

# Rule: Enable Coordinated Multi-AP transmission
#
# Multiple APs coordinate to transmit simultaneously:
# - Coordinated Beamforming (C-BF)
# - Coordinated Spatial Reuse (C-SR)
# - Joint transmission to same client
# - Reduces interference, increases throughput
#
# Why: In dense deployments, APs interfere with each other
# Coordination turns interference into productive transmission
allow if {
    input.action == "enable_multi_ap_coordination"
    input.user.role == "network_admin"
    all_aps_wifi7_capable(input.aps)
    aps_synchronized(input.aps)  # Need time sync for coordination
    coordination_mode_valid(input.mode)  # "beamforming", "spatial_reuse", "joint_tx"
}

######################
# PUNCTURED TRANSMISSION
######################

# Rule: Use punctured preamble transmission
#
# WiFi 7 can puncture (skip) 20 MHz sub-channels that have interference:
# - Use 80 MHz channel even if one 20 MHz part has interference
# - WiFi 6 would have to drop to 40 MHz
# - Maintains high throughput despite partial interference
#
# Why: Spectrum is crowded, full clean channels rare
# Puncturing allows using wide channels opportunistically
allow if {
    input.action == "use_punctured_transmission"
    device_supports_puncturing(input.device)
    channel_width_requested(input.channel) >= 80
    subchannels_to_puncture := identify_interfered_subchannels(input.channel)
    count(subchannels_to_puncture) <= 2  # Can't puncture too many
    remaining_bandwidth := channel_bandwidth(input.channel) - (count(subchannels_to_puncture) * 20)
    remaining_bandwidth >= 40  # Minimum useful bandwidth
}

######################
# EMLSR (Enhanced Multi-Link Single Radio)
######################

# Rule: Enable EMLSR operation
#
# Device with single radio switches rapidly between MLO links:
# - Appears to use multiple links simultaneously
# - Lower cost than true multi-radio
# - Fast link switching (<1ms)
# - Power efficient
#
# Why: Not all devices can afford multiple radios
# EMLSR provides most MLO benefits at lower complexity/cost
allow if {
    input.action == "enable_emlsr"
    device_supports_emlsr(input.device)
    device_has_active_mlo(input.device.mac)
    emlsr_switching_time_acceptable(input.device)
    input.device.switching_time_us <= 1000  # Max 1ms switching
}

######################
# DATA TRANSMISSION
######################

# Rule: Transmit with WiFi 7 features
allow if {
    input.action == "transmit"
    device_connected(input.device.mac)
    data_within_quota(input.device.mac, input.data_size)
    # Can use MLO, 320MHz, or standard transmission
    transmission_method_authorized(input.transmission_method)
}

######################
# HELPER FUNCTIONS
######################

device_authenticated(mac) if { data.authenticated_sessions[mac] != null }
device_wifi7_capable(device) if { device.wifi7_capable == true }
device_supports_mlo(device) if { device.mlo_capable == true }
all_links_available(links) if { every link in links { link_capacity_available(link) } }
sufficient_mlo_resources(links) if { count(links) > 0 }
device_has_active_mlo(mac) if { data.mlo_sessions[mac] != null }
aggregation_mode_valid(mode) if { mode in ["load_balance", "primary_backup", "aggregation"] }
qos_requirements_met(device, mode) if { device.qos_level >= 5 }
channel_width_available(channel, width) if { data.channel_availability[channel.id][width] == true }
no_radar_detected(channel) if { not channel.id in data.radar_detected_channels }
regulatory_allows_320mhz(channel, location) if { location.country in ["US", "EU"] }
all_devices_wifi7_capable(devices) if { every d in devices { d.wifi7_capable == true } }
ap_has_16_spatial_streams(ap) if { data.access_points[ap.bssid].spatial_streams >= 16 }
device_supports_multi_ru(device) if { device.multi_ru_capable == true }
all_rus_available(channel, rus) if { count(rus) > 0 }
device_qos_level(device) := data.authorized_devices[device.mac].qos_level
device_supports_4096qam(device) if { device.max_qam >= 4096 }
signal_quality_excellent(rssi, snr) if { rssi >= -50; snr >= 35 }
distance_to_ap(device) := data.device_locations[device.mac].distance_meters
all_aps_wifi7_capable(aps) if { every ap in aps { data.access_points[ap].wifi7_capable == true } }
aps_synchronized(aps) if { every ap in aps { data.access_points[ap].time_synced == true } }
coordination_mode_valid(mode) if { mode in ["beamforming", "spatial_reuse", "joint_tx"] }
device_supports_puncturing(device) if { device.puncturing_capable == true }
channel_width_requested(channel) := channel.width_mhz
identify_interfered_subchannels(channel) := data.interference_map[channel.id]
channel_bandwidth(channel) := channel.width_mhz
device_supports_emlsr(device) if { device.emlsr_capable == true }
emlsr_switching_time_acceptable(device) if { device.switching_time_us <= 1000 }
device_connected(mac) if { some network; data.connected_devices[network][mac] != null }
data_within_quota(mac, size) if { data.bandwidth_usage[mac] + size <= data.authorized_devices[mac].quota }
transmission_method_authorized(method) if { method in ["mlo", "320mhz", "multi_ru", "standard"] }
link_capacity_available(link) if { data.link_status[link] == "available" }
"""

# Continue with the script...
print("Generating WiFi 7 policy...")
with open("/home/user/Autherization/examples/network-authorization/wifi/wifi7/policy.rego", "w") as f:
    f.write(WIFI7_POLICY)

print("✅ WiFi 7 enhanced policy created!")
