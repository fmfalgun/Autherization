package wifi5

# WiFi 5 (802.11ac) - Very High Throughput Authorization Policy
#
# WiFi 5 introduced major performance improvements over WiFi 4:
# - VHT (Very High Throughput) with 80/160 MHz channels
# - Downlink MU-MIMO (serve up to 4 users simultaneously)
# - 256-QAM modulation (higher data rates)
# - Explicit beamforming (improve range and throughput)
# - Dynamic bandwidth operation
# - Short Guard Interval (400ns)
#
# Why this policy exists:
# WiFi 5 brings enterprise-grade features that need careful management.
# MU-MIMO requires fair allocation, wide channels need interference management,
# and beamforming needs proper steering to avoid interference.
#
# Author: Authorization Framework Team
# Version: 1.0.0

import future.keywords

default allow := false

######################
# VHT CHANNEL AUTHORIZATION
######################

# Rule: Authorize 80 MHz VHT channel usage
#
# 80 MHz channels provide 4x bandwidth of 20 MHz:
# - Requires 4 contiguous 20 MHz channels
# - Primary channel for compatibility
# - Secondary channels for VHT devices
# - DFS (Dynamic Frequency Selection) may be required
#
# Why: 80 MHz is WiFi 5's sweet spot - widely available, good performance
# Must check for radar and ensure regulatory compliance
allow if {
    input.action == "use_80mhz_channel"
    device_wifi5_capable(input.device)
    vht_80mhz_available(input.channel)
    no_radar_interference(input.channel, 80)
    regulatory_permits_80mhz(input.location, input.channel)
}

# Rule: Authorize 160 MHz VHT channel usage
#
# 160 MHz channels double throughput but have limitations:
# - Requires 8 contiguous 20 MHz channels
# - Limited availability (mostly DFS channels)
# - Higher power consumption
# - Only beneficial at close range
#
# Why: 160 MHz is powerful but rare, use only when justified
# High QoS devices in good signal conditions benefit most
allow if {
    input.action == "use_160mhz_channel"
    device_wifi5_capable(input.device)
    device_supports_160mhz(input.device)
    vht_160mhz_available(input.channel)
    no_radar_interference(input.channel, 160)
    signal_strength_sufficient(input.device.rssi)
    device_qos_level(input.device) >= 6
}

######################
# MU-MIMO AUTHORIZATION
######################

# Rule: Assign downlink MU-MIMO spatial streams
#
# WiFi 5 introduces DL MU-MIMO (WiFi 4 only had SU-MIMO):
# - Transmit to up to 4 users simultaneously
# - Each user gets independent spatial stream(s)
# - Requires CSI (Channel State Information) from clients
# - Beamforming steering matrix calculation
#
# Why: MU-MIMO increases network capacity in high-density scenarios
# Conference rooms, offices with many users benefit greatly
allow if {
    input.action == "assign_mu_mimo_dl"
    count(input.devices) >= 2
    count(input.devices) <= 4  # WiFi 5 max 4 users
    all_devices_mu_mimo_capable(input.devices)
    ap_has_sufficient_chains(input.ap, input.devices)
    csi_reports_current(input.devices)
    spatial_correlation_acceptable(input.devices)
}

# Rule: Single-User MIMO (fallback)
#
# When MU-MIMO not beneficial, use SU-MIMO:
# - All spatial streams to one device
# - Higher per-device throughput
# - Better for high-bandwidth single-user scenarios
#
# Why: MU-MIMO has overhead, not always better than SU-MIMO
# Single high-bandwidth user (e.g., 4K video streaming) benefits from SU-MIMO
allow if {
    input.action == "assign_su_mimo"
    device_wifi5_capable(input.device)
    device_supports_mimo(input.device)
    requested_streams := input.requested_streams
    requested_streams <= ap_max_streams(input.ap)
    requested_streams <= device_max_streams(input.device)
}

######################
# BEAMFORMING
######################

# Rule: Enable explicit beamforming
#
# Explicit beamforming uses feedback to steer signal:
# - Client sends CSI feedback
# - AP calculates steering matrix
# - Focused beam improves SNR
# - Better range and throughput
#
# Why: Beamforming is crucial for WiFi 5 performance
# Can extend range by 30-50% and improve throughput significantly
allow if {
    input.action == "enable_beamforming"
    device_supports_vht_beamformee(input.device)
    ap_supports_vht_beamformer(input.ap)
    csi_feedback_configured(input.device)
    beamforming_sounding_permitted(input.ap)
}

# Rule: Transmit beamforming sounding frame
#
# Sounding frames measure channel for beamforming:
# - NDP (Null Data Packet) announcement
# - NDP frame with known pattern
# - Client responds with CSI
# - Overhead but necessary for beamforming
#
# Why: Sounding enables beamforming but uses airtime
# Rate-limit to balance beamforming benefits vs overhead
allow if {
    input.action == "transmit_sounding"
    beamforming_enabled(input.ap)
    sounding_interval_acceptable(input.last_sounding_time)
    not exceeds_sounding_rate_limit(input.ap)
}

######################
# 256-QAM MODULATION
######################

# Rule: Use 256-QAM modulation
#
# 256-QAM provides higher data rate than 64-QAM:
# - 8 bits per symbol (vs 6 bits for 64-QAM)
# - Requires SNR > 25 dB
# - 33% higher data rate
# - Sensitive to interference
#
# Why: 256-QAM only works with clean signal
# Automatically select based on signal quality
allow if {
    input.action == "use_256qam"
    device_supports_256qam(input.device)
    signal_quality_good(input.device.rssi, input.device.snr)
    input.device.snr >= 25
    interference_level_low(input.channel)
}

######################
# DYNAMIC BANDWIDTH OPERATION
######################

# Rule: Dynamic bandwidth switching
#
# Adapt channel width based on conditions:
# - Start with wide channel (80/160 MHz)
# - Fall back to narrow (40/20 MHz) if interference
# - Automatic or manual selection
# - Optimize throughput vs reliability
#
# Why: Wide channels offer speed but narrow channels reliability
# Dynamic switching gets best of both worlds
allow if {
    input.action == "switch_bandwidth"
    input.new_bandwidth in [20, 40, 80, 160]
    current_bandwidth := data.device_bandwidth[input.device.mac]
    bandwidth_change_justified(current_bandwidth, input.new_bandwidth, input.reason)
    new_bandwidth_available(input.channel, input.new_bandwidth)
}

######################
# CONNECTION & AUTHENTICATION
######################

allow if {
    input.action == "authenticate"
    device_credentials_valid(input.device)
    device_wifi5_capable(input.device)
    device_not_blacklisted(input.device.id)
}

allow if {
    input.action == "connect"
    device_authenticated(input.device.id)
    network_has_capacity(input.network)
    vht_features_negotiated(input.device)
}

allow if {
    input.action == "transmit"
    device_connected(input.device.id)
    data_within_quota(input.device.id, input.data_size)
}

######################
# HELPER FUNCTIONS
######################

device_wifi5_capable(device) if { device.wifi5_capable == true }
device_supports_160mhz(device) if { device.max_bandwidth_mhz >= 160 }
vht_80mhz_available(channel) if { data.channel_availability[channel][80] == true }
vht_160mhz_available(channel) if { data.channel_availability[channel][160] == true }
no_radar_interference(channel, bw) if { not channel in data.radar_channels }
regulatory_permits_80mhz(location, channel) if { location.country in ["US", "EU", "JP"] }
signal_strength_sufficient(rssi) if { rssi >= -65 }
device_qos_level(device) := data.authorized_devices[device.id].qos_level

all_devices_mu_mimo_capable(devices) if {
    every d in devices { data.authorized_devices[d.id].mu_mimo_capable == true }
}

ap_has_sufficient_chains(ap, devices) if {
    total_streams := sum([d.requested_streams | d := devices[_]])
    total_streams <= data.access_points[ap].spatial_streams
}

csi_reports_current(devices) if {
    every d in devices {
        csi_age := time.now_ns() - data.csi_reports[d.id].timestamp
        csi_age < 100000000  # 100ms
    }
}

spatial_correlation_acceptable(devices) if { count(devices) <= 4 }
ap_max_streams(ap) := data.access_points[ap].spatial_streams
device_max_streams(device) := data.authorized_devices[device.id].max_spatial_streams
device_supports_mimo(device) if { device.mimo_capable == true }
device_supports_vht_beamformee(device) if { data.authorized_devices[device.id].beamformee_capable == true }
ap_supports_vht_beamformer(ap) if { data.access_points[ap].beamformer_capable == true }
csi_feedback_configured(device) if { data.authorized_devices[device.id].csi_feedback_enabled == true }
beamforming_sounding_permitted(ap) if { data.access_points[ap].beamforming_enabled == true }
beamforming_enabled(ap) if { data.access_points[ap].beamforming_enabled == true }

sounding_interval_acceptable(last_time) if {
    interval := time.now_ns() - last_time
    interval >= 100000000  # Min 100ms between soundings
}

exceeds_sounding_rate_limit(ap) if {
    count := data.sounding_counts[ap]
    count >= 10  # Max 10 soundings per second
}

device_supports_256qam(device) if { data.authorized_devices[device.id].max_qam >= 256 }

signal_quality_good(rssi, snr) if {
    rssi >= -60
    snr >= 25
}

interference_level_low(channel) if { data.interference_levels[channel] < 30 }
bandwidth_change_justified(current, new, reason) if { reason in ["interference", "performance", "admin"] }
new_bandwidth_available(channel, bw) if { data.channel_availability[channel][bw] == true }
device_credentials_valid(device) if { device.id in data.authorized_devices }
device_not_blacklisted(device_id) if { not device_id in data.blacklisted_devices }
device_authenticated(device_id) if { data.active_sessions[device_id] != null }

network_has_capacity(network) if {
    current := count(data.connected_devices[network.id])
    max := data.networks[network.id].max_devices
    current < max
}

vht_features_negotiated(device) if { data.vht_negotiations[device.id].completed == true }
device_connected(device_id) if { some network_id; data.connected_devices[network_id][device_id] != null }

data_within_quota(device_id, data_size) if {
    current := data.bandwidth_usage[device_id]
    quota := data.authorized_devices[device_id].quota
    current + data_size <= quota
}
