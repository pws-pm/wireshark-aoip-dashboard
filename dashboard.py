import streamlit as st
import pyshark
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
import os
from collections import defaultdict

# Define PTP message types for analysis
ptp_types = [
    'PTP_v2_Sync', 'PTP_v2_Delay_Req', 'PTP_v2_Pdelay_Req', 'PTP_v2_Pdelay_Resp',
    'PTP_v2_Follow_Up', 'PTP_v2_Delay_Resp', 'PTP_v2_Pdelay_Resp_Follow_Up',
    'PTP_v2_Announce', 'PTP_v2_Signaling', 'PTP_v2_Management',
    'PTP_v1_Sync', 'PTP_v1_Delay_Req', 'PTP_v1_Follow_Up', 'PTP_v1_Delay_Resp', 'PTP_v1_Management'
]

# Define mappings for clock accuracy and time source based on IEEE 1588 specification
clock_accuracy_mapping = {
    0x17: "within 1 ps",
    0x18: "within 2.5 ps",
    0x19: "within 10 ps",
    0x1A: "within 25 ps",
    0x1B: "within 100 ps",
    0x1C: "within 250 ps",
    0x1D: "within 1 ns",
    0x1E: "within 2.5 ns",
    0x1F: "within 10 ns",
    0x20: "within 25 ns",
    0x21: "within 100 ns",
    0x22: "within 250 ns",
    0x23: "within 1 us",
    0x24: "within 2.5 us",
    0x25: "within 10 us",
    0x26: "within 25 us",
    0x27: "within 100 us",
    0x28: "within 250 us",
    0x29: "within 1 ms",
    0x2A: "within 2.5 ms",
    0x2B: "within 10 ms",
    0x2C: "within 25 ms",
    0x2D: "within 100 ms",
    0x2E: "within 250 ms",
    0x2F: "within 1 s",
    0x30: "within 10 s",
    0x31: "within >10 s",
    0x32: "reserved",
    0x80: "for alternate profiles",
    0xFE: "accuracy unknown",
    0xFF: "reserved"
}

time_source_mapping = {
    0x10: "atomic clock",
    0x20: "gps",
    0x30: "terrestrial radio",
    0x40: "ptp",
    0x50: "ntp",
    0x60: "handset",
    0x90: "other",
    0xA0: "internal oscillator",
    0xF0: "master clock (arb timescale)",
    0xF1: "master clock (initially local reference)",
    # 0xF2 to 0xFE: "for use by alternate ptp profiles",  # This range can be handled as a special case in your code
    0xFF: "reserved"
}


class IGMPProcessor:
    def __init__(self, election_timeout=255):  # Default value can be set here, 255 is a bit more than twice the standard Query Interval
        self.election_timeout = election_timeout
        self.possible_queriers = set()
        self.elected_querier = None
        self.allowed_paths = defaultdict(set)
        self.denied_paths = defaultdict(set)
        self.last_igmp_query_time = defaultdict(float)

    def process_igmp_packet(self, packet_info, current_time):
        src_ip = packet_info['src_ip']
        igmp_type = packet_info['igmp_type']
        igmp_maddr = packet_info['igmp_maddr']
        igmp_version = packet_info.get('igmp_version', '2')  # Default to IGMPv2 if not provided

        # Check for Membership Query
        if igmp_type == 'Membership Query':
            self.possible_queriers.add(src_ip)
            last_query_time = self.last_igmp_query_time.get(src_ip, 0)
            if (not self.elected_querier or src_ip < self.elected_querier) and current_time - last_query_time > self.election_timeout:
                self.elected_querier = src_ip
            self.last_igmp_query_time[src_ip] = current_time

        # Check for Membership Report and Leave Group
        elif igmp_type in ('Membership Report', 'Leave Group'):
            # Only process these if a valid multicast address is associated with the report/leave
            if igmp_maddr and igmp_maddr != '0.0.0.0':
                path_set = self.allowed_paths if igmp_type == 'Membership Report' else self.denied_paths
                path_set[igmp_maddr].add(src_ip)
                # For IGMPv1, the source IP is also the group address
                if igmp_version == '1' and igmp_type == 'Membership Report':
                    path_set[src_ip].add(src_ip)

    def get_igmp_info(self):
        return {
            'possible_queriers': self.possible_queriers,
            'elected_querier': self.elected_querier,
            'allowed_paths': self.allowed_paths,
            'denied_paths': self.denied_paths,
        }

# Function to load the pcap file using PyShark
def load_capture(file_path):
    # We use only_summaries=False to get detailed packet info
    return pyshark.FileCapture(file_path, only_summaries=False)

def classify_packet(packet, packet_number, igmp_info=None):
    ptp_v2_message_types = {
        '0x00': 'PTP_v2_Sync',
        '0x01': 'PTP_v2_Delay_Req',
        '0x02': 'PTP_v2_Pdelay_Req',
        '0x03': 'PTP_v2_Pdelay_Resp',
        '0x08': 'PTP_v2_Follow_Up',
        '0x09': 'PTP_v2_Delay_Resp',
        '0x0a': 'PTP_v2_Pdelay_Resp_Follow_Up',
        '0x0b': 'PTP_v2_Announce',
        '0x0c': 'PTP_v2_Signaling',
        '0x0d': 'PTP_v2_Management',
    }
    ptp_v1_message_types = {
        '0': 'PTP_v1_Sync',
        '1': 'PTP_v1_Delay_Req',
        '2': 'PTP_v1_Follow_Up',
        '3': 'PTP_v1_Delay_Resp',
        '4': 'PTP_v1_Management',
    }

    # Determines the type of the packet and gathers basic info
    packet_type = 'Non-IP'
    packet_info = {'packet_number': packet_number, 'local_capture_timestamp': float(packet.sniff_timestamp)}
    
    try:
        if hasattr(packet, 'ip'):
            dst_port = packet[packet.transport_layer].dstport if packet.transport_layer and hasattr(packet, packet.transport_layer) else None

            # Check for Dante and Multicast Audio classification
            if hasattr(packet, 'udp') and packet.udp:
                udp_dst_port = int(packet.udp.dstport)
                if 14336 <= udp_dst_port <= 14591:
                    packet_type = 'Audio_DanteUnicast|' + packet.ip.dst + ':' + str(udp_dst_port)
                elif 34336 <= udp_dst_port <= 34600:
                    packet_type = 'Audio_DanteViaUnicast|' + packet.ip.dst + ':' + str(udp_dst_port)
                elif packet.ip.dst.startswith('239.') and dst_port:
                    packet_type = 'Audio_Multicast|' + packet.ip.dst + ':' + dst_port

            # Non-Dante audio packets classification
            elif packet.ip.dst.startswith('239.') and dst_port:
                packet_type = 'Audio_Multicast|' + packet.ip.dst + ':' + dst_port
            else:
                packet_type = packet.highest_layer

            packet_info.update({
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'src_port': packet[packet.transport_layer].srcport if packet.transport_layer else None,
                'dst_port': dst_port
            })

            # Check for PTP layer and classify PTP messages
            if hasattr(packet, 'ptp'):
                # Handle PTP v2 packets
                if hasattr(packet.ptp, 'v2.versionptp'):
                    ptp_message_type_code = packet.ptp.get_field_value('ptp.v2.messagetype')
                    packet_type = ptp_v2_message_types.get(ptp_message_type_code.lower(), 'Unknown_PTP_Type')

                    # Common fields for all PTP v2 packets
                    packet_info.update({
                        'sequence_id': packet.ptp.get_field_value('ptp.v2.sequenceid'),
                        'source_port_id': packet.ptp.get_field_value('ptp.v2.sourceportid'),
                        'clock_identity': packet.ptp.get_field_value('ptp.v2.clockidentity')
                    })
                    if packet_type == 'PTP_v2_Sync':
                        origin_timestamp_seconds = float(packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.seconds'))
                        origin_timestamp_nanoseconds = float(packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.nanoseconds'))
                        ptp_timestamp = origin_timestamp_seconds + origin_timestamp_nanoseconds / 1e9
                    elif packet_type == 'PTP_v2_Follow_Up':
                        precise_origin_timestamp_seconds = float(packet.ptp.get_field_value('ptp.v2.fu.preciseorigintimestamp.seconds'))
                        precise_origin_timestamp_nanoseconds = float(packet.ptp.get_field_value('ptp.v2.fu.preciseorigintimestamp.nanoseconds'))
                        ptp_timestamp = precise_origin_timestamp_seconds + precise_origin_timestamp_nanoseconds / 1e9
                    elif packet_type == 'PTP_v2_Announce':
                        packet_info.update({
                            'domain_number': packet.ptp.get_field_value('ptp.v2.domainnumber'),
                            'priority1': packet.ptp.get_field_value('ptp.v2.an.priority1'),
                            'grandmaster_clock_class': packet.ptp.get_field_value('ptp.v2.an.grandmasterclockclass'),
                            'grandmaster_clock_accuracy': clock_accuracy_mapping.get(int(packet.ptp.get_field_value('ptp.v2.an.grandmasterclockaccuracy'), 16), 'Unknown'),
                            'grandmaster_clock_variance': packet.ptp.get_field_value('ptp.v2.an.grandmasterclockvariance'),
                            'priority2': packet.ptp.get_field_value('ptp.v2.an.priority2'),
                            'time_source': time_source_mapping.get(int(packet.ptp.get_field_value('ptp.v2.timesource'), 16), 'Unknown')
                        })
                        ptp_timestamp = None  # Explicitly set to None as no timestamp calculation is required
                    else:
                        ptp_timestamp = None


                    if ptp_timestamp is not None:
                        local_timestamp = packet_info['local_capture_timestamp']
                        packet_info['ptp_time_offset'] = local_timestamp - ptp_timestamp

                # Handle PTP v1 packets
                elif hasattr(packet.ptp, 'versionptp'):
                    ptp_message_type_code = packet.ptp.get_field_value('ptp.controlfield')
                    packet_type = ptp_v1_message_types.get(ptp_message_type_code.lower(), 'Unknown_PTP_Type')

                    # Common fields for all PTP v1 packets
                    packet_info.update({
                        'sequence_id': packet.ptp.get_field_value('ptp.sequenceid'),
                        'source_port_id': packet.ptp.get_field_value('ptp.sourceportid'),
                    })

                    # Handle Sync and Delay Request messages for PTP v1
                    if packet_type in ['PTP_v1_Sync', 'PTP_v1_Delay_Req']:
                        packet_info['parent_uuid'] = packet.ptp.get_field_value('ptp.sdr.parentuuid') # MAC address of this slave's currenr master clock
                        packet_info['grandmasterclock_uuid'] = packet.ptp.get_field_value('ptp.sdr.grandmasterclockuuid') # MAC address of the grand master clock
                        ptp_timestamp = float(packet.ptp.get_field_value('ptp.sdr.origintimestamp'))
                    elif packet_type == 'PTP_v1_Follow_Up':
                        ptp_timestamp = float(packet.ptp.get_field_value('ptp.fu.preciseorigintimestamp'))
                    elif packet_type == 'PTP_v1_Delay_Resp':
                        ptp_timestamp = float(packet.ptp.get_field_value('ptp.dr.delayreceipttimestamp'))
                    else:
                        ptp_timestamp = None

                    if ptp_timestamp is not None:
                        local_timestamp = packet_info['local_capture_timestamp']
                        packet_info['ptp_time_offset'] = local_timestamp - ptp_timestamp

                else:
                    packet_type = 'Unknown_PTP_Type'


        # Classification logic for IGMP
        if 'igmp' in packet:
            packet_type = 'IGMP'
            igmp_version = packet.igmp.version
            igmp_type_code = packet.igmp.type
            igmp_maddr = packet.igmp.maddr

            # Map the hex type codes to strings for IGMPv2 and IGMPv3
            igmp_type_map_v2_v3 = {
                '0x11': 'Membership Query',
                '0x16': 'Membership Report',
                '0x17': 'Leave Group',
                # Add any additional or custom IGMP types here for v2 and v3
            }

            # IGMPv1 specific mapping
            igmp_type_map_v1 = {
                '0x12': 'Membership Report',
                # Add any additional or custom IGMP types here for v1
            }

            # Determine the IGMP type based on the version
            if igmp_version == '1':
                igmp_type = igmp_type_map_v1.get(igmp_type_code, f"Unknown IGMPv1 Type ({igmp_type_code})")
            else:
                igmp_type = igmp_type_map_v2_v3.get(igmp_type_code, f"Unknown IGMP Type ({igmp_type_code})")

            packet_info.update({
                'igmp_version': igmp_version,
                'igmp_type': igmp_type,
                'igmp_maddr': igmp_maddr,
            })

        # Add packet_type to packet_info
        packet_info['packet_type'] = packet_type
    
    except Exception as e:
        st.error(f"Error classifying packet #{packet_number}: {e}")

    return packet_type, packet_info




def calculate_inter_arrival_time(packet, packet_info, packet_type, last_timestamps):
    # Calculates and updates the inter-arrival time for a packet
    current_timestamp = float(packet.sniff_timestamp)
    if packet_type not in last_timestamps:
        last_timestamps[packet_type] = current_timestamp
    else:
        delta_ms = (current_timestamp - last_timestamps[packet_type]) * 1000
        packet_info['delta_ms'] = delta_ms
        last_timestamps[packet_type] = current_timestamp

def initialize_packet_data_structure(packet_data, packet_type):
    # Initializes packet data structure if it doesn't exist
    if packet_type not in packet_data:
        packet_data[packet_type] = {'inter_arrival_times': [], 'info': []}

def update_packet_data_structure(packet_data, packet_type, packet_info):
    # Initialize the packet type key if it does not exist
    if packet_type not in packet_data:
        packet_data[packet_type] = {'inter_arrival_times': [], 'info': []}

    # Updates the packet data structure with new packet info
    packet_data[packet_type]['info'].append(packet_info)
    if 'delta_ms' in packet_info:
        packet_data[packet_type]['inter_arrival_times'].append(packet_info['delta_ms'])


def process_packets(capture):
    packet_data = defaultdict(lambda: defaultdict(list))
    last_timestamps = {}
    igmp_processor = IGMPProcessor(election_timeout=255)

    for packet_number, packet in enumerate(capture, start=1):
        packet_type, packet_info = classify_packet(packet, packet_number)
        calculate_inter_arrival_time(packet, packet_info, packet_type, last_timestamps)
        update_packet_data_structure(packet_data, packet_type, packet_info)

        # Process IGMP separately
        if packet_type == 'IGMP':
            igmp_processor.process_igmp_packet(packet_info, float(packet.sniff_timestamp))

    # Merge IGMP info into packet_data
    packet_data['IGMP']['info'] = igmp_processor.get_igmp_info()

    return packet_data


# Function to create a Plotly box plot for inter-arrival times per packet type with log scale for non audio
def plot_inter_arrival_times_box(packet_data):
    # Create box plot for other packet types
    other_fig = go.Figure()
    for ptype, data in packet_data.items():
        # Check if the packet type does NOT start with 'Audio_'
        if not ptype.startswith('Audio_'):  # Corrected condition to exclude all audio streams
            other_fig.add_trace(go.Box(
                y=data['inter_arrival_times'],
                name=ptype,
                boxpoints='outliers',  # Show outliers
                jitter=0.5,  # Add some jitter for better visualization
                marker=dict(size=2)
            ))
    other_fig.update_layout(
        title='Non-Audio Packet Inter-arrival Times (ms)',
        yaxis_title='Time (milliseconds)',
        template='plotly_white'
    )

    return other_fig

def calculate_bandwidth(capture, interval_duration=0.1):
    # Extract packet lengths, timestamps, and flow information
    packets_info = [(int(packet.length), float(packet.sniff_timestamp), 
                     packet.ip.src, packet.ip.dst, 
                     packet[packet.transport_layer].srcport if packet.transport_layer else 'None', 
                     packet[packet.transport_layer].dstport if packet.transport_layer else 'None') 
                    for packet in capture if hasattr(packet, 'ip')]

    # Organize packets by flow
    flows = {}
    for length, timestamp, src_ip, dst_ip, src_port, dst_port in packets_info:
        flow = (src_ip, dst_ip, src_port, dst_port)
        if flow not in flows:
            flows[flow] = {'timestamps': [], 'lengths': []}
        flows[flow]['timestamps'].append(timestamp)
        flows[flow]['lengths'].append(length)

    # Initialize bandwidth results
    unique_flows = list(flows.keys())
    avg_bandwidth = np.zeros(len(unique_flows))
    max_bandwidth = np.zeros(len(unique_flows))

    # Calculate bandwidth for each flow
    for i, flow in enumerate(unique_flows):
        timestamps = flows[flow]['timestamps']
        lengths = flows[flow]['lengths']

        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        total_bytes = sum(lengths)

        # Check for zero duration to avoid division by zero
        if duration > 0:
            avg_bandwidth[i] = (total_bytes * 8) / (duration * 1e6)
        else:
            avg_bandwidth[i] = 0

        # Maximum bandwidth using a smaller sliding window
        sorted_packets = sorted(zip(timestamps, lengths))

        for j in range(len(sorted_packets)):
            window_start_time = sorted_packets[j][0]
            window_end_time = window_start_time + interval_duration
            window_bytes = sum(packet[1] for packet in sorted_packets if window_start_time <= packet[0] < window_end_time)
            window_bandwidth = (window_bytes * 8) / (interval_duration * 1e6)
            max_bandwidth[i] = max(max_bandwidth[i], window_bandwidth)

    return unique_flows, avg_bandwidth, max_bandwidth

def create_connections_dataframe(packet_data, capture):
    # Calculate bandwidth
    unique_flows, avg_bandwidth, max_bandwidth = calculate_bandwidth(capture)
    
    # Convert unique_flows from a NumPy array to a list of tuples for easy lookup
    unique_flows_list = [tuple(flow) for flow in unique_flows]
    
    # Dictionary to hold the aggregated data before creating DataFrame
    aggregated_data = {}

    # Aggregate packet data by flow
    for ptype, data in packet_data.items():
        # Skip IGMP data for this aggregation
        if ptype == 'IGMP':
            continue

        for info in data['info']:
            if info.get('src_ip') and info.get('dst_ip'):
                flow = (info['src_ip'], info['dst_ip'], info.get('src_port', 'None'), info.get('dst_port', 'None'))
                if flow in unique_flows_list:
                    flow_index = unique_flows_list.index(flow)
                    avg_bw = avg_bandwidth[flow_index]
                    max_bw = max_bandwidth[flow_index]
                else:
                    avg_bw = max_bw = 0

                simplified_protocol = ptype.split('|')[0]
                key = (info['src_ip'], info['dst_ip'], info.get('dst_port', 'None'), simplified_protocol)

                if key not in aggregated_data:
                    aggregated_data[key] = {
                        'Packet Count': 0,
                        'Total Bytes': 0,
                        'Average Bandwidth (Mbps)': avg_bw,
                        'Maximum Bandwidth (Mbps)': max_bw
                    }
                
                aggregated_data[key]['Packet Count'] += 1
                aggregated_data[key]['Total Bytes'] += info.get('length', 0)

    # Prepare the data for DataFrame creation
    rows = [{
        'Source IP': key[0],
        'Destination IP': key[1],
        'Port': key[2],
        'Protocol': key[3],
        'Packet Count': value['Packet Count'],
        'Traffic % per source': (value['Packet Count'] / sum([v['Packet Count'] for v in aggregated_data.values() if v])) * 100,
        'Avg Mbps': value['Average Bandwidth (Mbps)'],
        'Max Mbps': value['Maximum Bandwidth (Mbps)']
    } for key, value in aggregated_data.items()]

    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame(rows)
    df.sort_values(by=['Source IP', 'Destination IP', 'Port', 'Protocol'], inplace=True)
    
    return df






def calculate_stats(times, packet_type):
    # Calculate statistics
    min_val = np.min(times)
    max_val = np.max(times)
    median_val = np.median(times)
    mean_val = np.mean(times)
    std_dev = np.std(times)

    # Return a dictionary with the statistics and the packet type (as flow)
    return {
        'Flow': packet_type.replace('Audio_', '').replace('_', ':').capitalize(),
        'Minimum (ms)': f"{min_val:.3f}",
        'Maximum (ms)': f"{max_val:.3f}",
        'Median (ms)': f"{median_val:.3f}",
        'Mean (ms)': f"{mean_val:.3f}",
        'Std Deviation (ms)': f"{std_dev:.3f}"
    }

def calculate_summary_stats(packet_data, packet_type_prefix):
    all_stats = []
    for packet_type, data in packet_data.items():
        if packet_type.startswith(packet_type_prefix) and data['inter_arrival_times']:
            times = data['inter_arrival_times']
            stats = calculate_stats(times, packet_type)
            all_stats.append(stats)

    return pd.DataFrame(all_stats)


def packet_ranges(packet_numbers):
    if not packet_numbers:
        return []

    # Sort packet numbers and initialize the first range
    sorted_packets = sorted(packet_numbers)
    ranges = [[sorted_packets[0], sorted_packets[0]]]

    for packet in sorted_packets[1:]:
        if packet == ranges[-1][1] + 1:
            # Extend the current range
            ranges[-1][1] = packet
        else:
            # Start a new range
            ranges.append([packet, packet])

    # Convert ranges to strings, combining contiguous packets into ranges
    range_strings = []
    for packet_range in ranges:
        if packet_range[0] == packet_range[1]:
            range_strings.append(str(packet_range[0]))
        else:
            range_strings.append(f"{packet_range[0]}-{packet_range[1]}")

    return range_strings

def tooltip_content_for_bin(bin_packets, max_display=5):
    # Get ranges for contiguous packets
    packet_display = packet_ranges(bin_packets)

    # If there are too many packet ranges, truncate the list
    if len(packet_display) > max_display:
        packet_display = packet_display[:max_display] + ["..."]

    return ", ".join(packet_display)

def plot_audio_streams_histogram(packet_data, summary_stats):
    MAX_PACKETS_DISPLAYED = 5
    PAD_RATIO = 0.05

    audio_streams = [ptype for ptype in packet_data if ptype.startswith('Audio_')]
    num_streams = len(audio_streams)
    if num_streams == 0:
        return None

    fig = make_subplots(rows=num_streams, cols=1, subplot_titles=audio_streams)

    for i, stream in enumerate(audio_streams, start=1):
        stream_data = packet_data[stream]['inter_arrival_times']
        packet_numbers = [info['packet_number'] for info in packet_data[stream]['info']]

        # Retrieve median value and convert it to float
        median_val_series = summary_stats.loc[summary_stats['Flow'] == stream.replace('Audio_', '').replace('_', ':').capitalize(), 'Median (ms)']
        if not median_val_series.empty:
            median_val = float(median_val_series.iloc[0])
        else:
            continue  # Skip this stream if the median value is not available

        double_median_val = 2 * median_val

        filtered_stream_data = [(time, pkt_num) for time, pkt_num in zip(stream_data, packet_numbers) if time > 0]
        if filtered_stream_data:
            stream_times = [time for time, _ in filtered_stream_data]
            if not stream_times:
                continue

            min_time = max(min(stream_times), 1e-3)
            max_time = max(stream_times)
            padded_min_time = min_time / (1 + PAD_RATIO)
            padded_max_time = max_time * (1 + PAD_RATIO)

            # Dynamically adjust the number of bins based on the range
            time_range = padded_max_time - padded_min_time
            num_bins = min(max(int(time_range * 10000), 20), 100)  # Clamp the bin number between two values

            linear_bins = np.linspace(padded_min_time, padded_max_time, num_bins)
            bin_midpoints = (linear_bins[:-1] + linear_bins[1:]) / 2

            histogram_data = np.histogram(stream_times, bins=linear_bins)
            bin_counts = histogram_data[0]
            bar_colors = ['red' if time >= double_median_val else 'darkgreen' for time in bin_midpoints]

            bin_packet_numbers = [[] for _ in range(num_bins)]
            for time, packet_num in filtered_stream_data:
                bin_index = np.digitize(time, linear_bins) - 1
                bin_packet_numbers[bin_index].append(packet_num)

            customdata = [tooltip_content_for_bin(bin_packet_numbers[bin_index], MAX_PACKETS_DISPLAYED) for bin_index in range(num_bins)]

            fig.add_trace(
                go.Bar(
                    x=bin_midpoints,
                    y=bin_counts,
                    name=stream,
                    marker_color=bar_colors,
                    customdata=customdata,
                    hovertemplate="<b>Bin Range: %{x:.2f} ms</b><br>Packet index: %{customdata}<extra></extra>"
                ),
                row=i,
                col=1
            )

            fig.update_xaxes(title='Inter-arrival Time (ms)', type='linear', range=[padded_min_time, padded_max_time], row=i, col=1)

    fig.update_layout(title='Histogram of Audio Packet Inter-arrival Times per Stream', template='plotly_white', height=300 * num_streams, showlegend=False)

    for j in range(1, num_streams + 1):
        fig.update_yaxes(title='Quantity', type='log', row=j, col=1)

    return fig

def create_ptp_relationships_dataframe(packet_data):
    devices = {}
    ptp_versions = {'PTP_v1_': 'PTP v1', 'PTP_v2_': 'PTP v2'}

    for packet_type, data in packet_data.items():
        if 'PTP_v1_' in packet_type or 'PTP_v2_' in packet_type:
            for packet in data['info']:
                src_ip = packet['src_ip']
                protocol = ptp_versions[packet_type[:7]]

                if 'PTP_v1_' in packet_type:
                    # For PTP v1, use parent_uuid for master-slave relationship
                    if 'Sync' in packet_type or 'Delay_Req' in packet_type:
                        master_uuid = packet.get('parent_uuid', None)
                        if master_uuid:
                            # Slave device
                            devices[src_ip] = {'role': 'Slave', 'master_uuid': master_uuid, 'protocol': protocol}
                        else:
                            # Master device
                            devices[src_ip] = {'role': 'Master', 'master_uuid': None, 'protocol': protocol}
                # Add similar logic for PTP v2 if needed

    device_list = [{'IP Address': ip, **details} for ip, details in devices.items()]
    return pd.DataFrame(device_list)


def visualize_igmp_info(igmp_info):
    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and edges for allowed paths
    for group, members in igmp_info['allowed_paths'].items():
        G.add_node(group, role='group', color='green')
        for member in members:
            G.add_node(member, role='member', color='blue')
            G.add_edge(member, group, color='green')

    # Add nodes and edges for denied paths
    for group, members in igmp_info['denied_paths'].items():
        G.add_node(group, role='group', color='red')
        for member in members:
            G.add_node(member, role='denied_member', color='orange')
            G.add_edge(member, group, color='red')

    # Add nodes for possible queriers
    for pq in igmp_info['possible_queriers']:
        if pq not in G:
            G.add_node(pq, role='possible_querier', color='purple')

    # Highlight the elected querier
    if igmp_info['elected_querier']:
        G.add_node(igmp_info['elected_querier'], role='elected_querier', color='gold')

    # Extract positions in a circular layout
    pos = nx.circular_layout(G)

    # Extract node and edge information for plotting
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    # Create the Plotly figure
    fig = go.Figure()

    # Add edges as lines
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines'))

    # Add nodes as scatter points
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=[f"{node}<br>{G.nodes[node]['role']}" for node in G.nodes()],
        marker=dict(showscale=False, color=[G.nodes[node]['color'] for node in G.nodes()], size=10, line_width=2)
    ))

    # Update the layout
    fig.update_layout(
        showlegend=False,
        hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=0),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )

    # Return the figure
    return fig

# Streamlit interface
st.set_page_config(layout="wide")
st.title("Packet Capture Analysis Dashboard")
st.write("\n")

# File uploader
uploaded_file = st.sidebar.file_uploader("Choose a pcap file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    with st.spinner("Processing, this may take several minutes if the file is large ..."):
        # Save the uploaded file to a temporary file
        temp_file_path = "temp.pcapng"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        
        capture = load_capture(temp_file_path)

        # Process packets and calculate inter-arrival times
        packet_data = process_packets(capture)

        # Connections DataFrame
        connections_df = create_connections_dataframe(packet_data, capture)
        st.header("Connections Overview")
        st.markdown("Protocols used by each source IP, bandwidth, and percentage of traffic for each protocol per source IP.")
        st.dataframe(connections_df)
        # Sum of Average Bandwidth
        total_avg_bandwidth = connections_df['Avg Mbps'].sum()
        st.markdown(f"**Total Average Bandwidth:** {total_avg_bandwidth:.2f} Mbps")
        st.markdown('---')

        # Calculate and display summary statistics for audio packets
        audio_summary_stats = calculate_summary_stats(packet_data, "Audio_")

        # Audio packets histogram
        audio_histogram_fig = plot_audio_streams_histogram(packet_data, audio_summary_stats)
        if audio_histogram_fig is not None:
            st.plotly_chart(audio_histogram_fig)
            st.dataframe(audio_summary_stats)
            st.markdown('---')

        # Inter-arrival times for other packet types
        other_fig = plot_inter_arrival_times_box(packet_data)
        st.plotly_chart(other_fig)

        # Display statistics for specific packet types
        if 'PTP_v2_Sync' in packet_data:
            ptp_v2_sync_stats = calculate_summary_stats(packet_data, 'PTP_v2_')
            st.dataframe(ptp_v2_sync_stats)

        if 'PTP_v1_Sync' in packet_data:
            ptp_v1_sync_stats = calculate_summary_stats(packet_data, 'PTP_v1_')
            st.dataframe(ptp_v1_sync_stats)

        # Create and display the PTP master-client relationships DataFrame
        st.header("PTP Overview")
        ptp_relationships_df = create_ptp_relationships_dataframe(packet_data)
        st.dataframe(ptp_relationships_df)

        # IGMP Visualization
        if 'IGMP' in packet_data:
            igmp_info = packet_data['IGMP']['info']
            igmp_visualization_figure = visualize_igmp_info(igmp_info)
            if igmp_visualization_figure is not None:
                st.header("IGMP Traffic Map")
                st.plotly_chart(igmp_visualization_figure)

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)
