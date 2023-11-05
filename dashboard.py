import streamlit as st
import pyshark
import pandas as pd
import plotly.graph_objects as go
import numpy as np
import os
from collections import defaultdict

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
        group_address = packet_info['igmp_group_address']
        if igmp_type == 'Membership Query':
            self.possible_queriers.add(src_ip)
            last_query_time = self.last_igmp_query_time.get(src_ip, 0)
            # Check if this is the earliest querier or if it's a new election
            if (not self.elected_querier or src_ip < self.elected_querier) and current_time - last_query_time > self.election_timeout:
                self.elected_querier = src_ip
            self.last_igmp_query_time[src_ip] = current_time
        elif igmp_type in ('Membership Report', 'Leave Group'):
            path_set = self.allowed_paths if igmp_type == 'Membership Report' else self.denied_paths
            path_set[group_address].add(src_ip)

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
    # Dictionary of PTP message types
    ptp_message_types = {
        '0x00': 'PTP_Sync',
        '0x01': 'PTP_Delay_Req',
        '0x02': 'PTP_Pdelay_Req',
        '0x03': 'PTP_Pdelay_Resp',
        '0x08': 'PTP_Follow_Up',
        '0x09': 'PTP_Delay_Resp',
        '0x0a': 'PTP_Pdelay_Resp_Follow_Up',
        '0x0b': 'PTP_Announce',
        '0x0c': 'PTP_Signaling',
        '0x0d': 'PTP_Management',
        # Add any additional or custom message types here
    }

    # Determines the type of the packet and gathers basic info
    packet_type = 'Non-IP'
    packet_info = {'packet_number': packet_number}
    
    if hasattr(packet, 'ip'):
        packet_type = 'audio' if packet.ip.dst.startswith('239.') else packet.highest_layer
        packet_info.update({
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'src_port': packet[packet.transport_layer].srcport if packet.transport_layer else None,
            'dst_port': packet[packet.transport_layer].dstport if packet.transport_layer else None,
        })

    # Check for PTP layer and classify PTP messages
    if hasattr(packet, 'ptp') and packet.ptp:
        ptp_message_type_code = packet.ptp.get_field_value('ptp.v2.messagetype')
        packet_type = ptp_message_types.get(ptp_message_type_code, 'Unknown_PTP_Type')

        # Update packet_info with PTP specific details
        packet_info.update({
            'sequence_id': packet.ptp.get_field_value('ptp.v2.sequenceid'),
            'source_port_id': packet.ptp.get_field_value('ptp.v2.sourceportid'),
            'clock_identity': packet.ptp.get_field_value('ptp.v2.clockidentity'),
            'origin_timestamp_seconds': packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.seconds'),
            'origin_timestamp_nanoseconds': packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.nanoseconds'),
        })

    # Classification logic for IGMP
    if hasattr(packet, 'igmp'):
        packet_type = 'IGMP'
        igmp_type = packet.igmp.type
        igmp_group_address = packet.igmp.group_address
        packet_info.update({
            'igmp_type': igmp_type,
            'igmp_group_address': igmp_group_address,
        })

    # Add packet_type to packet_info
    packet_info['packet_type'] = packet_type

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
        if ptype != 'audio':
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

# Function to calculate and display summary statistics in Streamlit
def display_summary_statistics(packet_data, packet_type):
    if packet_type in packet_data and packet_data[packet_type]['inter_arrival_times']:
        times = packet_data[packet_type]['inter_arrival_times']
        min_val = np.min(times)
        max_val = np.max(times)
        median_val = np.median(times)
        mean_val = np.mean(times)
        std_dev = np.std(times)

        # Create a DataFrame for the summary statistics
        summary_df = pd.DataFrame({
            'Minimum (ms)': [f"{min_val:.3f}"],
            'Maximum (ms)': [f"{max_val:.3f}"],
            'Median (ms)': [f"{median_val:.3f}"],
            'Mean (ms)': [f"{mean_val:.3f}"],
            'Std Deviation (ms)': [f"{std_dev:.3f}"]
        })

        # Display the DataFrame
        st.write(f"{packet_type.capitalize()} Packet Inter-arrival Times Summary:")
        st.dataframe(summary_df)

def calculate_bandwidth(capture, interval_duration=1):
    # Extract packet lengths and timestamps, filtering out non-IP packets
    packet_lengths = np.array([int(packet.length) for packet in capture if hasattr(packet, 'ip')])
    packet_timestamps = np.array([float(packet.sniff_timestamp) for packet in capture if hasattr(packet, 'ip')])

    # Find the start and end times
    start_time = np.min(packet_timestamps)
    end_time = np.max(packet_timestamps)
    duration = end_time - start_time
    
    # Calculate bytes per source-destination pair for IP packets only
    src_dst_pairs = [(packet.ip.src, packet.ip.dst) for packet in capture if hasattr(packet, 'ip')]
    unique_pairs, indices = np.unique(src_dst_pairs, return_inverse=True, axis=0)
    total_bytes = np.bincount(indices, weights=packet_lengths)

    # Calculate average bandwidth (Mbps)
    avg_bandwidth = (total_bytes * 8) / (duration * 1e6)

    # Calculate maximum bandwidth (Mbps) within smaller intervals
    num_intervals = int(np.ceil(duration / interval_duration))
    max_bandwidth = np.zeros(len(unique_pairs))

    for i in range(num_intervals):
        interval_mask = (packet_timestamps >= (start_time + i * interval_duration)) & \
                        (packet_timestamps < (start_time + (i + 1) * interval_duration))
        interval_indices = indices[interval_mask]
        interval_lengths = packet_lengths[interval_mask]
        interval_bytes = np.bincount(interval_indices, weights=interval_lengths, minlength=len(unique_pairs))
        interval_bandwidth = (interval_bytes * 8) / (interval_duration * 1e6)
        max_bandwidth = np.maximum(max_bandwidth, interval_bandwidth)

    return unique_pairs, avg_bandwidth, max_bandwidth


def create_connections_dataframe(packet_data, capture):
    # Calculate bandwidth
    unique_pairs, avg_bandwidth, max_bandwidth = calculate_bandwidth(capture)
    
    # Convert unique_pairs from a NumPy array to a list of tuples for easy lookup
    unique_pairs_list = [tuple(pair) for pair in unique_pairs]
    
    # Dictionary to hold the aggregated data before creating DataFrame
    aggregated_data = {}

    # Aggregate packet data by source-destination pair and protocol
    for ptype, data in packet_data.items():
        
        # Skip IGMP data for this aggregation as it has a different structure
        if ptype == 'IGMP':
            continue

        for info in data['info']:
            if info.get('src_ip') and info.get('dst_ip'):
                src_dst_pair = (info['src_ip'], info['dst_ip'])
                if src_dst_pair in unique_pairs_list:
                    pair_index = unique_pairs_list.index(src_dst_pair)
                    avg_bw = avg_bandwidth[pair_index]
                    max_bw = max_bandwidth[pair_index]
                else:
                    avg_bw = max_bw = 0  # No bandwidth if pair not found
                
                protocol = 'Multicast Audio' if info['dst_ip'].startswith('239.') else ptype
                key = (src_dst_pair[0], src_dst_pair[1], protocol)

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
        'Protocol': key[2],
        'Packet Count': value['Packet Count'],
        'Traffic % per source': (value['Packet Count'] / sum([v['Packet Count'] for v in aggregated_data.values() if v])) * 100,
        'Avg Mbps': value['Average Bandwidth (Mbps)'],
        'Max Mbps': value['Maximum Bandwidth (Mbps)']
    } for key, value in aggregated_data.items()]

    # Convert the list of dictionaries to a DataFrame in one go
    df = pd.DataFrame(rows)
    df.sort_values(by=['Source IP', 'Destination IP', 'Protocol'], inplace=True)
    
    return df



def plot_inter_arrival_times_histogram(packet_data):
    if 'audio' not in packet_data:
        return None

    audio_times = packet_data['audio']['inter_arrival_times']
    if not audio_times:
        return None

    # Since we are using a log scale, filter out any times that are 0
    audio_times = [time for time in audio_times if time > 0]

    # Calculate the number of bins to use
    num_bins = 50

    # Define bins for histogram with equal width in log space
    min_time = min(audio_times)
    max_time = max(audio_times)
    log_min = np.log10(min_time)
    log_max = np.log10(max_time)
    log_bins = np.logspace(log_min, log_max, num=num_bins)

    # Create the histogram data
    histogram_data = np.histogram(audio_times, bins=log_bins)
    bin_counts = histogram_data[0]
    bin_edges = histogram_data[1]

    # Use a scatter plot to simulate bars with 'lines+markers' and fill below the line
    fig = go.Figure(data=go.Scatter(
        x=bin_edges.repeat(2)[1:-1],
        y=np.repeat(bin_counts, 2),
        mode='lines',
        line=dict(
            color='rgba(0, 100, 80, .8)',  # Single color for all 'bars'
            shape='hv'  # Create a horizontal line followed by a vertical line
        ),
        fill='tozeroy'  # Fill the area under the line
    ))

    # Update the layout to use log scales
    fig.update_layout(
        title='2D Histogram of Audio Packet Inter-arrival Times',
        xaxis=dict(
            title='Inter-arrival Time (ms)',
            type='log',
            tickformat='.3f'
        ),
        yaxis=dict(
            title='Quantity',
            type='log'
        ),
        template='plotly_white'
    )

    return fig

# Streamlit interface
st.set_page_config(layout="wide")
st.title("Packet Capture Analysis Dashboard")
st.write("\n")

# File uploader
uploaded_file = st.sidebar.file_uploader("Choose a pcap file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    with st.spinner("Processing, this may take a while if the file is large..."):
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
        st.markdown('---')

        # Audio packets histogram
        histogram_fig = plot_inter_arrival_times_histogram(packet_data)
        if histogram_fig is not None:
            st.plotly_chart(histogram_fig)
            display_summary_statistics(packet_data, 'audio')
            st.markdown('---')

        # Inter-arrival times
        other_fig = plot_inter_arrival_times_box(packet_data)
        st.plotly_chart(other_fig)

        # PTP packets stats
        if 'PTP_Sync' in packet_data:
            display_summary_statistics(packet_data, 'PTP_Sync')

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)
