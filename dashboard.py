import streamlit as st
import pyshark
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
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
        if hasattr(packet, 'ip'):
            dst_port = packet[packet.transport_layer].dstport if packet.transport_layer and hasattr(packet, packet.transport_layer) else None
            if packet.ip.dst.startswith('239.') and dst_port:  # Check if it's a multicast packet, typically used for audio/video streaming and has a transport layer
                packet_type = 'audio_' + packet.ip.dst + '_' + dst_port
            else:
                packet_type = packet.highest_layer  # Non-audio packets are classified by the highest layer protocol

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
        # Check if the packet type does NOT start with 'audio_'
        if not ptype.startswith('audio_'):  # Corrected condition to exclude all audio streams
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


def calculate_stats(times, packet_type):
    # Calculate statistics
    min_val = np.min(times)
    max_val = np.max(times)
    median_val = np.median(times)
    mean_val = np.mean(times)
    std_dev = np.std(times)

    # Return a dictionary with the statistics and the packet type (as flow)
    return {
        'Flow': packet_type.replace('audio_', '').replace('_', ':').capitalize(),
        'Minimum (ms)': f"{min_val:.3f}",
        'Maximum (ms)': f"{max_val:.3f}",
        'Median (ms)': f"{median_val:.3f}",
        'Mean (ms)': f"{mean_val:.3f}",
        'Std Deviation (ms)': f"{std_dev:.3f}"
    }

def display_summary_statistics(packet_data, packet_type=None):
    # List to hold all statistics data
    all_stats = []

    # If a specific packet type is provided, display statistics only for that type
    if packet_type:
        if packet_type in packet_data and packet_data[packet_type]['inter_arrival_times']:
            times = packet_data[packet_type]['inter_arrival_times']
            stats = calculate_stats(times, packet_type)
            all_stats.append(stats)
    # If no specific packet type is provided, display statistics for all audio streams
    else:
        for packet_type, data in packet_data.items():
            if packet_type.startswith('audio_') and data['inter_arrival_times']:
                times = data['inter_arrival_times']
                stats = calculate_stats(times, packet_type)
                all_stats.append(stats)
    
    # Create a DataFrame for all the summary statistics
    if all_stats:
        summary_df = pd.DataFrame(all_stats)
        # Display the DataFrame
        st.dataframe(summary_df)

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

def plot_audio_streams_histogram(packet_data):
    # Constants for plotting
    MAX_PACKETS_DISPLAYED = 5  # Maximum number of packets/ranges to show in the tooltip
    num_bins = 50  # Number of bins for the histogram

    # Prepare subplots; one for each audio stream
    audio_streams = [ptype for ptype in packet_data if ptype.startswith('audio_')]
    num_streams = len(audio_streams)
    if num_streams == 0:
        return None

    fig = make_subplots(rows=num_streams, cols=1, subplot_titles=audio_streams)

    for i, stream in enumerate(audio_streams, start=1):
        stream_data = packet_data[stream]['inter_arrival_times']
        packet_numbers = [info['packet_number'] for info in packet_data[stream]['info']]

        # Filter out any times that are 0
        filtered_stream_data = [(time, pkt_num) for time, pkt_num in zip(stream_data, packet_numbers) if time > 0]
        stream_times, stream_packets = zip(*filtered_stream_data)

        # Define bins for histogram
        min_time = min(stream_times)
        max_time = max(stream_times)
        log_min = np.log10(min_time)
        log_max = np.log10(max_time)
        log_bins = np.logspace(log_min, log_max, num_bins)
        bin_midpoints = (log_bins[:-1] + log_bins[1:]) / 2

        # Create the histogram data
        histogram_data = np.histogram(stream_times, bins=log_bins)
        bin_counts = histogram_data[0]
        bin_edges = histogram_data[1]

        # Calculate packet numbers for each bin
        bin_packet_numbers = [[] for _ in range(num_bins)]
        for time, packet_num in filtered_stream_data:
            bin_index = np.digitize(time, bin_edges) - 1  # -1 as np.digitize returns 1-based indices
            bin_packet_numbers[bin_index].append(packet_num)

        # Prepare tooltip content
        customdata = []
        for bin_index in range(num_bins):
            bin_packets = bin_packet_numbers[bin_index]
            tooltip_content = tooltip_content_for_bin(bin_packets, MAX_PACKETS_DISPLAYED)
            # For each midpoint, we must add the same tooltip content twice since we repeat the midpoints
            customdata.extend([tooltip_content, tooltip_content])

        # Add filled scatter plot to the subplot
        fig.add_trace(
            go.Scatter(
                x=bin_midpoints.repeat(2),
                y=np.repeat(bin_counts, 2),
                mode='lines',
                line=dict(color='rgba(0, 100, 80, .8)', shape='hv'),
                fill='tozeroy',
                name=stream,
                customdata=customdata,
                hovertemplate="<b>Bin Range: %{x:.2f}ms - %{x:.2f}ms</b><br>Packets: %{customdata}<extra></extra>"
            ),
            row=i,
            col=1
        )

    # Update the layout for the figure
    fig.update_layout(
        title='Histogram of Audio Packet Inter-arrival Times per Stream',
        template='plotly_white',
        height=300 * num_streams,  # Adjust height based on the number of streams
        showlegend=False
    )

    # Update x-axis and y-axis to use log scales and custom tick labels for each subplot
    for j in range(1, num_streams + 1):
        fig.update_xaxes(
            title='Inter-arrival Time (ms)', 
            type='log',
            tickvals=bin_midpoints,  # Set custom tick values to the middle of the bins
            ticktext=[f"{x:.2f}" for x in bin_midpoints],  # Custom tick text with reduced precision
            row=j, 
            col=1
        )
        fig.update_yaxes(
            title='Quantity', 
            type='log', 
            row=j, 
            col=1
        )

    return fig






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
        audio_histogram_fig = plot_audio_streams_histogram(packet_data)
        if audio_histogram_fig is not None:
            st.plotly_chart(audio_histogram_fig)
            display_summary_statistics(packet_data)
            st.markdown('---')

        # Inter-arrival times
        other_fig = plot_inter_arrival_times_box(packet_data)
        st.plotly_chart(other_fig)

        # PTP packets stats
        if 'PTP_Sync' in packet_data:
            display_summary_statistics(packet_data, 'PTP_Sync')

        # IGMP Visualization
        if 'IGMP' in packet_data:
            igmp_info = packet_data['IGMP']['info']
            igmp_visualization_figure = visualize_igmp_info(igmp_info)
            if igmp_visualization_figure is not None:
                st.header("IGMP Traffic Map")
                st.plotly_chart(igmp_visualization_figure)

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)
