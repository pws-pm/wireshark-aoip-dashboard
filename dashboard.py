import streamlit as st
import pyshark
import pandas as pd
import plotly.graph_objects as go
import numpy as np
import os
from collections import defaultdict

# Function to load the pcap file using PyShark
def load_capture(file_path):
    # We use only_summaries=False to get detailed packet info
    return pyshark.FileCapture(file_path, only_summaries=False)

def classify_packet(packet, packet_number):

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
        
        if ptp_message_type_code == '0x00':
            packet_type = 'PTP_Sync'
        elif ptp_message_type_code == '0x0b':
            packet_type = 'PTP_Announce'

        # Update packet_info with PTP specific details
        packet_info.update({
            'sequence_id': packet.ptp.get_field_value('ptp.v2.sequenceid'),
            'source_port_id': packet.ptp.get_field_value('ptp.v2.sourceportid'),
            'clock_identity': packet.ptp.get_field_value('ptp.v2.clockidentity'),
            'origin_timestamp_seconds': packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.seconds'),
            'origin_timestamp_nanoseconds': packet.ptp.get_field_value('ptp.v2.sdr.origintimestamp.nanoseconds'),
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


# The refactored process_packets function
def process_packets(capture):
    packet_data = {}
    last_timestamps = {}

    for packet_number, packet in enumerate(capture, start=1):
        packet_type, packet_info = classify_packet(packet, packet_number)
        calculate_inter_arrival_time(packet, packet_info, packet_type, last_timestamps)
        update_packet_data_structure(packet_data, packet_type, packet_info)
    
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

def calculate_bandwidth(capture):
    # Dictionary to store bytes per source-destination pair
    bytes_per_connection = defaultdict(int)

    for packet in capture:
        if 'IP' in packet:
            src_dst_pair = (packet.ip.src, packet.ip.dst)
            frame_len = int(packet.length)
            bytes_per_connection[src_dst_pair] += frame_len

    # Convert bytes to Mbps (1 byte = 8 bits, 1 Mbps = 1e6 bits per second)
    bandwidth_per_connection = {pair: (bytes * 8) / 1e6 for pair, bytes in bytes_per_connection.items()}
    return bandwidth_per_connection

def create_connections_dataframe(packet_data, capture):
    connection_info = defaultdict(lambda: {'total_packets': 0, 'protocols': defaultdict(int), 'total_bytes': 0})
    # Add a call to calculate_bandwidth
    bandwidth_per_connection = calculate_bandwidth(capture)

    # List to store rows for DataFrame creation
    rows = []

    for ptype, data in packet_data.items():
        for info in data['info']:
            # Ensure 'src_ip' and 'dst_ip' are present and not None
            if info.get('src_ip') and info.get('dst_ip'):
                src_dst_pair = (info['src_ip'], info['dst_ip'])
                connection_info[src_dst_pair]['total_packets'] += 1
                
                # Classify the protocol based on the destination IP
                protocol = 'Multicast Audio' if info['dst_ip'].startswith('239.') else ptype
                connection_info[src_dst_pair]['protocols'][protocol] += 1

    # Prepare the data for DataFrame creation
    for (src_ip, dst_ip), info in connection_info.items():
        total_packets = info['total_packets']
        for protocol, count in info['protocols'].items():
            percentage = (count / total_packets) * 100
            # Retrieve the bandwidth using the src_dst_pair
            bandwidth = bandwidth_per_connection.get((src_ip, dst_ip), 0)
            rows.append({
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Protocol': protocol,
                'Packet Count': count,
                'Percentage': percentage,
                'Bandwidth (Mbps)': bandwidth  # Add the bandwidth data here
            })

    # Convert the list of dictionaries to a DataFrame in one go
    df = pd.DataFrame(rows)

    # Sort the DataFrame
    df.sort_values(by='Percentage', ascending=False, inplace=True)

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
st.title("Packet Capture Analysis Dashboard")

# File uploader
uploaded_file = st.sidebar.file_uploader("Choose a pcap file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    with st.spinner("Processing..."):
        # Save the uploaded file to a temporary file
        temp_file_path = "temp.pcapng"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        
        capture = load_capture(temp_file_path)

        # Process packets and calculate inter-arrival times
        packet_data = process_packets(capture)

        # Add this to create and display the connections DataFrame
        connections_df = create_connections_dataframe(packet_data, capture)
        st.dataframe(connections_df)

        # Display the histogram for audio packet inter-arrival times
        histogram_fig = plot_inter_arrival_times_histogram(packet_data)
        if histogram_fig is not None:
            st.plotly_chart(histogram_fig)

        # Display the summary statistics for audio packets
        display_summary_statistics(packet_data, 'audio')

        # Plotting
        other_fig = plot_inter_arrival_times_box(packet_data)
        st.plotly_chart(other_fig)

        # Check if PTP packets are in the data and display their statistics
        if 'PTP_Sync' in packet_data:
            display_summary_statistics(packet_data, 'PTP_Sync')

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)