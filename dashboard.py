import streamlit as st
import pyshark
import pandas as pd
import plotly.graph_objects as go
import numpy as np
import os

# Function to load the pcap file using PyShark
def load_capture(file_path):
    # We use only_summaries=False to get detailed packet info
    return pyshark.FileCapture(file_path, only_summaries=False)

def classify_packet(packet, packet_number):
    # Determines the type of the packet and gathers basic info
    packet_type = 'Non-IP'
    packet_info = {'packet_number': packet_number}
    
    if 'IP' in packet:
        packet_type = 'audio' if packet.ip.dst.startswith('239.') else packet.highest_layer
        packet_info.update({
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'src_port': packet[packet.transport_layer].srcport if packet.transport_layer else None,
            'dst_port': packet[packet.transport_layer].dstport if packet.transport_layer else None,
        })

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
        initialize_packet_data_structure(packet_data, packet_type)
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

        # Display the summary statistics in an info box
        st.info(f"""
        **{packet_type.capitalize()} Packet Inter-arrival Times Summary:**
        - Minimum: {min_val:.3f} ms
        - Maximum: {max_val:.3f} ms
        - Median: {median_val:.3f} ms
        - Mean: {mean_val:.3f} ms
        - Standard Deviation: {std_dev:.3f} ms
        """)

def create_connections_dataframe(packet_data):
    # Dictionary to hold the connection information
    connection_info = {}

    # Iterate over the packet information to fill the connection_info
    for ptype, data in packet_data.items():
        for info in data['info']:
            # Skip packets without IP information
            if 'src_ip' not in info or 'dst_ip' not in info or info['src_ip'] is None or info['dst_ip'] is None:
                continue

            src_dst_pair = (info['src_ip'], info['dst_ip'])
            if src_dst_pair not in connection_info:
                connection_info[src_dst_pair] = {'total_packets': 0, 'protocols': {}}
            
            # Increment the total packet count for the source-destination pair
            connection_info[src_dst_pair]['total_packets'] += 1
            
            # Classify packets with destination IP starting with '239.' as 'Multicast Audio'
            protocol = 'Multicast Audio' if info['dst_ip'].startswith('239.') else ptype
            
            # Increment the packet count for the specific protocol
            if protocol not in connection_info[src_dst_pair]['protocols']:
                connection_info[src_dst_pair]['protocols'][protocol] = 0
            connection_info[src_dst_pair]['protocols'][protocol] += 1

    # Prepare the data for DataFrame creation
    rows = []
    for (src_ip, dst_ip), info in connection_info.items():
        total_packets = info['total_packets']
        for protocol, count in info['protocols'].items():
            percentage = (count / total_packets) * 100
            rows.append({
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Protocol': protocol,
                'Packet Count': count,
                'Percentage': percentage
            })

    # Create the DataFrame
    df = pd.DataFrame(rows)
    df.sort_values(by='Percentage', ascending=False, inplace=True)

    # Display the DataFrame using Streamlit
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
        connections_df = create_connections_dataframe(packet_data)
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
        if 'PTP' in packet_data:  # Replace 'PTP' with the correct key if different
            display_summary_statistics(packet_data, 'PTP')

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)