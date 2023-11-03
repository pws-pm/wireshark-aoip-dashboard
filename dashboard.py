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

def process_packets(capture):
    packet_data = {}
    last_audio_timestamp = None

    for packet_number, packet in enumerate(capture, start=1):
        if 'IP' in packet and packet.ip.dst.startswith('239.'):
            packet_type = 'audio'
            packet_info = {
                'packet_number': packet_number,
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'src_port': packet[packet.transport_layer].srcport,
                'dst_port': packet[packet.transport_layer].dstport,
            }
            
            if last_audio_timestamp is not None:
                delta = packet.frame_info.time_delta_displayed
                delta_ms = float(delta) * 1000  # Convert to milliseconds
                packet_info['delta_ms'] = f"{delta_ms:.3f}"
                packet_info['sniff_timestamp'] = float(packet.sniff_timestamp)

                if packet_type not in packet_data:
                    packet_data[packet_type] = {'inter_arrival_times': [], 'info': []}
                packet_data[packet_type]['inter_arrival_times'].append(delta_ms)
                packet_data[packet_type]['info'].append(packet_info)

            last_audio_timestamp = float(packet.sniff_timestamp)
        else:
            # Handle non-audio packets
            packet_type = packet.highest_layer
            if packet_type not in packet_data:
                packet_data[packet_type] = {'timestamps': [], 'info': []}
            timestamp = float(packet.sniff_timestamp)
            packet_data[packet_type]['timestamps'].append(timestamp)
            # Skip further processing for non-audio packets
            continue

    # Calculate inter-arrival times for non-audio packets using sniff timestamps
    for ptype, data in packet_data.items():
        if ptype != 'audio':
            timestamps = data['timestamps']
            inter_arrival_times = np.diff(timestamps) * 1000  # Convert to milliseconds
            packet_data[ptype]['inter_arrival_times'] = list(inter_arrival_times)

    return packet_data


# Function to create a Plotly box plot for inter-arrival times per packet type with log scale for audio
def plot_inter_arrival_times_box(packet_data):
    # Create box plot for audio packets with log scale
    audio_fig = go.Figure()
    if 'audio' in packet_data:
        audio_times = packet_data['audio']['inter_arrival_times']
        tooltip_texts = [
            f"Packet Number: {info['packet_number']}<br>"
            f"Source: {info['src_ip']}:{info['src_port']}<br>"
            f"Destination: {info['dst_ip']}:{info['dst_port']}<br>"
            f"Delta: {info['delta_ms']} ms"
            for info in packet_data['audio']['info']
        ]
        audio_fig.add_trace(go.Box(
            y=audio_times,
            name='Audio',
            boxpoints='outliers',  # Show outliers
            jitter=0.5,  # Add some jitter for better visualization
            marker=dict(size=2),
            text=tooltip_texts,
            hoverinfo='text'
        ))
    audio_fig.update_layout(
        title='Audio Packet Inter-arrival Times (ms)',
        yaxis_title='Time (milliseconds)',
        yaxis_type='log',  # Log scale
        yaxis_tickformat='.3f',  # Format y-axis ticks to always show three decimal places
        template='plotly_white'
    )

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

    return audio_fig, other_fig

# Function to calculate and display summary statistics in Streamlit
def display_summary_statistics(packet_data):
    if 'audio' in packet_data and packet_data['audio']['inter_arrival_times']:
        audio_times = packet_data['audio']['inter_arrival_times']
        min_val = np.min(audio_times)
        max_val = np.max(audio_times)
        median_val = np.median(audio_times)
        mean_val = np.mean(audio_times)
        std_dev = np.std(audio_times)

        # Display the summary statistics in an info box
        st.info(f"""
        **Audio Packet Inter-arrival Times Summary:**
        - Minimum: {min_val:.3f} ms
        - Maximum: {max_val:.3f} ms
        - Median: {median_val:.3f} ms
        - Mean: {mean_val:.3f} ms
        - Standard Deviation: {std_dev:.3f} ms
        """)


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
        
        # Plotting
        audio_fig, other_fig = plot_inter_arrival_times_box(packet_data)
        
        # Display charts
        st.plotly_chart(audio_fig)

        # Display the summary statistics for audio packets
        display_summary_statistics(packet_data)

        st.plotly_chart(other_fig)

        # Delete the temporary file now that we're done with it
        os.remove(temp_file_path)
