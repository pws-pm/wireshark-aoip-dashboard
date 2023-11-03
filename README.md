# Packet Capture Analysis Dashboard

This repository contains a Streamlit application that analyzes packet captures (PCAP files) and visualizes audio packet inter-arrival times. The application leverages PyShark for packet capture processing, Pandas for data manipulation, and Plotly for interactive plotting.

## Features

- Load and parse PCAP files using PyShark.
- Calculate inter-arrival times for audio packets identified by a specific IP address pattern.
- Display summary statistics for audio packet inter-arrival times.
- Interactive box plots for audio and non-audio packet inter-arrival times with a logarithmic scale for audio packets.
- Summary statistics for PTP (Precision Time Protocol) packets, if present in the capture.

## Installation

Before using this application, you need to install the necessary dependencies:

### Installing `tshark` (macOS, Linux, and Windows)

On all three platforms, you can use package managers to install Wireshark, which includes `tshark`. Follow the instructions below based on your platform:

#### macOS (using Homebrew)

```bash
brew install wireshark
```

#### Linux (using APT)

```bash
sudo apt-get install wireshark
```

#### Windows (using Chocolatey)

```bash
choco install wireshark
```

### Installing Python Dependencies

After installing Wireshark (which includes `tshark`), you should also install the Python dependencies listed in the `requirements.txt` file by running the following command:

```bash
pip install -r requirements.txt
```

Once you have installed these dependencies, you can proceed with running the application as described in the "Usage" section below.

## Usage

1. Clone the repository to your local machine.
2. Navigate to the cloned repository's directory.
3. Install the required dependencies using the commands provided in the "Installation" section above.
4. Run the Streamlit application with the following command:

```bash
streamlit run dashboard.py
```

Please note that decoding PCAP files can be time-consuming, especially for larger captures, due to the detailed processing involved.

## Requirements

This application requires Python 3.6+ and the following packages listed in the `requirements.txt` file.

## Contributing

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## License

This project is open-sourced under the MIT License. See the LICENSE file for details.

## Acknowledgments

- PyShark for providing packet capture processing capabilities.
- Plotly for the interactive plotting library.
- Streamlit for the framework that turns data scripts into shareable web apps.

## Contact

If you have any questions or feedback, please open an issue in the GitHub issue tracker for this repository.

---

*This README was generated using OpenAI's language model.*
