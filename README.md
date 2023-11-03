# Packet Capture Analysis Dashboard

This repository contains a Streamlit application that analyzes packet captures (PCAP files) and visualizes audio packet inter-arrival times. The application leverages PyShark for packet capture processing, Pandas for data manipulation, and Plotly for interactive plotting.

## Features

- Load and parse PCAP files using PyShark.
- Calculate inter-arrival times for audio packets identified by a specific IP address pattern.
- Display summary statistics for audio packet inter-arrival times.
- Interactive box plots for audio and non-audio packet inter-arrival times with a logarithmic scale for audio packets.
- Summary statistics for PTP (Precision Time Protocol) packets, if present in the capture.

## Installation

To install the necessary dependencies for this project, run the following command:

```bash
pip install -r requirements.txt
```

This will install all the libraries listed in the `requirements.txt` file.

## Usage

1. Clone the repository to your local machine.
2. Navigate to the cloned repository's directory.
3. Install the required dependencies using the command above.
4. Run the Streamlit application with `streamlit run app.py`.

Please note that decoding PCAP files can be time-consuming, especially for larger captures, due to the detailed processing involved.

## Requirements

This application requires Python 3.6+ and the following packages listed in the `requirements.txt` file.

## Contributing

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## License

This project is open-sourced under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- PyShark for providing packet capture processing capabilities.
- Plotly for the interactive plotting library.
- Streamlit for the framework that turns data scripts into shareable web apps.

## Contact

If you have any questions or feedback, please open an issue in the GitHub issue tracker for this repository.

---

*This README was generated using OpenAI's language model.*