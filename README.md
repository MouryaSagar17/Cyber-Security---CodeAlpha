# Cyber-Security---CodeAlpha
# Packet Sniffer

## Overview

**Packet Sniffer** is a compact network monitoring tool written in Python. It captures and analyzes packets on a user-selected network interface and prints a clear, color-coded view of packet layers (IP, TCP, UDP, ICMP), addresses, and protocol-specific details.

This README explains how to install dependencies, run the sniffer, and what to expect while using it.

## Features

* Lists local network interfaces with MAC and IP addresses in a readable table.
* Cross-platform IP and MAC lookup using `psutil`.
* Real-time packet capture and analysis using `scapy`.
* Decodes and prints details for IP, TCP, UDP, and ICMP layers.
* Color-coded terminal output for easier reading.
* Graceful shutdown on `Ctrl+C` (keyboard interrupt).
* Designed to work alongside an ARP Spoofer module (run the spoofer first for full visibility on switched networks).

## Prerequisites

* Python 3.8 or higher (tested with Python 3.11).

Required Python packages:

* `scapy`
* `psutil`
* `prettytable`
* `colorama`

Install dependencies with:

```bash
pip install scapy psutil prettytable colorama
```

> Note: Some operating systems may require additional system packages for `scapy` to function fully. On Linux you may need `libpcap` development headers; on macOS you may need `tcpdump` permissions. Run the sniffer with the privileges required by your platform (root/Administrator).

## Installation

1. Clone or download this project to your machine.
2. Create and activate a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate    # macOS / Linux
venv\Scripts\activate     # Windows
```

3. Install Python dependencies (see Prerequisites).

## Usage

1. If your network setup requires it, start the ARP Spoofer module first.
2. Run the sniffer script:

```bash
python Sniffer.py
```

3. The script will list detected interfaces with MAC and IP addresses.
4. Enter the interface name you want to sniff when prompted (for example: `eth0`, `en0`, or `Ethernet`).
5. The sniffer will begin capturing packets and printing analyzed output in real time.
6. Stop the sniffer with `Ctrl+C`.

## Important Notes

* The script must be run with appropriate privileges to capture packets (root on Linux/macOS, Administrator on Windows).
* ARP Spoofer must be running beforehand if you expect to see traffic between other devices on a switched network.
* Cross-platform support: Windows, Linux, and macOS are supported, but behavior can vary based on OS packet capture permissions and drivers.
* Tested with Python 3.11; earlier Python 3.8+ versions should work but were not explicitly tested.

## Project Structure

```
Packet-Sniffer/
├── Sniffer.py        # Main script that lists interfaces and performs sniffing
├── README.md         # This file
└── (optional files)  # ARP Spoofer module or other helpers if present
```

If you have an ARP Spoofer component, add a short reference or link here explaining how to start it and any configuration options.
## Output
![](https://github.com/MouryaSagar17/Cyber-Security---CodeAlpha/blob/a93934495a0069121c52c61cc0fc3073362476d8/Output1.png)
![](https://github.com/MouryaSagar17/Cyber-Security---CodeAlpha/blob/a93934495a0069121c52c61cc0fc3073362476d8/Packet_Capture.png)
![](https://github.com/MouryaSagar17/Cyber-Security---CodeAlpha/blob/a93934495a0069121c52c61cc0fc3073362476d8/Nmap_Scan.png)

## Troubleshooting

* If no interfaces appear, make sure your system allows Python to access network interfaces and that `psutil` is installed.
* If you capture very little traffic on a switched network, ensure the ARP Spoofer is running or try running on the device hosting the traffic.
* Permission errors: run the script with elevated privileges.

## Contributing

Contributions are welcome. If you add features or fixes, consider:

* Adding unit tests where practical.
* Documenting new options in this README.
* Keeping ARP Spoofer references up to date.

## License

This project is released under the MIT License. See the `LICENSE` file for details.

## Author

A. Mourya

---


* Add a quick example of captured output for the README.
* Create a `requirements.txt` or a basic `LICENSE` file.
* Add usage examples for Windows and Linux specific commands.

Tell me which of the above you want and I will update the README.
