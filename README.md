# No Intrude Firewall

No Intrude Firewall is a simple yet powerful Python-based firewall tool with a graphical user interface (GUI). 
It allows users to monitor network traffic in real-time, define custom rules to block specific IP hosts, and analyze active connections. 
Built with Tkinter for GUI and Scapy for packet sniffing, this tool is perfect for enthusiasts and professionals looking for a lightweight network monitoring and management solution.

## Features

* Real-Time Traffic Analysis:
* Sniffs and analyzes IP, TCP, and UDP packets.
* Displays connection details, including protocol, source, destination, and organization name.

### Custom Firewall Rules:

* Block specific IP hosts by adding them to the rule list.
* Persistent rule storage for easy reuse.

### Interactive GUI:

* Easy-to-use interface for managing rules and monitoring traffic.
* Start and stop the firewall with a single click.

### Active Connection Logging:

* Displays detailed information about ongoing network connections.

### Automatic Response:

* Sends a custom payload ("TRY HARDER") to blocked hosts for additional control.

## Requirements

* Python 3.8 or higher
### Dependencies:
  * Tkinter
  * Scapy
  * ipwhois

## Installation

`pip install scapy ipwhois`

#### If tkinter is not available in your Python installation, you may need to install it manually:

### On Ubuntu/Debian:

`sudo apt-get install python3-tk`

### On Fedora:

`sudo dnf install python3-tkinter`

#### On macOS and Windows, tkinter is included by default.


