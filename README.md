# Basic-Network-Analyzer-Python-Scapy-
This project is a fundamental command-line utility developed in Python to demonstrate core principles of Network Analysis and Passive Reconnaissance. It utilizes the powerful Scapy library to capture and parse network traffic in real-time.

It serves as a basic, educational equivalent of sophisticated tools like Wireshark, showing how network packets can be intercepted, filtered (specifically for TCP and UDP), and analyzed to extract crucial connection metadata.

⚙️ How It Works?
The script continuously listens on the specified network interface and filters traffic based on two fundamental transport protocols:

TCP (Transmission Control Protocol): Extracts detailed metadata for reliable, connection-oriented packets.

UDP (User Datagram Protocol): Extracts metadata for connectionless packets.

For every detected packet, the tool extracts and displays critical information:

Source and Destination MAC Addresses

Source and Destination IP Addresses

(Recommended: Add Source and Destination Port Numbers for better detail.)

⚠️ Prerequisites and Requirements
For this script to function correctly, Root (Sudo) access is required for proper network interface access. It is highly recommended to use a Linux-based operating system (e.g., Kali Linux) to minimize the likelihood of encountering interface errors and to ensure effective packet filtering, although the tool may be run on other systems like Windows.

Scapy Installation: Install the necessary Python library:

Bash

pip install scapy
🚀 Usage Steps (Recommended: Linux/Kali Linux)
Identify Interface: Determine the name of your active network interface (e.g., eth0 or wlan0).

Run the Script: Run the script with superuser privileges:

Bash

sudo python3 packet_analyzer.py
Note: Remember to update the iface="Wi-Fi" parameter in the code with your actual interface name.

🎯 Cybersecurity Focus
This tool demonstrates a solid understanding of the TCP/IP protocol stack and lays the groundwork for more advanced cybersecurity tasks, such as:

Understanding network session establishment.

Identifying potential Man-in-the-Middle (MITM) activity.

Analyzing network topology and data flow.
