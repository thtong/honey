# honey
## deploy honeypot using docker-compose
`docker-compose up -d`

Once the honeypot program is running, clients can connect to the HTTPS service by pointing a browser at the following URL: https://THE-HOST-IP:19443/, where “THE-HOST-IP” is the ip/hostname of  the computer running the program. Clients can connect to the telnet service by executing the command: telnet THE-HOST-IP 19023. 

The ports can be changed as required via the PORT mapping in docker-compose.yml

## purpose
This honeypot program supports HTTPS and Telnet connections. The honeypot could be used to provide the operator with a deeper understanding of attacks targeted at the emulated services. Perhaps, patterns of trends and behaviors can be developed that would allow the operator to prevent similar attacks from making its way to legitimate targets. Ideally, it will provide the operator the opportunity to learn and gain experience with and develop methods for analyzing attack data.

## usage
Some functionality of the honeypot can be configured via edits to the “/app/honeypot.cfg” configuration file. The following capabilities are supported:
* Enable/Disable packet sniffing and PCAP output via “writepcap” in section “mainset” 
* Number of packets per PCAP file (default is 100) via “pcappackets” in section “mainset”
* Scapy information verboseness via “sniff_stdout” in section “mainset”
* Enable/Disable fingerprinting using the p0f program via “p0f” in section “mainset”.
* HTTPS listening port via “port” in section “web_srv”
* Telnet listening port via “port” in section “telnet_srv”
* The valid username and password for authenticating into the services via “username” and “password” in section “authentication”

## tips
The program generates HTML reports when it first starts up and daily thereafter. This is mainly used to show daily activity chart for the honeypot. To generate the latest report without waiting 24 hours, restart the honeypot container.

## persistent data
Honeypot and client interactions and events are written to the “honeypot.sqlite” database file as they occur. Scapy packet captures are stored as PCAP files in the “pcap” directory. The “data” directory contains content files used by the honeypot program to simulate reponses to the client. Files that have the “tel-“ prefix are data files for the Telnet emulated service and files that have the “web-“ prefix are for the web server emulated service. The “daily” directory contains the trends/metrics report that is generated when the honeypot is started up and at each 24 hour interval. 

## Dependencies
Module Name	| Module Functions
--- | ---
plotly | An interactive, browser-based charting library for python
P0f	| Tool that uses passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications (often as little as a single normal SYN). Used to conduct device fingerprinting passively.
Scapy | Packet manipulation program. Used to record TCP byte stream.
ConfigParser | Read/write configuration files similar to Windows INI files.
Sqlite3 | Sqlite database
tcpdump | Packet analyzer
