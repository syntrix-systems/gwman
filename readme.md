# Syntrix Gateway Manager

This project was originally designed to convert a single board computer with limited specs running Debian into a router to manage VPN connections and routing settings for them. It has been tested on Debian 12 but should work on other newer versions as well.
---

## Quick Installation

Copy and paste the following command
```bash
apt install git -y && git clone https://github.com/syntrix-systems/gwman && cd gwman && bash install.sh
```

## Features

- Manage configurations through web UI
   - Add VPN Clients
   - Add VPN Servers
   - Add Proxy Clients
   - Add Proxy Serisers
   - Manage Route Settings
- Dashboard and status page
   - View system resource usage
   - View bandwidth usage for each connection
- Firewall Management

## Supported Client Protocols (Outbound Connections)
- [x] OpenVPN Client
- [x] L2TP/IPsec Client
- [x] ShadowSocks Client
- [x] Socks Client
- [x] HTTP Proxy Client
## Supported Server Protocols (Inbound Connections)
- [x] OpenVPN Server
- [x] L2TP/IPsec Server
- [x] Socks Server
- [x] ShadowSocks Server
- [x] NAT on direct local incoming connections
## Routing Management
- [x] Destination CIDR Selection
- [x] Distance Selection
- [x] Gateway IP Selection
## Firewall Management
- [x] Fully functional firewall management via iptables
## Monitoring Dashboard
- [x] Interface usage
- [x] CPU usage
- [x] RAM usage
- [x] Connection overview

## Password Reset
Run the following command in order to reset the admin password
```bash
python3 /opt/gwmanager/app.py --passwd
```