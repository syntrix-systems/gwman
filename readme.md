# Syntrix Gateway Manager

This project was originally designed to convert a single board computer with limited specs running Debian into a router to manage VPN connections and routing settings for them. It has been tested on Debian 12 but should work on other newer versions as well.
---
## Features

- Manage configurations through web UI
   - Add VPNs
   - Add Proxies
   - Manage Route Settings
- Dashboard and status page
   - View system resource usage
   - View bandwidth usage for each connection

## Supported Client Protocols (Outbound Connections)
- [x] OpenVPN Client
- [x] L2TP/IPsec Client
- [x] ShadowSocks Client
- [x] Socks Client
- [x] HTTP Proxy Client
## Supported Server Protocols (Inbound Connections)
- [x] OpenVPN Server
- [x] L2TP/IPsec Server
- [x] NAT on direct local incoming connections
## Routing Management
- [x] Destination CIDR Selection
- [x] Distance Selection
- [x] Gateway IP Selection

# Installation

1. Clone the project and extract it
2. Run the installer
```bash
bash install.sh
```
3. A temporary password will be printed in the terminal with instructions on how to connect to the management interface
4. Login to the web ui and change your password