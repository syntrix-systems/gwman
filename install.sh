#!/bin/bash
# Installs GW Manager on Debian 11/12+. Run as root from the unpacked directory.
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-flask python3-waitress iproute2 nftables openvpn openssl strongswan-starter xl2tpd ppp curl unzip ca-certificates iptables
apt-get install -y microsocks || echo 'WARNING: microsocks package not available - inbound SOCKS disabled'
apt-get install -y shadowsocks-libev qrencode || echo "WARNING: shadowsocks-libev/qrencode not available - inbound Shadowsocks disabled"
# tun2socks (outbound SOCKS5/HTTP/Shadowsocks proxies)
case "$(dpkg --print-architecture)" in arm64) A=arm64;; amd64) A=amd64;; armhf) A=armv7;; *) A="";; esac
if [ -n "$A" ] && [ ! -x /usr/local/bin/tun2socks ]; then
  T=$(mktemp -d)
  curl -fsSL -o "$T/t.zip" "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-$A.zip" && unzip -oq "$T/t.zip" -d "$T" \
    && install -m 755 "$T"/tun2socks-linux-* /usr/local/bin/tun2socks || echo "WARNING: tun2socks not installed - proxy support disabled (get it from github.com/xjasonlyu/tun2socks/releases)"
  rm -rf "$T"
fi
install -d -m 700 /etc/gwmanager; install -d /opt/gwmanager/static
cp app.py /opt/gwmanager/; cp static/index.html /opt/gwmanager/static/
grep -q 'ipsec.d/\*.conf' /etc/ipsec.conf || echo 'include /etc/ipsec.d/*.conf' >> /etc/ipsec.conf
grep -q 'ipsec.d/gw.secrets' /etc/ipsec.secrets 2>/dev/null || echo 'include /etc/ipsec.d/gw.secrets' >> /etc/ipsec.secrets
install -m 600 /dev/null /etc/ipsec.d/gw.secrets 2>/dev/null || true
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=2\nnet.ipv4.conf.default.rp_filter=2\n' > /etc/sysctl.d/99-gwmanager.conf
sysctl --system >/dev/null
modprobe tun 2>/dev/null; echo tun > /etc/modules-load.d/gwmanager.conf
[ -c /dev/net/tun ] || echo 'WARNING: /dev/net/tun is missing - OpenVPN and proxies will not work (kernel without TUN?)'
systemctl disable --now xl2tpd strongswan-starter 2>/dev/null || true   # gwmanager starts them only when needed
PW=$(python3 /opt/gwmanager/app.py --init)
cp gwmanager.service /etc/systemd/system/
systemctl daemon-reload; systemctl enable gwmanager; systemctl restart gwmanager
echo; echo "GW Manager is running on https://<this-host>:8443 (self-signed certificate -- your browser will warn once)"
[ -n "$PW" ] && echo "Admin password: $PW   (change it in Settings, or: python3 /opt/gwmanager/app.py --passwd)"
