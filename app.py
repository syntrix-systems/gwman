#!/usr/bin/env python3
"""gwmanager - Debian router/gateway manager. Runs as root. Drives ip, nftables, OpenVPN, strongSwan, xl2tpd."""
from collections import deque
import getpass, ipaddress, json, os, re, secrets, socket, subprocess, sys, threading, time, urllib.parse, zlib
from flask import Flask, request, jsonify, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = os.environ.get("GW_CONFIG", "/etc/gwmanager/config.json")
PKI = os.path.join(os.path.dirname(CFG), "pki")
PROTO = "77"  # routes we own are tagged "proto 77"
NAME = re.compile(r"^[a-z][a-z0-9]{0,7}$")
IFN = re.compile(r"^[\w.\-]{1,15}$")
lock = threading.RLock()
state = {"routes": [], "errors": [], "attempt": {}}
PROXY = ("socks5", "http", "shadowsocks")
CIPHERS = ("chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm")
IKE = "aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!"
ESP = "aes256-sha1,aes128-sha1,3des-sha1!"
DEFAULT = {"admin_hash": "", "secret": "", "lan_ifaces": [], "nat": True, "vpn_clients": [], "routes": [],
           "ovpn_server": {"enabled": False, "port": 1194, "proto": "udp", "subnet": "10.8.0.0/24", "public_host": "",
                           "push_routes": [], "dns": "", "redirect": False, "clients": []},
           "l2tp_server": {"enabled": False, "psk": "", "local_ip": "10.9.0.1", "pool": "10.9.0.10-10.9.0.100",
                           "dns": "", "users": []}}

def sh(*a, inp=None):
    p = subprocess.run(a, input=inp, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()

def load():
    try: c = json.load(open(CFG))
    except Exception: c = {}
    for k, v in DEFAULT.items(): c.setdefault(k, json.loads(json.dumps(v)))
    if not c["secret"]: c["secret"] = secrets.token_hex(32)
    return c

def wr(path, text, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    old = open(path).read() if os.path.exists(path) else None
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f: f.write(text)
    return old != text

def save(c): wr(CFG, json.dumps(c, indent=1))
def rm(path):
    try: os.remove(path)
    except OSError: pass

def safe(s, what):
    s = str(s)
    if re.search(r'[\r\n"\\]', s): raise ValueError(f"invalid characters in {what}")
    return s

def net4(s):
    n = ipaddress.ip_network(str(s).strip(), strict=False)
    if n.version != 4: raise ValueError("IPv4 only")
    return n

def vif(v): return {"openvpn": "ovpn-", "l2tp": "l2tp-"}.get(v["type"], "px-") + v["name"]

def validate(c):
    names = set()
    for v in c["vpn_clients"]:
        if not NAME.match(v["name"]) or v["name"] in names: raise ValueError("VPN name: 1-8 chars a-z0-9, unique, starts with a letter")
        names.add(v["name"])
        for k in ("server", "psk", "username", "password"): safe(v.get(k, ""), k)
        if v["type"] == "openvpn" and "remote" not in v.get("ovpn", ""): raise ValueError("OpenVPN profile needs a 'remote' line")
        if v["type"] == "l2tp" and not (v["server"] and v["psk"]): raise ValueError("L2TP needs server and PSK")
        if v["type"] not in ("openvpn", "l2tp") + PROXY: raise ValueError("bad type")
        if v["type"] in PROXY:
            if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", v.get("host", "")): raise ValueError("bad proxy host")
            v["port"] = int(v["port"])
            if not 0 < v["port"] < 65536: raise ValueError("bad proxy port")
            if v["type"] == "shadowsocks" and v.get("cipher") not in CIPHERS: raise ValueError("bad cipher")
    px = [paddr(v["name"]) for v in c["vpn_clients"] if v["type"] in PROXY]
    if len(px) != len(set(px)): raise ValueError("proxy name collision, pick another name")
    seen_rt = set()
    for r in c["routes"]:
        r["cidr"] = str(net4(r["cidr"]))
        r["metric"] = int(r.get("metric") or 1)
        if not 1 <= r["metric"] <= 65535: raise ValueError("distance must be 1-65535")
        if r.get("enabled", True):
            if (r["cidr"], r["metric"]) in seen_rt: raise ValueError(f"{r['cidr']}: two rules with the same distance {r['metric']} (give the backup a higher one)")
            seen_rt.add((r["cidr"], r["metric"]))
        if r["type"] == "gateway": ipaddress.IPv4Address(r["gw"])
        elif r["type"] == "vpn" and r.get("vpn") not in names: raise ValueError(f"route {r['cidr']}: unknown VPN")
        elif r["type"] not in ("gateway", "vpn", "blackhole"): raise ValueError("bad route type")
    for i in c["lan_ifaces"]:
        if not IFN.match(i): raise ValueError("bad interface name")
    o = c["ovpn_server"]; l = c["l2tp_server"]
    net4(o["subnet"]); o["port"] = int(o["port"]); safe(o["public_host"], "host")
    if o["proto"] not in ("udp", "tcp"): raise ValueError("bad proto")
    for r in o["push_routes"]: net4(r)
    for k in (o["dns"], l["dns"]):
        if k: ipaddress.IPv4Address(k)
    ipaddress.IPv4Address(l["local_ip"]); safe(l["psk"], "psk")
    if not re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", l["pool"]): raise ValueError("pool: a.b.c.d-e.f.g.h")
    for u in l["users"]: safe(u["username"], "user"); safe(u["password"], "password")
    if l["enabled"] and not l["psk"]: raise ValueError("L2TP server needs a PSK")

def ifup(n):
    rc, o = sh("ip", "-j", "link", "show", "dev", n)
    try: l = json.loads(o)[0]
    except Exception: return False
    return "UP" in l.get("flags", []) and l.get("operstate") != "DOWN"

# ---------------- VPN clients ----------------
BAD = {"dev", "dev-type", "redirect-gateway", "route-nopull", "script-security", "up", "down", "plugin", "route-up", "route-pre-down",
       "down-pre", "ipchange", "tls-verify", "auth-user-pass", "client-connect", "client-disconnect", "learn-address", "up-restart",
       "management", "daemon", "log", "log-append", "writepid", "cd", "chroot", "setenv", "setenv-safe"}

def sync_ovpn_clients(c):
    d = "/etc/openvpn/client"; os.makedirs(d, exist_ok=True)
    want = {f"gwc-{v['name']}": v for v in c["vpn_clients"] if v["type"] == "openvpn"}
    for f in os.listdir(d):
        if f.startswith("gwc-") and f.endswith((".conf", ".auth")) and f.rsplit(".", 1)[0] not in want:
            sh("systemctl", "disable", "--now", f"openvpn-client@{f.rsplit('.', 1)[0]}"); rm(f"{d}/{f}")
    for n, v in want.items():
        lines = [l for l in v["ovpn"].splitlines() if (l.split() or [""])[0].lower() not in BAD]
        lines += [f"dev {vif(v)}", "dev-type tun", "route-nopull"]
        if v.get("username"):
            wr(f"{d}/{n}.auth", f"{v['username']}\n{v.get('password', '')}\n"); lines.append(f"auth-user-pass {d}/{n}.auth")
        else: rm(f"{d}/{n}.auth")
        changed = wr(f"{d}/{n}.conf", "\n".join(lines) + "\n"); u = f"openvpn-client@{n}"
        if v.get("enabled"):
            sh("systemctl", "enable", "--now", u)
            if changed: sh("systemctl", "restart", u)
        else: sh("systemctl", "disable", "--now", u)

def l2tp_connect(n):
    if time.time() - state["attempt"].get(n, 0) < 30: return
    state["attempt"][n] = time.time()
    sh("ipsec", "up", f"gwc-{n}")
    try: open("/var/run/xl2tpd/l2tp-control", "w").write(f"c gwc-{n}\n")
    except OSError: pass

def l2tp_disconnect(n):
    try: open("/var/run/xl2tpd/l2tp-control", "w").write(f"d gwc-{n}\n")
    except OSError: pass
    sh("ipsec", "down", f"gwc-{n}")

def sync_l2tp(c):
    S = c["l2tp_server"]; cl = [v for v in c["vpn_clients"] if v["type"] == "l2tp"]; D = "/etc/ipsec.d"
    os.makedirs(D, exist_ok=True); os.makedirs("/etc/ppp/peers", exist_ok=True)
    have = {v["name"] for v in cl}
    for f in os.listdir(D):
        if f.startswith("gwc-") and f.endswith(".conf") and f[4:-5] not in have: rm(f"{D}/{f}"); rm(f"/etc/ppp/peers/{f[:-5]}")
    sec, x, chg = [], ["[global]", "port = 1701", ""], False
    for v in cl:
        n = v["name"]
        chg |= wr(f"{D}/gwc-{n}.conf", f"conn gwc-{n}\n  keyexchange=ikev1\n  authby=secret\n  type=transport\n  left=%defaultroute\n"
                  f"  leftprotoport=17/1701\n  right={v['server']}\n  rightprotoport=17/1701\n  ike={IKE}\n  esp={ESP}\n  auto=add\n")
        sec.append(f'%any {v["server"]} : PSK "{v["psk"]}"')
        chg |= wr(f"/etc/ppp/peers/gwc-{n}", f'ifname l2tp-{n}\nname "{v["username"]}"\npassword "{v["password"]}"\nnoauth\nnodefaultroute\n'
                  "noipdefault\nipcp-accept-local\nipcp-accept-remote\nnoccp\nnodeflate\nnobsdcomp\nrefuse-eap\nmtu 1280\nmru 1280\n"
                  "lcp-echo-interval 30\nlcp-echo-failure 4\n")
        x += [f"[lac gwc-{n}]", f"lns = {v['server']}", f"pppoptfile = /etc/ppp/peers/gwc-{n}", "length bit = yes", ""]
    if S["enabled"]:
        chg |= wr(f"{D}/gw-l2tp-server.conf", f"conn gw-l2tp-server\n  keyexchange=ikev1\n  authby=secret\n  type=transport\n  left=%defaultroute\n"
                  f"  leftprotoport=17/1701\n  right=%any\n  rightprotoport=17/%any\n  rekey=no\n  ike={IKE}\n  esp={ESP}\n  auto=add\n")
        sec.append(f'%any %any : PSK "{S["psk"]}"')
        x += ["[lns default]", f"ip range = {S['pool']}", f"local ip = {S['local_ip']}", "require chap = yes", "refuse pap = yes",
              "require authentication = yes", "name = gwmanager", "pppoptfile = /etc/ppp/gw-server.options", "length bit = yes", ""]
        chg |= wr("/etc/ppp/gw-server.options", "auth\nnoccp\nmtu 1280\nmru 1280\nlcp-echo-interval 30\nlcp-echo-failure 4\n" +
                  (f"ms-dns {S['dns']}\n" if S["dns"] else ""))
        chg |= wr("/etc/ppp/chap-secrets", "# managed by gwmanager\n" + "".join(f'"{u["username"]}" * "{u["password"]}" *\n' for u in S["users"]))
    else: rm(f"{D}/gw-l2tp-server.conf")
    chg |= wr(f"{D}/gw.secrets", "\n".join(sec) + "\n")
    chg |= wr("/etc/xl2tpd/xl2tpd.conf", "\n".join(x) + "\n", 0o644)
    if cl or S["enabled"]:
        sh("systemctl", "enable", "--now", "strongswan-starter", "xl2tpd")
        if chg: sh("ipsec", "rereadsecrets"); sh("ipsec", "reload"); sh("systemctl", "restart", "xl2tpd")
    else: sh("systemctl", "disable", "--now", "xl2tpd", "strongswan-starter")
    for v in cl:
        up = ifup(vif(v))
        if v.get("enabled") and not up: l2tp_connect(v["name"])
        elif not v.get("enabled") and up: l2tp_disconnect(v["name"])

# ---------------- outbound proxies (tun2socks) ----------------
def paddr(n): return f"198.18.{zlib.crc32(n.encode()) % 250 + 1}.1"

def proxy_url(v):
    q = lambda x: urllib.parse.quote(str(x), safe="")
    if v["type"] == "shadowsocks": auth = f"{v['cipher']}:{q(v.get('password', ''))}@"
    elif v.get("username"): auth = f"{q(v['username'])}:{q(v.get('password', ''))}@"
    else: auth = ""
    return f"{ {'socks5': 'socks5', 'http': 'http', 'shadowsocks': 'ss'}[v['type']] }://{auth}{v['host']}:{v['port']}"

def proxy_unit(v):
    i = vif(v)
    return (f"[Unit]\nDescription=GW proxy {v['name']}\nAfter=network-online.target\n\n[Service]\n"
            f"ExecStart=/usr/local/bin/tun2socks --device tun://{i} --proxy {proxy_url(v).replace('%', '%%')} --loglevel warning\n"
            f"ExecStartPost=/usr/bin/timeout 10 /bin/sh -c 'until ip link show dev {i} >/dev/null 2>&1; do sleep 0.25; done'\n"
            f"ExecStartPost=/usr/bin/env ip addr replace {paddr(v['name'])}/30 dev {i}\nExecStartPost=/usr/bin/env ip link set {i} up\n"
            "Restart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n")

def sync_proxies(c):
    d = "/etc/systemd/system"; want = {f"gwp-{v['name']}": v for v in c["vpn_clients"] if v["type"] in PROXY}; chg = False
    for f in os.listdir(d):
        if f.startswith("gwp-") and f.endswith(".service") and f[:-8] not in want:
            sh("systemctl", "disable", "--now", f); rm(f"{d}/{f}"); chg = True
    if want and not os.path.exists("/usr/local/bin/tun2socks"): raise RuntimeError("tun2socks is not installed (see install.sh)")
    ch = {n: wr(f"{d}/{n}.service", proxy_unit(v)) for n, v in want.items()}
    if chg or any(ch.values()): sh("systemctl", "daemon-reload")
    for n, v in want.items():
        u = n + ".service"
        if v.get("enabled"):
            sh("systemctl", "enable", "--now", u)
            if ch[n]: sh("systemctl", "restart", u)
        else: sh("systemctl", "disable", "--now", u)

# ---------------- OpenVPN server + PKI ----------------
def issue(cn, eku):
    p = lambda e: os.path.join(PKI, f"{cn}.{e}")
    sh("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", p("key"), "-out", p("csr"), "-subj", f"/CN={cn}")
    wr(p("ext"), f"extendedKeyUsage={eku}\nsubjectAltName=DNS:{cn}\n")
    rc, o = sh("openssl", "x509", "-req", "-in", p("csr"), "-CA", f"{PKI}/ca.crt", "-CAkey", f"{PKI}/ca.key", "-CAcreateserial", "-out", p("crt"), "-days", "3650", "-extfile", p("ext"))
    if rc: raise RuntimeError(o)

def ensure_pki():
    os.makedirs(PKI, mode=0o700, exist_ok=True)
    if not os.path.exists(f"{PKI}/ca.crt"):
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{PKI}/ca.key", "-out", f"{PKI}/ca.crt", "-subj", "/CN=gwmanager-ca", "-days", "3650")
        sh("openvpn", "--genkey", "secret", f"{PKI}/tc.key")
    if not os.path.exists(f"{PKI}/server.crt"): issue("server", "serverAuth")

def sync_ovpn_server(c):
    s = c["ovpn_server"]; u = "openvpn-server@gw-server"
    if not s["enabled"]: sh("systemctl", "disable", "--now", u); return
    ensure_pki(); n = net4(s["subnet"])
    conf = [f"port {s['port']}", f"proto {s['proto']}", "dev ovpn-srv", "dev-type tun", f"server {n.network_address} {n.netmask}", "topology subnet",
            f"ca {PKI}/ca.crt", f"cert {PKI}/server.crt", f"key {PKI}/server.key", "dh none", f"tls-crypt {PKI}/tc.key", "keepalive 10 60",
            "data-ciphers AES-256-GCM:AES-128-GCM", "user nobody", "group nogroup", "persist-key", "persist-tun", "verb 3"]
    for r in s["push_routes"]:
        rn = net4(r); conf.append(f'push "route {rn.network_address} {rn.netmask}"')
    if s["redirect"]: conf.append('push "redirect-gateway def1"')
    if s["dns"]: conf.append(f'push "dhcp-option DNS {s["dns"]}"')
    ch = wr("/etc/openvpn/server/gw-server.conf", "\n".join(conf) + "\n")
    sh("systemctl", "enable", "--now", u)
    if ch: sh("systemctl", "restart", u)

def ovpn_profile(c, name):
    s = c["ovpn_server"]; rd = lambda f: open(f"{PKI}/{f}").read().strip()
    return (f"client\ndev tun\nproto {s['proto']}\nremote {s['public_host'] or 'CHANGE_ME'} {s['port']}\nnobind\npersist-key\npersist-tun\n"
            f"remote-cert-tls server\ndata-ciphers AES-256-GCM:AES-128-GCM\nverb 3\n<ca>\n{rd('ca.crt')}\n</ca>\n<cert>\n{rd(name + '.crt')}\n</cert>\n"
            f"<key>\n{rd(name + '.key')}\n</key>\n<tls-crypt>\n{rd('tc.key')}\n</tls-crypt>\n")

# ---------------- NAT + routing ----------------
def apply_nft(c):
    internal = list(c["lan_ifaces"])
    if c["ovpn_server"]["enabled"]: internal.append("ovpn-srv")
    if c["l2tp_server"]["enabled"]: internal.append("ppp*")
    rules = []
    if c["nat"]:
        for i in internal: rules.append(f'iifname "{i}" ' + " ".join(f'oifname != "{o}"' for o in internal) + " masquerade")
    mss = [f'oifname "{p}" tcp flags syn tcp option maxseg size set rt mtu' for p in ("ovpn-*", "l2tp-*", "ppp*", "ovpn-srv")]
    script = ("add table ip gwmgr\ndelete table ip gwmgr\ntable ip gwmgr {\n chain nat_post { type nat hook postrouting priority srcnat; policy accept;\n " +
              "\n ".join(rules) + "\n }\n chain mss_clamp { type filter hook forward priority mangle; policy accept;\n " + "\n ".join(mss) + "\n }\n}\n")
    rc, o = sh("nft", "-f", "-", inp=script)
    if rc: raise RuntimeError(o)

def endpoint(v):
    try:
        h = v["host"] if v["type"] in PROXY else v["server"] if v["type"] == "l2tp" else next((l.split()[1] for l in v["ovpn"].splitlines() if l.strip().startswith("remote ")), None)
        ip = socket.gethostbyname(h) if h else None
        return None if ip and ipaddress.ip_address(ip).is_private else ip  # private/on-link servers are reached normally, no pin
    except Exception: return None

def apply_routes(c):
    rc, o = sh("ip", "-j", "-4", "route", "show", "default"); gw = None
    for r in (json.loads(o) if rc == 0 and o else []):
        if r.get("protocol") != PROTO and r.get("gateway"): gw = (r["gateway"], r.get("dev")); break
    sh("ip", "-4", "route", "flush", "proto", PROTO)
    state["pins"] = []
    if gw:  # pin VPN server addresses to the real uplink. metric 0 replaces pppd's peer route when the ppp peer == server IP.
        for v in c["vpn_clients"]:
            ip = v.get("enabled") and endpoint(v)
            if ip:
                sh("ip", "route", "replace", ip + "/32", "via", gw[0], "dev", gw[1], "proto", PROTO, "metric", "0")
                state["pins"].append((ip, gw[1]))
    ifs = {v["name"]: vif(v) for v in c["vpn_clients"]}; res = []
    for r in c["routes"]:
        st = "disabled"
        if r.get("enabled", True):
            n = net4(r["cidr"]); nets = list(n.subnets(1)) if n.prefixlen == 0 else [n]; st = "active"
            for x in nets:
                if r["type"] == "blackhole": cmd = ["ip", "route", "replace", "blackhole", str(x)]
                elif r["type"] == "gateway": cmd = ["ip", "route", "replace", str(x), "via", r["gw"]]
                else:
                    if not ifup(ifs[r["vpn"]]): st = "vpn down"; break
                    cmd = ["ip", "route", "replace", str(x), "dev", ifs[r["vpn"]]]
                rc, o = sh(*cmd, "proto", PROTO, "metric", str(r.get("metric", 1)))
                if rc: st = o; break
        res.append(st)
    state["routes"] = res

def reconcile(c):
    errs = []
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2")
    for f in (sync_ovpn_clients, sync_l2tp, sync_proxies, sync_ovpn_server, apply_nft, apply_routes):
        try: f(c)
        except Exception as e: errs.append(f"{f.__name__}: {e}")
    state["errors"] = errs

def pins_ok(): return tuple(f" dev {d} " in sh("ip", "route", "get", ip)[1] + " " for ip, d in state.get("pins", []))

def loop():
    first, last = True, None
    sig = lambda c: (tuple(ifup(vif(v)) for v in c["vpn_clients"]), pins_ok())
    while True:
        try:
            with lock:
                c = load()
                if first: reconcile(c); first = False
                else:
                    for v in c["vpn_clients"]:
                        if v["type"] == "l2tp" and v.get("enabled") and not ifup(vif(v)): l2tp_connect(v["name"])
                    if sig(c) != last: apply_routes(c)
                last = sig(c)
        except Exception as e: state["errors"] = [str(e)]
        time.sleep(15)

# ---------------- system metrics ----------------
hist = deque(maxlen=240)  # 5 s samples = last 20 min

def read_cpu():
    v = list(map(int, open("/proc/stat").readline().split()[1:])); return sum(v), v[3] + v[4]

def read_net():
    r = {}
    for l in open("/proc/net/dev").read().splitlines()[2:]:
        n, d = l.split(":", 1); f = d.split(); n = n.strip()
        if n != "lo": r[n] = (int(f[0]), int(f[8]))
    return r

def meminfo():
    m = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo") if len(l.split()) > 1}
    return m["MemTotal"] * 1024, (m["MemTotal"] - m.get("MemAvailable", m["MemFree"])) * 1024

def sampler():
    pc = pn = pt = None
    while True:
        try:
            t = time.time(); cpu = read_cpu(); net = read_net(); tot, used = meminfo(); c = 0.0; rates = {}
            if pc and cpu[0] > pc[0]: c = 100 * (1 - (cpu[1] - pc[1]) / (cpu[0] - pc[0]))
            if pn:
                for k, (rx, tx) in net.items():
                    if k in pn: rates[k] = [round(max(0, (rx - pn[k][0]) / (t - pt))), round(max(0, (tx - pn[k][1]) / (t - pt)))]
            hist.append({"t": round(t), "cpu": round(c, 1), "mem": round(100 * used / tot, 1), "net": rates})
            pc, pn, pt = cpu, net, t
        except Exception: pass
        time.sleep(5)

# ---------------- web ----------------
app = Flask(__name__); app.config.update(SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_HTTPONLY=True)

@app.before_request
def guard():
    if request.path in ("/", "/api/login"): return
    if not session.get("ok"): return jsonify(error="auth"), 401
    if request.method != "GET" and request.headers.get("X-Requested-With") != "gw": return jsonify(error="bad request"), 400

@app.get("/")
def index(): return send_file(os.path.join(BASE, "static", "index.html"))

@app.post("/api/login")
def login():
    c = load()
    if c["admin_hash"] and check_password_hash(c["admin_hash"], (request.get_json() or {}).get("password", "")):
        session["ok"] = True; return jsonify(ok=True)
    time.sleep(1); return jsonify(error="wrong password"), 403

@app.post("/api/password")
def passwd():
    pw = (request.get_json() or {}).get("password", "")
    if len(pw) < 8: return jsonify(error="min 8 characters"), 400
    with lock: c = load(); c["admin_hash"] = generate_password_hash(pw); save(c)
    return jsonify(ok=True)

@app.get("/api/config")
def get_config():
    c = load(); c.pop("admin_hash"); c.pop("secret"); return jsonify(c)

@app.put("/api/config")
def put_config():
    d = request.get_json() or {}
    with lock:
        c = load()
        for k in ("lan_ifaces", "nat", "vpn_clients", "routes", "l2tp_server"):
            if k in d: c[k] = d[k]
        if "ovpn_server" in d: c["ovpn_server"].update({k: v for k, v in d["ovpn_server"].items() if k != "clients"})
        try: validate(c)
        except (ValueError, KeyError, TypeError) as e: return jsonify(error=str(e)), 400
        save(c); reconcile(c)
    return jsonify(ok=True, errors=state["errors"])

@app.post("/api/ovpn/client")
def ovpn_add():
    n = (request.get_json() or {}).get("name", "")
    if not re.match(r"^[a-z][a-z0-9_-]{0,31}$", n) or n == "server": return jsonify(error="bad name"), 400
    with lock:
        c = load()
        if n in c["ovpn_server"]["clients"]: return jsonify(error="exists"), 400
        ensure_pki(); issue(n, "clientAuth"); c["ovpn_server"]["clients"].append(n); save(c)
    return jsonify(ok=True)

@app.get("/api/ovpn/client/<n>")
def ovpn_get(n):
    c = load()
    if n not in c["ovpn_server"]["clients"]: return jsonify(error="unknown"), 404
    return ovpn_profile(c, n), 200, {"Content-Type": "application/x-openvpn-profile", "Content-Disposition": f'attachment; filename="{n}.ovpn"'}

@app.delete("/api/ovpn/client/<n>")
def ovpn_del(n):  # note: removes the profile; full revocation would need a CRL (not implemented)
    with lock:
        c = load()
        if n in c["ovpn_server"]["clients"]:
            c["ovpn_server"]["clients"].remove(n); save(c)
            for e in ("key", "crt", "csr", "ext"): rm(f"{PKI}/{n}.{e}")
    return jsonify(ok=True)

@app.get("/api/metrics")
def metrics():
    tot, used = meminfo(); st = os.statvfs("/")
    try: temp = max(int(open(f"/sys/class/thermal/{z}/temp").read()) / 1000 for z in os.listdir("/sys/class/thermal") if z.startswith("thermal_zone"))
    except Exception: temp = None
    return jsonify(hist=list(hist), cores=os.cpu_count(), load=os.getloadavg(), uptime=float(open("/proc/uptime").read().split()[0]), temp=temp,
                   mem_total=tot, mem_used=used, disk_total=st.f_blocks * st.f_frsize, disk_used=(st.f_blocks - st.f_bfree) * st.f_frsize,
                   totals={k: list(v) for k, v in read_net().items()}, hostname=socket.gethostname())

@app.get("/api/log/<n>")
def vpn_log(n):
    v = next((x for x in load()["vpn_clients"] if x["name"] == n), None)
    if not v: return jsonify(error="unknown"), 404
    units = {"openvpn": [f"openvpn-client@gwc-{n}"], "l2tp": ["xl2tpd", "strongswan-starter"]}.get(v["type"], [f"gwp-{n}"])
    return sh("journalctl", "--no-pager", "-n", "60", *[a for u in units for a in ("-u", u)])[1] or "(no log lines)", 200, {"Content-Type": "text/plain"}

@app.get("/api/status")
def status():
    c = load(); ifs = []
    rc, o = sh("ip", "-j", "addr")
    for i in json.loads(o or "[]"):
        ifs.append({"name": i["ifname"], "state": i.get("operstate", ""), "addrs": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []) if a["family"] == "inet"]})
    rc, o = sh("ip", "-j", "-4", "route", "show")
    rt = [{"dst": r["dst"], "via": r.get("gateway", ""), "dev": r.get("dev", ""), "proto": r.get("protocol", "")} for r in json.loads(o or "[]")]
    units = ["strongswan-starter", "xl2tpd", "openvpn-server@gw-server"]
    return jsonify(tun=os.path.exists("/dev/net/tun"), ifaces=ifs, kroutes=rt, routes=state["routes"], errors=state["errors"],
                   vpn=[{"name": v["name"], "up": ifup(vif(v)), "iface": vif(v)} for v in c["vpn_clients"]],
                   services={u: sh("systemctl", "is-active", u)[1] for u in units})

if __name__ == "__main__":
    c = load()
    if "--init" in sys.argv:  # installer: set a random admin password on first install
        if not c["admin_hash"]:
            pw = secrets.token_urlsafe(9); c["admin_hash"] = generate_password_hash(pw); save(c); print(pw)
        else: save(c)
        sys.exit()
    if "--passwd" in sys.argv:
        c["admin_hash"] = generate_password_hash(getpass.getpass("New password: ")); save(c); sys.exit()
    save(c); app.secret_key = c["secret"]
    threading.Thread(target=loop, daemon=True).start(); threading.Thread(target=sampler, daemon=True).start()
    h, p = os.environ.get("GW_LISTEN", "0.0.0.0:8080").rsplit(":", 1)
    try:
        from waitress import serve; serve(app, host=h, port=int(p))
    except ImportError: app.run(host=h, port=int(p))
