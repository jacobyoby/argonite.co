#!/usr/bin/env python3
"""Local network HUD.

Reads this Mac's own network settings and counters and serves them to a page
on 127.0.0.1. It sends nothing to the network it reports on: every command
below reads local state only.
"""
import collections
import http.server
import ipaddress
import json
import os
import re
import subprocess
import threading
import time

HOST, PORT = "127.0.0.1", 8787
HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL_PREFIXES = ("utun", "ipsec", "ppp", "wg", "tun", "tap")

lock = threading.Lock()
state = {"fast": {}, "wifi": {}, "egress": {}, "updated": 0}
history = collections.deque(maxlen=90)  # outbound packets/s on Wi-Fi


def run(cmd, timeout=25):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        ).stdout
    except Exception:
        return ""


def hardware_ports():
    ports = {}
    out = run(["networksetup", "-listallhardwareports"])
    for name, dev in re.findall(r"Hardware Port: (.+)\nDevice: (\S+)", out):
        ports[dev] = name
    return ports


def wifi_device(ports):
    for dev, name in ports.items():
        if name == "Wi-Fi":
            return dev
    return "en0"


def braces(text, key):
    m = re.search(re.escape(key) + r"[^\n]*?\{([^}]*)\}", text)
    return [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []


def one(text, pattern):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ""


def lease(dev):
    out = run(["ipconfig", "getsummary", dev])
    routers = braces(out, "router (ip_mult):")
    return {
        "ip": one(out, r"yiaddr = (\S+)"),
        "mask": one(out, r"subnet_mask \(ip\): (\S+)"),
        "router": routers[0] if routers else "",
        "dns": braces(out, "domain_name_server (ip_mult):"),
        "domain": one(out, r"domain_name \(string\): (\S+)"),
    }


def default_route(ports):
    out = run(["route", "-n", "get", "default"])
    dev = one(out, r"interface: (\S+)")
    return {
        "gateway": one(out, r"gateway: (\S+)"),
        "device": dev,
        "port": ports.get(dev, ""),
    }


def tunnels():
    found, dev = [], ""
    for line in run(["ifconfig"]).splitlines():
        m = re.match(r"^(\S+?):", line)
        if m:
            dev = m.group(1)
            continue
        m = re.match(r"\s+inet (\S+)", line)
        if m and dev.startswith(TUNNEL_PREFIXES):
            ip = m.group(1)
            try:
                if ipaddress.ip_address(ip).is_link_local:
                    continue  # link-local utun, not a VPN carrying traffic
            except ValueError:
                pass
            found.append({"device": dev, "ip": ip})
    return found


def firewall():
    out = run([
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "--getglobalstate", "--getstealthmode",
    ])
    level = one(out, r"State = (\d)")
    return {
        "level": {"0": "off", "1": "on", "2": "block all incoming"}.get(level, "unknown"),
        "on": level in ("1", "2"),
        "stealth": bool(re.search(r"stealth mode is on", out, re.I)),
    }


def listeners():
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "cn"])
    seen, cmd = [], ""
    for line in out.splitlines():
        if line.startswith("c"):
            cmd = line[1:]
        elif line.startswith("n"):
            addr = line[1:]
            if addr.startswith(("127.", "[::1]", "localhost")):
                continue
            item = {"process": cmd, "address": addr}
            if item not in seen:
                seen.append(item)
    return seen


def counters(dev):
    lines = run(["netstat", "-ibn", "-I", dev]).splitlines()
    if not lines:
        return None
    # Locate the Opkts/Obytes columns by name rather than by position: the
    # trailing "Coll" column is not guaranteed on every macOS release.
    header = lines[0].split()
    try:
        oi, bi = header.index("Opkts"), header.index("Obytes")
    except ValueError:
        oi = bi = None
    for line in lines[1:]:
        if "<Link#" in line:
            f = line.split()
            try:
                if oi is not None and bi < len(f):
                    return {"opkts": int(f[oi]), "obytes": int(f[bi])}
                return {"opkts": int(f[-4]), "obytes": int(f[-2])}
            except (ValueError, IndexError):
                return None
    return None


def wifi_link(dev):
    try:
        data = json.loads(run(["system_profiler", "SPAirPortDataType", "-json"], 40))
        for iface in data["SPAirPortDataType"][0].get("spairport_airport_interfaces", []):
            if iface.get("_name") != dev:
                continue
            cur = iface.get("spairport_current_network_information") or {}
            if not cur.get("_name"):
                return {"connected": False}
            sec = str(cur.get("spairport_security_mode", ""))
            sec = sec.replace("spairport_security_mode_", "").replace("_", " ")
            sig = re.findall(r"-?\d+", str(cur.get("spairport_signal_noise", "")))
            return {
                "connected": True,
                "ssid": cur.get("_name", ""),
                "security": sec or "unknown",
                "open": sec == "none",
                "channel": cur.get("spairport_network_channel", ""),
                "phy": cur.get("spairport_network_phymode", ""),
                "rate": cur.get("spairport_network_rate", ""),
                "signal": int(sig[0]) if sig else None,
                "noise": int(sig[1]) if len(sig) > 1 else None,
            }
    except Exception:
        pass
    return {"connected": False}


def findings(s):
    out = []
    wifi, fast, egress = s["wifi"], s["fast"], s["egress"]
    le = fast.get("lease", {})
    if not wifi.get("connected"):
        if le.get("ip"):
            return [{"sev": "warn", "text": "Wi-Fi link details are unavailable — grant this tool Location Services access to read the SSID and encryption. The lease has an address, so you are likely connected."}]
        return [{"sev": "info", "text": "Wi-Fi is not connected to a network."}]
    if wifi.get("open"):
        out.append({"sev": "bad", "text": "Wi-Fi has no encryption. Anything sent on it without a tunnel or HTTPS is readable in radio range."})
    if egress.get("quiet"):
        out.append({"sev": "ok", "text": "Almost nothing is leaving on Wi-Fi (under 0.5 packets a second over the last 30 seconds)."})
    elif egress.get("samples", 0) >= 5:
        out.append({"sev": "warn", "text": "This Mac is sending packets on Wi-Fi."})
    try:
        net = ipaddress.ip_network(f"{le.get('ip')}/{le.get('mask')}", strict=False)
        off = [d for d in le.get("dns", [])
               if ipaddress.ip_address(d).is_private and ipaddress.ip_address(d) not in net]
        if off:
            out.append({"sev": "warn", "text": f"The lease hands out {len(off)} private DNS server(s) outside the guest subnet."})
    except ValueError:
        pass
    if le.get("domain"):
        out.append({"sev": "warn", "text": "The lease hands out a domain name, which is added to this Mac's search list."})
    rt = fast.get("route", {})
    if rt.get("device") and rt.get("device") != fast.get("wifi_device"):
        out.append({"sev": "ok", "text": f"Default route is {rt.get('port') or rt.get('device')}, not Wi-Fi."})
    else:
        out.append({"sev": "warn", "text": "Default route is the Wi-Fi."})
    tuns = fast.get("tunnels")
    if not tuns:
        out.append({"sev": "info", "text": "No tunnel interface has an address, so no VPN is carrying traffic."})
    elif any(t.get("default") for t in tuns):
        out.append({"sev": "ok", "text": "A VPN tunnel carries the default route; outbound traffic is going through it."})
    else:
        out.append({"sev": "info", "text": "A tunnel interface has an address but does not carry the default route (e.g. iCloud Private Relay), so no VPN is carrying your traffic."})
    fw = fast.get("firewall", {})
    if not fw.get("on"):
        out.append({"sev": "bad", "text": "The macOS firewall is off."})
    elif not fw.get("stealth"):
        out.append({"sev": "warn", "text": "Firewall stealth mode is off."})
    else:
        out.append({"sev": "ok", "text": f"Firewall: {fw.get('level')}, stealth mode on."})
    n = len(fast.get("listeners", []))
    if n:
        out.append({"sev": "info", "text": f"{n} service(s) listening on non-loopback addresses."})
    return out


def fast_loop():
    ports = hardware_ports()
    dev = wifi_device(ports)
    last, tick = None, 0
    while True:
        now = time.time()
        c = counters(dev)
        if c and last and now > last[0]:
            dt = now - last[0]
            pps = max(0, c["opkts"] - last[1]["opkts"]) / dt
            bps = max(0, c["obytes"] - last[1]["obytes"]) / dt
            history.append(round(pps, 2))
            recent = list(history)[-15:]
            with lock:
                state["egress"] = {
                    "pps": round(pps, 1),
                    "bps": round(bps),
                    "history": list(history),
                    "samples": len(history),
                    "quiet": len(recent) >= 15 and sum(recent) / len(recent) < 0.5,
                }
        if c:
            last = (now, c)
        if tick % 4 == 0:
            if tick % 40 == 0:
                ports = hardware_ports()
                dev = wifi_device(ports)
            route = default_route(ports)
            tuns = tunnels()
            for t in tuns:
                t["default"] = t["device"] == route.get("device")
            fast = {
                "wifi_device": dev,
                "lease": lease(dev),
                "route": route,
                "tunnels": tuns,
                "firewall": firewall(),
                "listeners": listeners(),
            }
            with lock:
                state["fast"] = fast
        with lock:
            state["updated"] = time.time()
        tick += 1
        time.sleep(2)


def wifi_loop():
    while True:
        with lock:
            dev = state["fast"].get("wifi_device", "en0")
        link = wifi_link(dev)
        with lock:
            state["wifi"] = link
        time.sleep(15)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/status":
            with lock:
                snap = json.loads(json.dumps(state))
            snap["findings"] = findings(snap)
            self.send(json.dumps(snap).encode(), "application/json")
        elif self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self.send(f.read(), "text/html; charset=utf-8")
        else:
            self.send_error(404)


if __name__ == "__main__":
    threading.Thread(target=fast_loop, daemon=True).start()
    threading.Thread(target=wifi_loop, daemon=True).start()
    print(f"Network HUD on http://{HOST}:{PORT}")
    http.server.ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
