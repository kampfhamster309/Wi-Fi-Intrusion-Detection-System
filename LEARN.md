#  LEARN.md — Wi-Fi Intrusion Detection System (WIDS)

> A guided learning companion for the Raspberry Pi Pico W–based Wi-Fi IDS project.
> Perfect for students, hobbyists, and cybersecurity learners who want to understand
> the theory, code, and real-world concepts behind this system.

---

##  Table of Contents

1. [Who This Is For](#-who-this-is-for)
2. [Prerequisites](#-prerequisites)
3. [Core Concepts](#-core-concepts)
   - [What is a WIDS?](#what-is-a-wids)
   - [Wi-Fi Attack Types Detected](#wi-fi-attack-types-detected)
   - [RSSI Explained](#rssi-explained)
4. [Hardware Deep Dive](#-hardware-deep-dive)
5. [MicroPython Walkthrough](#-micropython-walkthrough)
   - [Wi-Fi Scanning with `network.WLAN`](#wi-fi-scanning-with-networkwlan)
   - [Evil Twin Detection Logic](#evil-twin-detection-logic)
   - [RSSI Anomaly Logic](#rssi-anomaly-logic)
   - [Channel Flooding Logic](#channel-flooding-logic)
   - [Alert Logging](#alert-logging)
6. [Socket Web Server](#-socket-web-server)
   - [Routes Explained](#routes-explained)
   - [Frontend Dashboard](#frontend-dashboard)
7. [Configuration Reference](#-configuration-reference)
8. [Learning Milestones](#-learning-milestones)
9. [Extending the Project](#-extending-the-project)
10. [Further Reading & Resources](#-further-reading--resources)

---

##  Who This Is For

This project is ideal for:

- **Cybersecurity beginners** wanting hands-on experience with wireless threat detection
- **MicroPython/Raspberry Pi hobbyists** learning embedded network programming
- **Students** studying networking, IoT security, or ethical hacking
- **Developers** building low-cost network monitoring tools

No professional security background required — just curiosity and a Pico W!

---

##  Prerequisites

Before diving in, you should be comfortable with:

| Skill | Level Needed |
|---|---|
| Basic Python syntax | Beginner |
| Understanding of Wi-Fi / networking basics | Beginner |
| Using Thonny IDE or similar MicroPython tools | Beginner |
| HTML/JavaScript fundamentals | Optional (for dashboard customization) |
| Cybersecurity concepts (spoofing, DoS) | Optional (covered below) |

---

##  Core Concepts

### What is a WIDS?

A **Wi-Fi Intrusion Detection System (WIDS)** passively monitors the wireless RF (radio frequency)
environment to detect suspicious activity. Unlike a firewall (which *blocks* traffic), a WIDS
*observes and alerts* — it is a **detection** tool, not a prevention tool.

This project implements a lightweight WIDS on the Raspberry Pi Pico W, which:
- Scans surrounding Wi-Fi access points every 5 seconds
- Maintains a baseline of known network signatures
- Alerts when anomalies are detected (new SSIDs, RSSI spikes, channel congestion)

### Wi-Fi Attack Types Detected

####  Evil Twin Attack
An attacker sets up a rogue Access Point broadcasting the **same SSID** as a legitimate network.
Victims unknowingly connect to the attacker's hotspot, enabling credential theft and
man-in-the-middle (MitM) interception.

**How WIDS detects it:** If two or more unique BSSIDs (MAC addresses) share the same SSID,
it flags an "Evil Twin suspected" alert.

```
Legitimate AP: SSID="HomeNet"  BSSID=AA:BB:CC:11:22:33
Rogue AP:      SSID="HomeNet"  BSSID=DD:EE:FF:44:55:66  ← ALERT!
```

####  RSSI Anomaly / Man-in-the-Middle Indicator
A sudden spike in signal strength (RSSI) from a known network may indicate that a rogue
device has been physically placed closer to the victim to intercept traffic.

**How WIDS detects it:** If a known `SSID+BSSID` key shows an RSSI change greater than
`RSSI_SPIKE` (default: 20 dBm), it logs an anomaly.

####  Channel Flooding / DoS
An attacker floods a specific Wi-Fi channel with many fake beacons or probe requests to
cause network disruption (Denial-of-Service) or to force clients to roam to a rogue AP.

**How WIDS detects it:** If more than 6 networks are detected on a single channel, a
"Channel flooding anomaly" alert is triggered.

### RSSI Explained

**RSSI (Received Signal Strength Indicator)** measures the power level of a received
wireless signal, expressed in **dBm** (decibel-milliwatts). It is a negative number:

| RSSI Value | Signal Quality |
|---|---|
| -30 dBm | Excellent (very close to AP) |
| -50 dBm | Good |
| -70 dBm | Fair |
| -90 dBm | Poor (far away or obstructed) |

A sudden jump from -70 dBm to -50 dBm for the same BSSID = +20 dBm spike → **ALERT**.

---

##  Hardware Deep Dive

### Raspberry Pi Pico W

The **Pico W** is a microcontroller board by Raspberry Pi Ltd featuring:
- **RP2040** dual-core ARM Cortex-M0+ processor @ 133 MHz
- **2MB onboard Flash** for storing MicroPython and scripts
- **CYW43439** Wi-Fi chip (2.4 GHz 802.11n) — the heart of this project
- **MicroPython** firmware support for high-level scripting

The onboard Wi-Fi chip is accessed via the `network` module in MicroPython, which allows:
- Connecting to existing networks (`STA_IF` — Station Mode)
- Hosting its own network (`AP_IF` — Access Point Mode)
- **Active scanning** of surrounding networks → used by this WIDS

### Power Options
- Micro-USB from a laptop or phone charger
- External 5V battery pack (for portable deployment)

---

##  MicroPython Walkthrough

The entire system lives in a single `main.py` file (~168 lines). Let's break it down.

### Wi-Fi Scanning with `network.WLAN`

```python
import network

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect(WIFI_SSID, WIFI_PASS)
```

The Pico W connects to your home network in **Station mode** (`STA_IF`). Once connected,
it can call `wlan.scan()` to probe the surrounding RF environment.

`wlan.scan()` returns a list of tuples for each detected AP:

```
(ssid, bssid, channel, rssi, security, hidden)
```

- `ssid` — Network name (bytes, decoded to string)
- `bssid` — Hardware MAC address of the AP (6-byte bytes object)
- `channel` — Wi-Fi channel (1–13 for 2.4 GHz)
- `rssi` — Signal strength in dBm

### Evil Twin Detection Logic

```python
seen = {}
for n in nets:
    ssid = n[0].decode("utf-8", "ignore")
    bssid = ":".join("%02x" % b for b in n[1])
    seen.setdefault(ssid, []).append((bssid, rssi))

for ssid in seen:
    if len(seen[ssid]) > 1:
        log_alert(f"Evil Twin suspected: {ssid}")
```

**Concept:** `seen` is a dictionary mapping each SSID → list of `(BSSID, RSSI)` tuples.
If any SSID has more than one entry, multiple physical APs are broadcasting the same
name — a hallmark of an Evil Twin.

### RSSI Anomaly Logic

```python
key = ssid + bssid
if key in baseline and abs(rssi - baseline[key]) > RSSI_SPIKE:
    log_alert(f"RSSI anomaly: {ssid}")
baseline[key] = rssi
```

**Concept:** `baseline` stores the last known RSSI for each `SSID+BSSID` key. If the new
scan shows a change exceeding `RSSI_SPIKE` (20 dBm by default), an alert is raised. The
baseline is then updated to the new value.

### Channel Flooding Logic

```python
channels = {}
for n in nets:
    ch = n[2]
    channels.setdefault(ch, []).append(rssi)

for ch in channels:
    if len(channels[ch]) > 6:
        log_alert(f"Channel flooding anomaly: ch {ch}")
```

**Concept:** Wi-Fi channels (especially 1, 6, 11 for 2.4 GHz) are shared. More than 6 networks
on a single channel is abnormally high and may indicate beacon flooding as a DoS technique.

### Alert Logging

```python
alerts = []

def log_alert(msg):
    alerts.append({"t": time.time(), "msg": msg})
    if len(alerts) > 50:
        alerts.pop(0)
```

Alerts are stored in a capped list (max 50 entries) as JSON-serializable dicts. The oldest
alert is evicted when the list is full — a simple **circular buffer** pattern.

---

##  Socket Web Server

### Routes Explained

The Pico W runs a minimal **raw socket HTTP server** on port 80 — no frameworks needed.

```python
addr = socket.getaddrinfo("0.0.0.0", 80)[0][-1]
s = socket.socket()
s.bind(addr)
s.listen(1)
```

Three routes are handled:

| Route | Response Type | Description |
|---|---|---|
| `GET /` | `text/html` | Serves the full dashboard HTML page |
| `GET /scan` | `application/json` | Returns channel activity as JSON |
| `GET /alerts` | `application/json` | Returns current alert list as JSON |

The main loop accepts one connection at a time (blocking), checks if a background scan
is due, and then reads the HTTP request line to route accordingly.

> **Why raw sockets?** The Pico W's limited RAM (~264 KB) makes full HTTP frameworks
> impractical. Raw sockets give full control with minimal overhead.

### Frontend Dashboard

The dashboard is a **self-contained HTML/JS string** embedded in `main.py`:

- **CSS:** Dark terminal aesthetic (`background:#0b0f1a`, monospace font)
- **JavaScript:** Uses `fetch()` to poll `/scan` and `/alerts` every 3 seconds
- **Channel Visualization:** Each network on a channel is represented by a `█` block
- **Alert Panel:** Scrollable, auto-scrolls to newest alert (red text)

The entire frontend is served from RAM — no SD card or filesystem needed.

---

##  Configuration Reference

All configurable constants are at the top of `main.py`:

```python
WIFI_SSID = "YourNetworkName"   # Your home/lab Wi-Fi SSID
WIFI_PASS = "YourPassword"      # Your Wi-Fi password
SCAN_INTERVAL = 5               # Seconds between background scans
RSSI_SPIKE = 20                 # dBm change threshold for RSSI anomaly alert
```

**Tuning tips:**
- Lower `SCAN_INTERVAL` (e.g., `2`) for faster detection but higher CPU use
- Raise `RSSI_SPIKE` (e.g., `30`) in dense environments to reduce false positives
- Lower `RSSI_SPIKE` (e.g., `10`) in quiet environments for higher sensitivity

---

##  Learning Milestones

Work through these progressively to solidify your understanding:

- [ ] **Level 1 — Setup:** Flash MicroPython onto Pico W and run `main.py` successfully
- [ ] **Level 2 — Explore:** Open the dashboard and observe real channel activity in your home
- [ ] **Level 3 — Understand:** Read `scan_wids()` and trace how one detected AP becomes an alert
- [ ] **Level 4 — Modify:** Change `RSSI_SPIKE` to `10` and observe if you get more alerts
- [ ] **Level 5 — Extend:** Add a new detection rule (e.g., alert on open/unsecured networks)
- [ ] **Level 6 — Challenge:** Add timestamp formatting to the alerts panel in the dashboard
- [ ] **Level 7 — Advanced:** Replace the raw socket server with `uasyncio` for concurrent connections

---

##  Extending the Project

Here are ideas to take this project further:

- **Persistent Logging:** Write alerts to a CSV file on a connected SD card using `uos`
- **Email/SMS Notifications:** Use an SMTP-over-Wi-Fi library to send real-time alert emails
- **Deauth Detection:** Detect 802.11 deauthentication frame floods (requires raw frame sniffing)
- **Geo-Channel Mapping:** Display alerts with timestamps in a time-series graph on the dashboard
- **Multi-Device Mesh:** Chain multiple Pico Ws covering different rooms, aggregating to a central server
- **Whitelist Mode:** Maintain a list of known-good BSSIDs and alert only on unknown APs
- **MQTT Integration:** Publish alerts to an MQTT broker (e.g., Home Assistant, Node-RED)

---

## 📖 Further Reading & Resources

### MicroPython & Pico W
- [Official MicroPython Documentation](https://docs.micropython.org/en/latest/)
- [Raspberry Pi Pico W Datasheet](https://datasheets.raspberrypi.com/picow/pico-w-datasheet.pdf)
- [Thonny IDE](https://thonny.org/) — Recommended for flashing and developing on Pico W

### Wi-Fi Security Concepts
- [IEEE 802.11 Standard Overview](https://en.wikipedia.org/wiki/IEEE_802.11)
- [Evil Twin Attack — OWASP](https://owasp.org/www-community/attacks/Wireless_Access_Point_Attack)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html) — Industry-standard wireless auditing suite
- [Wireshark Wi-Fi Capture Guide](https://wiki.wireshark.org/CaptureSetup/WLAN) — For visualizing raw frames

### Ethical Hacking & Learning Platforms
- [TryHackMe — Pre-Security Path](https://tryhackme.com/path/outline/presecurity)
- [Hack The Box Academy — Introduction to Networking](https://academy.hackthebox.com/)

---

>  **Ethical Use Notice:** This tool is designed for **monitoring your own network only**.
> Scanning or interfering with networks you do not own or have explicit permission to test
> is illegal in most jurisdictions. Always practice responsible, ethical security research.

---

*LEARN.md authored for [flatmarstheory/Wi-Fi-Intrusion-Detection-System](https://github.com/flatmarstheory/Wi-Fi-Intrusion-Detection-System)*
*Developed by Rai Bahadur Singh — Licensed under The Unlicense (Public Domain)*
