# 802.11 Probe Request Exfiltration Toolkit

**By Nick Paul and AJ Lopez**

A research toolkit for demonstrating and detecting data exfiltration via 802.11 WiFi probe requests. The project has two components: an exfiltration tool that encodes data into probe request SSIDs, and a detection tool that monitors for this behavior on the network.

> ⚠️ **Disclaimer:** This toolkit is intended for educational and authorized security research only. Use only on networks and systems you own or have explicit permission to test.

---

## How It Works

WiFi devices broadcast **probe requests** — packets containing an SSID — when scanning for known networks. SSIDExfil abuses this mechanism by encoding arbitrary data into the SSID field of probe requests, effectively transmitting data over the air without ever connecting to a network. ProbyMonitor sits on the other side, passively monitoring probe requests to detect this behavior.

```
[Windows Device]                         [Monitoring Device]
  SSIDEXFIL.py                             ProbyMonitor.py
  - Read & compress file                   - Put interface in monitor mode
  - Encode chunks into SSIDs               - Capture all probe requests
  - Broadcast as probe requests   --->     - Filter out legitimate SSIDs
                                           - Flag suspicious patterns
  SSIDEXFILLISTENER.py
  - Read .pcap capture
  - Extract marked SSIDs
  - Reassemble & decompress data
```

---

## Tools

### `SSIDEXFIL.py` — Exfiltration Sender
**Platform:** Windows

Reads a file, compresses it with zlib, splits it into 6-byte chunks, and transmits each chunk as a crafted WiFi probe request. Each SSID is prefixed with a `*` marker for identification.

**Requirements:**
```
pip install pywifi
```

**Usage:**
```bash
python SSIDEXFIL.py <path_to_file>
```

**Example:**
```bash
python SSIDEXFIL.py C:\Users\user\sensitive_data.txt
```

---

### `SSIDEXFILLISTENER.py` — Exfiltration Receiver
**Platform:** Linux / Windows

Takes a `.pcap` capture file, extracts all `*`-prefixed SSIDs, reassembles the chunks, decompresses the data, and writes the result to `exfiltratedData.txt`.

**Requirements:**
```
pip install scapy
```

**Usage:**
```bash
echo "/path/to/capture.pcap" | python SSIDEXFILLISTENER.py
```

**Output:** `exfiltratedData.txt` in the current directory.

---

### `ProbyMonitor.py` — Exfiltration Detector
**Platform:** Linux (tested on Parrot OS and Kali)

Puts a wireless interface into monitor mode using `airmon-ng`, captures all 802.11 probe requests, and filters out known legitimate SSIDs. Any remaining probe requests — especially repeated ones from a single device — are flagged as potentially suspicious.

**Requirements:**
```
pip install scapy wifi
```
- A wireless interface that supports monitor mode
- `airmon-ng` installed (`sudo apt install aircrack-ng`)
- Must be run as root

**Usage:**
```bash
sudo python3 ProbyMonitor.py
```

You will be prompted to:
1. Select a wireless interface
2. Confirm it is disconnected from any network

ProbyMonitor will then begin monitoring and print results when interrupted with `CTRL+C`.

**Output:**

```
All Captured Probe Requests Minus Legitimate Access Points
# of Probes    MAC Address                     SSID
14             aa:bb:cc:dd:ee:ff               *b'\x78\x9c...'

[+] Results
   - The Device with most bogus probe requests is aa:bb:cc:dd:ee:ff with 14 requests
     A closer look should be taken at the SSID field to see if data is being exfiltrated
```

---

## Demo

See `ProbyMonitorDemo.mp4` for a full demonstration of the toolkit in action.

---

## Authors

- **Nick Paul**
- **AJ Lopez**
