---
name: traffic-analysis-pcap
description: >-
  Traffic analysis and PCAP forensics playbook. Use when analyzing network captures including Wireshark filters, protocol analysis (HTTP/DNS/FTP/SMTP/USB/WiFi), data extraction, covert channel detection, PCAP repair, TLS decryption, and tshark command-line analysis.
---

# SKILL: Traffic Analysis & PCAP

> **AI LOAD INSTRUCTION**: Expert traffic analysis and PCAP forensics. Covers PCAP repair, Wireshark filters, protocol analysis (HTTP, HTTPS/TLS, DNS, FTP, SMTP, USB HID, WiFi, ICMP), data extraction, NetworkMiner, and tshark CLI.

## 0. RELATED ROUTING

- [memory-forensics-volatility](../memory-forensics-volatility/SKILL.md) for correlating memory artifacts with network traffic
- [steganography-techniques](../steganography-techniques/SKILL.md) for analyzing extracted files

---

## 1. PCAP REPAIR

```bash
pcapfix corrupted.pcap -o fixed.pcap
# Magic bytes: d4c3b2a1=pcap(LE), a1b2c3d4=pcap(BE), 0a0d0d0a=pcapng
editcap -F pcap capture.pcapng capture.pcap    # convert pcapng->pcap
mergecap -w merged.pcap file1.pcap file2.pcap  # merge
```

---

## 2. WIRESHARK ESSENTIAL FILTERS

```
# IP
ip.addr == 10.0.0.1        ip.src == 10.0.0.1
ip.addr == 10.0.0.0/24    !(ip.addr == 10.0.0.1)

# TCP stream
tcp.stream eq 5
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.len > 0

# HTTP
http.request.method == "POST"
http.response.code >= 400
http.request.uri contains "login"
http.cookie contains "session"
frame contains "password"
frame contains "flag{"

# DNS
dns.qry.name contains "evil.com"
dns.qry.type == 16    # TXT records
dns.qry.name.len > 50 # DNS tunneling indicator

# TLS
tls.handshake.type == 1   # Client Hello
tls.handshake.extensions.server_name  # SNI
```

---

## 3. PROTOCOL ANALYSIS

### HTTP
```
Right-click -> Follow -> TCP Stream
File -> Export Objects -> HTTP -> Save All
Credential filter: http.request.method=="POST" && frame contains "password"
```

### HTTPS/TLS Decryption
```bash
# Method 1: SSLKEYLOGFILE
export SSLKEYLOGFILE=/tmp/sslkeys.log && firefox https://target.com
# Wireshark: Preferences -> Protocols -> TLS -> Pre-Master-Secret log

# Method 2: Server private key (RSA only)
# Wireshark: Preferences -> TLS -> RSA keys list -> Add .pem
```

### DNS Tunneling
```bash
# Indicators: long subdomains (>30 chars), high TXT volume, Base32/64 subdomains
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name
```

### FTP
```bash
tshark -r capture.pcap -Y "ftp.request.command==USER || ftp.request.command==PASS" -T fields -e ftp.request.arg
```

### USB Keyboard HID
```bash
# Filter: usb.transfer_type == 0x01
tshark -r usb.pcap -Y "usb.capdata && usb.data_len == 8" -T fields -e usb.capdata > keystrokes.txt
# byte[0]=modifier, byte[2]=keycode: 0x04=a..0x1d=z, 0x1e=1..0x27=0, 0x28=Enter, 0x2c=Space
```

### WiFi
```bash
hcxpcapngtool -o hash.hc22000 capture.pcap
hashcat -m 22000 hash.hc22000 wordlist.txt
# Deauth: wlan.fc.type_subtype == 0x0c
```

### ICMP Exfiltration
```bash
# Unusual payload: icmp && data.len > 48
tshark -r capture.pcap -Y "icmp.type==8" -T fields -e data.data
```

---

## 4. DATA EXTRACTION

```bash
# File carving: Wireshark File -> Export Objects
binwalk -e exported_stream.bin
foremost -i exported_stream.bin -o carved/

# Credentials
# NTLM: ntlmssp.auth.username -> extract challenge/response
# hash format: user::domain:challenge:NTProofStr:blob -> hashcat -m 5600
```

---

## 5. TSHARK COMMAND-LINE

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u
tshark -r capture.pcap -q -z io,stat,1        # I/O graph
tshark -r capture.pcap -q -z conv,tcp         # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip     # IP endpoints
tshark -r capture.pcap -q -z io,phs           # protocol hierarchy
tshark -r capture.pcap --export-objects http,/tmp/exported/
```

---

## 6. DECISION TREE

```
PCAP file?
|-- Won't open? -> pcapfix, editcap (Section 1)
|-- Overview: tshark -q -z io,phs / conv,tcp / endpoints,ip
|
|-- HTTP traffic?
|   |-- Export objects: File -> Export Objects -> HTTP
|   |-- Credential hunt: POST + password filters
|   |-- Encrypted? -> SSLKEYLOGFILE or RSA key
|
|-- DNS traffic?
|   |-- Long subdomains / high TXT -> DNS tunneling
|   |-- tshark -Y dns -T fields -e dns.qry.name
|
|-- FTP/SMTP? -> extract plaintext credentials
|-- USB? -> HID keyboard decode
|-- WiFi? -> WPA handshake -> hashcat
|-- ICMP large payloads? -> data exfiltration
|
|-- Need automated extraction?
    |-- NetworkMiner for files/creds/images
    |-- tshark --export-objects
    |-- binwalk/foremost on exported streams
```
