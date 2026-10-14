---
name: memory-forensics-volatility
description: >-
  Memory forensics playbook using Volatility 2/3. Use when analyzing memory dumps for malware analysis, credential extraction, process investigation, code injection detection, and incident response timeline reconstruction.
---

# SKILL: Memory Forensics — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert memory forensics techniques using Volatility 2 and 3. Covers memory acquisition, OS identification, process analysis (hidden process detection), network connections, DLL/module analysis, code injection detection (malfind), credential extraction, file carving, registry analysis, and timeline generation. Base models miss the Vol2/Vol3 command differences, malware indicator patterns, and Linux-specific memory analysis.

## 0. RELATED ROUTING

- [traffic-analysis-pcap](../traffic-analysis-pcap/SKILL.md) for correlating network artifacts with memory findings
- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) for understanding post-exploitation artifacts in memory

### Quick Reference

Also load [VOLATILITY_CHEATSHEET.md](./VOLATILITY_CHEATSHEET.md) for Vol2 vs Vol3 command comparison table and common plugin sequences.

---

## 1. MEMORY ACQUISITION

### Linux

```bash
# LiME (Linux Memory Extractor)
insmod lime.ko "path=/tmp/mem.lime format=lime"

# /proc/kcore
dd if=/proc/kcore of=/tmp/mem.raw bs=1M

# AVML (Microsoft's open-source)
./avml /tmp/mem.lime
```

### Windows

```bash
# WinPmem
winpmem_mini_x64.exe memdump.raw

# DumpIt (single-click memory dump)
DumpIt.exe
```

### Virtual Machines

```bash
# VMware: .vmem file in VM directory (suspend VM first)
# VirtualBox: VBoxManage debugvm "VM_NAME" dumpvmcore --filename mem.raw
# KVM/QEMU: virsh dump DOMAIN memdump --memory-only
```

---

## 2. VOLATILITY 2 vs 3

| Concept | Volatility 2 | Volatility 3 |
|---|---|---|
| Profile system | `--profile=Win10x64_19041` | Auto-detected (symbol tables) |
| Image info | `imageinfo` | `windows.info` / `linux.info` |
| Process list | `pslist` | `windows.pslist` |
| Network | `netscan` / `connections` | `windows.netscan` / `windows.netstat` |
| DLLs | `dlllist` | `windows.dlllist` |
| Injection | `malfind` | `windows.malfind` |
| Hashes | `hashdump` | `windows.hashdump` |
| Files | `filescan` | `windows.filescan` |
| Registry | `hivelist` / `printkey` | `windows.registry.hivelist` / `windows.registry.printkey` |

---

## 3. ANALYSIS METHODOLOGY

### Step 1: Identify OS

```bash
# Vol2
vol.py -f mem.raw imageinfo

# Vol3
vol -f mem.raw windows.info
vol -f mem.raw banners.Banners
```

### Step 2: Process Listing — Hidden Process Detection

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE pslist       # EPROCESS linked list
vol.py -f mem.raw --profile=PROFILE psscan       # pool tag scan (finds unlinked)
vol.py -f mem.raw --profile=PROFILE pstree       # parent-child hierarchy

# Vol3
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan
vol -f mem.raw windows.pstree
```

**Red flags**: Process in `psscan` but not `pslist` = DKOM (Direct Kernel Object Manipulation) hiding.

### Step 3: Network Connections

```bash
vol -f mem.raw windows.netscan
vol -f mem.raw windows.netstat
```

### Step 4: DLL / Module Analysis

```bash
vol -f mem.raw windows.dlllist --pid PID
```

**Red flags**: DLL in `dlllist` but `False` in all three `ldrmodules` columns = reflective DLL injection.

### Step 5: Code Injection Detection (Malfind)

```bash
vol -f mem.raw windows.malfind --pid PID
```

**What malfind detects**: Memory regions with `PAGE_EXECUTE_READWRITE` that don't map to a file on disk.

### Step 6: Credential Extraction

```bash
vol -f mem.raw windows.hashdump     # SAM hashes
vol -f mem.raw windows.lsadump      # LSA secrets
vol -f mem.raw windows.cachedump    # domain cached creds
```

### Step 7: File Extraction

```bash
vol -f mem.raw windows.filescan | grep -i "password\|secret\|flag"
vol -f mem.raw windows.dumpfiles --virtaddr OFFSET
```

### Step 8: Registry Analysis

```bash
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
vol -f mem.raw windows.registry.userassist
```

### Step 9: Command History

```bash
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.consoles
```

### Step 10: Timeline Generation

```bash
vol -f mem.raw timeliner.Timeliner
```

---

## 4. LINUX MEMORY ANALYSIS

```bash
# Vol3
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash          # bash history
vol -f mem.lime linux.check_afinfo  # rootkit detection
vol -f mem.lime linux.check_syscall # syscall hooking
vol -f mem.lime linux.tty_check     # TTY hooking
```

### Building Linux Profiles (Vol2)

```bash
cd volatility/tools/linux && make
zip LinuxProfile.zip module.dwarf /boot/System.map-$(uname -r)
# Place in volatility/plugins/overlays/linux/
```

---

## 5. MALWARE INDICATORS IN MEMORY

| Indicator | Detection Method | What It Means |
|---|---|---|
| Process in psscan but not pslist | Compare pslist vs psscan | DKOM -- process hiding |
| Unexpected parent-child | pstree analysis | e.g., svchost spawned by cmd.exe |
| MZ header in non-image memory | malfind | Reflective DLL / PE injection |
| RWX memory without backing file | malfind | Shellcode injection |
| DLL unlinked from all PEB lists | ldrmodules (all False) | Stealth DLL loading |
| svchost.exe not child of services.exe | pstree | Fake svchost (malware) |
| Unusual network connections | netscan + PID correlation | C2 communication |
| Hooking in SSDT/IDT | ssdt / idt plugins | Rootkit |

### Normal Parent-Child Relationships (Windows)

```
System (4)
+-- smss.exe
    +-- csrss.exe
    +-- wininit.exe
    |   +-- services.exe
    |   |   +-- svchost.exe (multiple)
    |   |   +-- spoolsv.exe
    |   +-- lsass.exe
    +-- winlogon.exe
        +-- explorer.exe
            +-- user applications
```

---

## 6. DECISION TREE

```
Memory dump acquired
+-- What OS?
|   +-- Windows -> vol imageinfo / windows.info (Step 1)
|   +-- Linux -> build profile or use Vol3 auto-detect (4)
+-- Malware investigation?
|   +-- pslist vs psscan (hidden?) (Step 2)
|   +-- pstree (suspicious spawning?) (5)
|   +-- malfind (RWX memory?) (Step 5)
|   +-- ldrmodules (unlinked DLLs?) (Step 4)
|   +-- netscan (C2 connections?) (Step 3)
|   +-- dumpfiles -> extract suspicious files (Step 7)
+-- Credential recovery?
|   +-- SAM hashes -> hashdump (Step 6)
|   +-- LSA secrets -> lsadump (Step 6)
|   +-- Cached domain creds -> cachedump (Step 6)
+-- Incident timeline?
|   +-- timeliner (Step 10)
|   +-- cmdscan / consoles (Step 9)
|   +-- userassist (Step 8)
+-- CTF / flag hunting?
|   +-- filescan + grep for flag patterns (Step 7)
|   +-- cmdscan for typed flags/passwords (Step 9)
|   +-- clipboard, screenshot, envars plugins
+-- Linux-specific?
    +-- linux_bash for shell history (4)
    +-- linux_check_syscall for rootkit (4)
```
