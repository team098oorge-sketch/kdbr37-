---
name: hash-attack-techniques
description: >-
  Hash attack playbook. Use when exploiting length extension, MD5/SHA1
  collisions, HMAC timing leaks, birthday attacks, or hash-based proof
  of work in CTF and authorized testing scenarios.
---

# SKILL: Hash Attack Techniques — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert hash attack techniques for CTF and security assessments. Covers length extension attacks, MD5/SHA1 collision generation, meet-in-the-middle hash attacks, HMAC timing side channels, birthday attacks, and proof-of-work solving.

## 0. RELATED ROUTING

- [rsa-attack-techniques](../rsa-attack-techniques/SKILL.md) when hash weaknesses affect RSA signature schemes
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) when hash is used in key derivation

### Quick attack selection

| Scenario | Attack | Tool |
|---|---|---|
| `H(secret \|\| msg)` known, extend message | Length extension | HashPump, hash_extender |
| Need two files with same MD5 | Identical-prefix collision | fastcoll |
| Need specific MD5 prefix match | Chosen-prefix collision | hashclash |
| Byte-by-byte HMAC comparison | Timing attack | Custom script |
| Find any collision | Birthday attack | O(2^(n/2)) |
| Proof of work: find hash with leading zeros | Brute force | hashcat, Python |

---

## 1. LENGTH EXTENSION ATTACK

### 1.1 Vulnerable vs Non-Vulnerable

| Hash | Vulnerable | Why |
|---|---|---|
| MD5 | Yes | Merkle-Damgard construction |
| SHA-1 | Yes | Merkle-Damgard construction |
| SHA-256 | Yes | Merkle-Damgard construction |
| SHA-512 | Yes | Merkle-Damgard construction |
| SHA-3 / Keccak | No | Sponge construction |
| HMAC-* | No | Double hashing prevents extension |
| BLAKE2 | No | Different construction |

### 1.2 Attack Mechanism

```
Given:   MAC = H(secret || original_message)
Known:   original_message, len(secret), MAC value
Compute: H(secret || original_message || padding || extension)
         WITHOUT knowing the secret!

How: The MAC value IS the internal hash state after processing
     (secret || original_message || padding).
     Initialize hash with this state, continue hashing extension.
```

### 1.3 Tool Usage

```bash
# HashPump
hashpump -s "known_mac_hex" \
         -d "original_data" \
         -k 16 \
         -a "extension_data"

# hash_extender
hash_extender --data "original" \
              --secret 16 \
              --append "extension" \
              --signature "known_mac_hex" \
              --format md5
```

---

## 2. MD5 COLLISION ATTACKS

### 2.1 Identical-Prefix Collision (fastcoll)

```bash
fastcoll -p prefix_file -o collision1.bin collision2.bin
# MD5(collision1.bin) == MD5(collision2.bin)
```

### 2.2 Chosen-Prefix Collision (hashclash)

```bash
./hashclash prefix1.bin prefix2.bin
# MD5(prefix1 || suffix1) == MD5(prefix2 || suffix2)
```

### 2.3 CTF MD5 Collision Tricks

```php
// PHP: md5($_GET['a']) == md5($_GET['b']) && $_GET['a'] != $_GET['b']

// Method 1: Array trick (not real collision)
?a[]=1&b[]=2  // md5(array) returns NULL, NULL == NULL

// Method 2: Real collision (fastcoll output, URL-encoded binary)
?a=<collision1_urlencoded>&b=<collision2_urlencoded>

// Method 3: 0e magic hashes (loose comparison ==)
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")   = "0e830400451993494058024219903391"
// PHP: "0e..." == "0e..." is TRUE (both evaluate to 0 as floats)
```

---

## 3. SHA-1 COLLISION

- SHAttered (2017): first practical SHA-1 collision, ~2^63 computations
- Chosen-prefix (2020): ~2^63.4, affects PGP/GnuPG key servers
- SHA-1 MUST NOT be used for digital signatures, certificate fingerprints, or deduplication
- SHA-1 is still OK for HMAC-SHA1, HKDF-SHA1, non-adversarial checksums

---

## 4. BIRTHDAY ATTACK

```
For n-bit hash: expected collisions after ~2^(n/2) hashes

Hash     Bits    Birthday bound
MD5      128     2^64
SHA-1    160     2^80
SHA-256  256     2^128

CTF: if hash is truncated to k bits, collision in ~2^(k/2) attempts
```

```python
import hashlib, os

def birthday_attack(hash_func, output_bits, max_attempts=2**28):
    mask = (1 << output_bits) - 1
    seen = {}
    for _ in range(max_attempts):
        msg = os.urandom(16)
        h = int(hash_func(msg).hexdigest(), 16) & mask
        if h in seen and seen[h] != msg:
            return seen[h], msg
        seen[h] = msg
    return None
```

---

## 5. HMAC TIMING ATTACK

```python
import requests, time

def hmac_timing_attack(url, data, hmac_len=32):
    known = ""
    for pos in range(hmac_len * 2):
        best_char = ""
        best_time = 0
        for c in "0123456789abcdef":
            candidate = known + c + "0" * (hmac_len * 2 - len(known) - 1)
            times = []
            for _ in range(50):
                start = time.perf_counter_ns()
                requests.get(url, params={**data, "mac": candidate})
                times.append(time.perf_counter_ns() - start)
            avg_time = sorted(times)[len(times)//2]
            if avg_time > best_time:
                best_time = avg_time
                best_char = c
        known += best_char
    return known

# Defense: use hmac.compare_digest(received, expected)
```

---

## 6. HASH PROOF-OF-WORK

```python
import hashlib

def solve_pow_prefix(prefix, zero_bits):
    target = '0' * (zero_bits // 4)
    i = 0
    while True:
        h = hashlib.sha256((prefix + str(i)).encode()).hexdigest()
        if h.startswith(target):
            return str(i)
        i += 1
```

---

## 7. MODERN PASSWORD HASHING

| Algorithm | Salt | Memory-Hard | Recommended |
|---|---|---|---|
| MD5 | No | No | Never |
| SHA-256 (raw) | No | No | Never for passwords |
| bcrypt | Yes | No | Yes |
| scrypt | Yes | Yes | Yes |
| Argon2 | Yes | Yes | Best choice |
| PBKDF2 | Yes | No | Acceptable |

---

## 8. DECISION TREE

```
Hash-related challenge?
├─ H(secret || message), need to extend?
│  ├─ MD5/SHA1/SHA256/SHA512? → Length extension (HashPump)
│  └─ SHA3/HMAC/BLAKE2? → Does not work
├─ Need two inputs with same hash?
│  ├─ MD5 same prefix → fastcoll (seconds)
│  ├─ MD5 different prefixes → hashclash (hours)
│  ├─ CTF PHP loose comparison → 0e magic hashes
│  └─ SHA-256+ → No practical collision
├─ Forge HMAC?
│  ├─ Timing side channel? → byte-by-byte attack
│  └─ Short/weak key? → hashcat brute force
├─ Hash truncated? → Birthday attack 2^(bits/2)
└─ Proof of work? → Python multi-processing / hashcat GPU
```

---

## 9. TOOLS

| Tool | Purpose |
|---|---|
| HashPump | Length extension attack |
| hash_extender | Length extension (multiple algorithms) |
| fastcoll | MD5 identical-prefix collision |
| hashclash | MD5 chosen-prefix collision |
| hashcat | Password/hash cracking (GPU) |
| John the Ripper | Password cracking (CPU/GPU) |
