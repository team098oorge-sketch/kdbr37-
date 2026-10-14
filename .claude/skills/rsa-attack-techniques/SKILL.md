---
name: rsa-attack-techniques
description: >-
  RSA attack playbook for CTF and real-world cryptanalysis. Use when given
  RSA parameters (n, e, c) and need to recover plaintext by exploiting
  weak keys, small exponents, shared factors, or padding oracles.
---

# SKILL: RSA Attack Techniques — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert RSA attack techniques for CTF and authorized security assessments. Covers factorization attacks, small exponent exploits, lattice-based approaches (Wiener/Boneh-Durfee/Coppersmith), broadcast attacks, common modulus, padding oracles, and fault attacks.

## 0. RELATED ROUTING

- [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md) for Coppersmith/Boneh-Durfee lattice theory
- [hash-attack-techniques](../hash-attack-techniques/SKILL.md) for RSA signature forgery via hash weaknesses
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) when RSA protects a symmetric key
- [RSA_ATTACK_CATALOG.md](./RSA_ATTACK_CATALOG.md) for detailed SageMath implementations

### Quick attack selection

| Given / Observable | Attack | Tool |
|---|---|---|
| Small n (< 512 bits) | Direct factorization | factordb, yafu, msieve |
| e = 3, small message | Cube root | gmpy2.iroot |
| Multiple (n, c) same small e | Hastad broadcast | CRT + iroot |
| Very large e or very small d | Wiener / Boneh-Durfee | SageMath, RsaCtfTool |
| Partial p knowledge | Coppersmith small roots | SageMath |
| Same n, different e | Common modulus | Extended GCD |
| Multiple n values | Batch GCD (shared factor) | Python/SageMath |
| Padding error oracle | Bleichenbacher | Custom script |
| LSB parity oracle | LSB oracle attack | Custom script |
| Fault in CRT computation | RSA-CRT fault | Single faulty signature |

---

## 1. FACTORIZATION ATTACKS

### 1.1 Direct Factorization (Small n)

```python
from sympy import factorint
n = 0x...  # small modulus
factors = factorint(n)
p, q = list(factors.keys())
```

### 1.2 Fermat's Factorization (p ≈ q)

```python
from gmpy2 import isqrt, is_square

def fermat_factor(n):
    a = isqrt(n) + 1
    while True:
        b2 = a * a - n
        if is_square(b2):
            b = isqrt(b2)
            return (a + b, a - b)
        a += 1
```

### 1.3 Pollard's p-1 (p-1 is B-smooth)

```python
from gmpy2 import gcd

def pollard_p1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
    d = gcd(a - 1, n)
    if 1 < d < n:
        return d
    return None
```

### 1.4 Batch GCD (Multiple n share a factor)

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    product = reduce(lambda a, b: a * b, moduli)
    results = {}
    for i, n in enumerate(moduli):
        remainder = product // n
        g = gcd(n, remainder)
        if g != 1 and g != n:
            results[i] = (g, n // g)
    return results
```

---

## 2. SMALL EXPONENT ATTACKS

### 2.1 Cube Root Attack (e = 3, small m)

```python
from gmpy2 import iroot
c = 0x...
e = 3
m, exact = iroot(c, e)
if exact:
    print(bytes.fromhex(hex(m)[2:]))
```

### 2.2 Hastad Broadcast Attack

Same message encrypted with same small e under different moduli.

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot

n_list = [n1, n2, n3]  # e=3
c_list = [c1, c2, c3]
r, M = crt(n_list, c_list)
m, exact = iroot(r, 3)
assert exact
```

### 2.3 Franklin-Reiter Related Message Attack

Two messages: m2 = a*m1 + b. Same n and e.

```python
# SageMath
def franklin_reiter(n, e, c1, c2, a, b):
    R.<x> = PolynomialRing(Zmod(n))
    f1 = x^e - c1
    f2 = (a*x + b)^e - c2
    return Integer(n - gcd(f1, f2).coefficients()[0])
```

---

## 3. LARGE e / SMALL d ATTACKS

### 3.1 Wiener's Attack (d < n^(1/4) / 3)

Continued fraction expansion of e/n reveals d.

```python
def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    convergents = get_convergents(cf)
    for k, d in convergents:
        if k == 0:
            continue
        phi_candidate = (e * d - 1) // k
        s = n - phi_candidate + 1
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            from gmpy2 import is_square
            if is_square(discriminant):
                return d
    return None

def continued_fraction(a, b):
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf

def get_convergents(cf):
    convergents = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        convergents.append((h_curr, k_curr))
    return convergents
```

### 3.2 Boneh-Durfee Attack (d < n^0.292)

Lattice-based. Use SageMath implementation. See [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md).

---

## 4. COPPERSMITH'S METHOD

### 4.1 Stereotyped Message

```python
# SageMath
n = ...; e = 3; c = ...
known_prefix = b"flag{" + b"\x00" * 27
known_int = int.from_bytes(known_prefix, 'big')

R.<x> = PolynomialRing(Zmod(n))
f = (known_int + x)^e - c
roots = f.small_roots(X=2^(27*8), beta=1.0)
if roots:
    m = known_int + int(roots[0])
    print(bytes.fromhex(hex(m)[2:]))
```

### 4.2 Partial Key Exposure

```python
# SageMath — known MSB of p
p_msb = ...
R.<x> = PolynomialRing(Zmod(n))
f = p_msb + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5)
if roots:
    p = p_msb + int(roots[0])
    q = n // p
```

---

## 5. COMMON MODULUS ATTACK

Same message, same n, different e1 and e2 where gcd(e1, e2) = 1.

```python
from gmpy2 import gcd, invert

def common_modulus(n, e1, e2, c1, c2):
    assert gcd(e1, e2) == 1
    _, s1, s2 = extended_gcd(e1, e2)
    if s1 < 0:
        c1 = invert(c1, n); s1 = -s1
    if s2 < 0:
        c2 = invert(c2, n); s2 = -s2
    return (pow(c1, s1, n) * pow(c2, s2, n)) % n

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x
```

---

## 6. ORACLE ATTACKS

### 6.1 LSB Oracle (Parity Oracle)

```python
def lsb_oracle_attack(n, e, c, oracle_func):
    from fractions import Fraction
    lo, hi = Fraction(0), Fraction(n)
    for _ in range(n.bit_length()):
        c = (c * pow(2, e, n)) % n  # multiply plaintext by 2
        if oracle_func(c) == 0:
            hi = (lo + hi) / 2
        else:
            lo = (lo + hi) / 2
    return int(hi)
```

### 6.2 Bleichenbacher (PKCS#1 v1.5)

Padding validity oracle (valid/invalid PKCS#1 v1.5) → O(2^16) queries per byte. Target: TLS implementations leaking different errors for valid/invalid padding.

### 6.3 Manger's Attack (PKCS#1 OAEP)

Oracle distinguishes whether first byte after unpadding is 0x00.

---

## 7. RSA-CRT FAULT ATTACK

```python
from math import gcd

def rsa_crt_fault(n, e, correct_sig, faulty_sig, msg):
    diff = pow(correct_sig, e, n) - pow(faulty_sig, e, n)
    p = gcd(diff % n, n)
    if 1 < p < n:
        return p, n // p
    return None

def rsa_crt_fault_simple(n, e, faulty_sig, msg):
    p = gcd(pow(faulty_sig, e, n) - msg, n)
    if 1 < p < n:
        return p, n // p
    return None
```

---

## 8. DECISION TREE

```
RSA challenge — what do you have?
│
├─ Small n (< 512 bits) → factordb → yafu → msieve
├─ Multiple n → batch GCD (shared factors?)
├─ Know e?
│  ├─ e = 3, single ciphertext, small message → cube root
│  ├─ e = 3, multiple ciphertexts, different n → Hastad broadcast
│  ├─ e = 3, two related messages → Franklin-Reiter
│  ├─ e = 3, partial plaintext known → Coppersmith
│  ├─ e very large → d is likely small → Wiener → Boneh-Durfee
│  └─ Same n, two different e → common modulus
├─ Partial factorization?
│  ├─ Some bits of p known → Coppersmith partial key
│  ├─ p-1 is B-smooth → Pollard p-1
│  └─ p ≈ q → Fermat factorization
├─ Oracle available?
│  ├─ Parity (LSB) oracle → LSB oracle attack
│  ├─ PKCS#1 v1.5 padding oracle → Bleichenbacher
│  └─ OAEP oracle → Manger's attack
├─ Faulty signature? → RSA-CRT fault → factor n
└─ None of above?
   ├─ Check factordb for known factorization
   ├─ Pollard rho for medium-size n
   └─ Look for weak PRNG in key generation
```

---

## 9. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| **RsaCtfTool** | Automated RSA attack suite | `python3 RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc` |
| **SageMath** | Coppersmith, lattice attacks | - |
| **factordb.com** | Online factor database | Check if n is already factored |
| **yafu** | SIQS/GNFS factorization | `yafu "factor(n)"` |
| **gmpy2** | Fast Python integer library | `iroot`, `invert`, `gcd` |

```bash
# RsaCtfTool quick commands
python3 RsaCtfTool.py --publickey pub.pem -n --private
python3 RsaCtfTool.py -n $N -e $E --uncipher $C
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc --attack all
```

```python
# Decrypt after factoring
from Crypto.PublicKey import RSA
from gmpy2 import invert

p, q = ...
n = p * q; e = 65537
phi = (p - 1) * (q - 1)
d = int(invert(e, phi))
c = ...  # ciphertext as integer
m = pow(c, d, n)
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
```
