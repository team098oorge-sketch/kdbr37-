---
name: lattice-crypto-attacks
description: >-
  Lattice-based cryptanalysis playbook. Use when attacking RSA via Coppersmith
  small roots, recovering DSA/ECDSA nonces from bias, solving knapsack
  problems, or applying LLL/BKZ reduction to cryptographic constructions.
---

# SKILL: Lattice-Based Cryptanalysis — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert lattice techniques for CTF and cryptanalysis. Covers LLL/BKZ reduction, Coppersmith's method, Hidden Number Problem for DSA/ECDSA nonce recovery, knapsack attacks, and NTRU analysis.

## 0. RELATED ROUTING

- [rsa-attack-techniques](../rsa-attack-techniques/SKILL.md) for RSA-specific attacks using lattice methods
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) for LCG state recovery via lattice

### Quick application guide

| Problem Type | Lattice Technique | Key Parameter |
|---|---|---|
| RSA small roots | Coppersmith (LLL on polynomial lattice) | Root bound X < N^(1/e) |
| RSA small d | Boneh-Durfee (multivariate Coppersmith) | d < N^0.292 |
| DSA/ECDSA nonce bias | Hidden Number Problem -> CVP | Bias bits known |
| Knapsack cipher | Low-density lattice attack | Density < 0.9408 |
| LCG truncated output | CVP on recurrence lattice | Unknown bits per output |
| Subset sum | LLL reduction on knapsack lattice | Element size vs count |
| NTRU key recovery | Lattice reduction on NTRU lattice | Dimension and key size |

---

## 1. LATTICE FUNDAMENTALS

A **lattice** L is the set of all integer linear combinations of basis vectors.

**Key problems**:
- **SVP** (Shortest Vector Problem): Find shortest non-zero vector in L
- **CVP** (Closest Vector Problem): Given target t, find v in L closest to t
- SVP is NP-hard in general, but LLL finds an approximately short vector in polynomial time

---

## 2. LLL ALGORITHM

Takes a lattice basis B and produces a **reduced basis** B' with nearly orthogonal vectors. First vector is approximately short (within 2^((n-1)/2) of SVP). Runs in polynomial time.

```python
# SageMath
M = matrix(ZZ, [
    [1, 0, 0, large_value_1],
    [0, 1, 0, large_value_2],
    [0, 0, 1, large_value_3],
    [0, 0, 0, modulus],
])
L = M.LLL()
short_vector = L[0]  # first row is typically shortest
```

```python
# fpylll
from fpylll import IntegerMatrix, LLL
A = IntegerMatrix(n, n)
LLL.reduction(A)
```

---

## 3. BKZ (BLOCK KORKINE-ZOLOTAREV)

| Property | LLL | BKZ-beta |
|---|---|---|
| Quality | 2^((n-1)/2) approximation | 2^(n/(beta-1)) approximation |
| Speed | Polynomial | Exponential in beta |

```python
# SageMath
L = M.BKZ(block_size=20)
```

Rule of thumb: start with LLL, increase to BKZ if needed. Block size 20-40 usually sufficient for CTF.

---

## 4. COPPERSMITH'S METHOD

### 4.1 Univariate Case

Given f(x) = 0 (mod N) with small root |x0| < X, find x0.
**Bound**: X < N^(1/d) where d = degree of f.

```python
# SageMath
N = ...
R.<x> = PolynomialRing(Zmod(N))
f = x^3 + a*x^2 + b*x + c
roots = f.small_roots(X=2^100, beta=1.0, epsilon=1/30)
```

**Parameters**:
- `X`: upper bound on the root
- `beta`: N = p^beta (beta=1.0 for root of N; beta=0.5 for root mod unknown factor p ~ sqrt(N))
- `epsilon`: smaller = better results but slower

### 4.2 Stereotyped Message Attack (RSA)

```python
n, e, c = ...
known_msb = ...
R.<x> = PolynomialRing(Zmod(n))
f = (known_msb + x)^e - c
X = 2^(unknown_bit_count)
roots = f.small_roots(X=X, beta=1.0)
if roots:
    m = known_msb + int(roots[0])
```

### 4.3 Partial Key Exposure (Factor p)

```python
n = ...
p_known = ...
R.<x> = PolynomialRing(Zmod(n))
f = p_known + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5)
if roots:
    p = p_known + int(roots[0])
    q = n // p
```

---

## 5. HIDDEN NUMBER PROBLEM (HNP) — DSA/ECDSA NONCE RECOVERY

### 5.1 Problem Statement

Given signatures (ri, si) where nonces ki have known bias (leaked MSBs/LSBs):

DSA: `s = k^-1(H(m) + xr) mod q`
If partial bits of k known -> reduces to CVP on a lattice.

### 5.2 Attack Setup

```python
# SageMath
n = len(signatures)
B = 2^(q.nbits() - known_bits)
M = matrix(QQ, n + 2, n + 2)

for i in range(n):
    r_i, s_i, h_i, a_i = signatures[i]
    t_i = Integer(inverse_mod(s_i, q) * r_i % q)
    u_i = Integer(inverse_mod(s_i, q) * h_i % q)
    M[i, i] = q
    M[n, i] = t_i
    M[n+1, i] = u_i - a_i

M[n, n] = B / q
M[n+1, n+1] = B
L = M.LLL()
# Search reduced rows for private key x
```

### 5.3 Nonce Bias Sources

| Source | Leaked Bits | Required Signatures |
|---|---|---|
| MSB bias (always 0) | 1 bit | ~100 signatures |
| k generated with wrong length | Variable | ~50 signatures |
| Timing side channel | 1-4 bits | 20-100 signatures |
| Reused nonce (k1 = k2) | All | 2 signatures |

For **reused nonce**:
```python
def ecdsa_reused_nonce(r, s1, s2, h1, h2, q):
    k = ((h1 - h2) * inverse_mod(s1 - s2, q)) % q
    x = ((s1 * k - h1) * inverse_mod(r, q)) % q
    return x, k
```

---

## 6. KNAPSACK / SUBSET SUM ATTACKS

**Density** d = n / max(log2 ai). If d < 0.9408, lattice attack works.

```python
# SageMath - CJLOSS embedding
n = len(weights)
N = ceil(sqrt(n) / 2)
M2 = matrix(ZZ, n + 1, n + 2)
for i in range(n):
    M2[i, i] = 1
    M2[i, n + 1] = N * weights[i]
M2[n, n] = 1
M2[n, n + 1] = N * (-target)
L = M2.LLL()

for row in L:
    if all(v in (0, 1) for v in row[:n]):
        solution = list(row[:n])
        if sum(solution[i] * weights[i] for i in range(n)) == target:
            return solution
```

---

## 7. NTRU CRYPTANALYSIS

```python
# SageMath - NTRU lattice for key recovery
# NTRU lattice:
# | qI  0 |
# | H   I |
def ntru_lattice_attack(h, q, N):
    H = matrix(ZZ, N, N)
    for i in range(N):
        for j in range(N):
            H[i, j] = h[(j - i) % N]
    M = block_matrix([[q * identity_matrix(N), zero_matrix(N)],
                      [H, identity_matrix(N)]])
    L = M.LLL()
    for row in L:
        f = vector(row[:N])
        g = vector(row[N:])
        if f.norm() < q and g.norm() < q:
            return f, g
    return None
```

---

## 8. CONSTRUCTING ATTACK LATTICES

```
1. Express problem as: "Find small x such that f(x) = 0 (mod N)"
   or "Find x close to target t in lattice L"

2. Choose lattice type:
   - Polynomial lattice -> Coppersmith-style
   - Modular lattice -> HNP-style CVP
   - Knapsack lattice -> subset sum / CJLOSS

3. Set scaling factors: balance rows so short vector has equal entries
   Common: multiply by N/X where X is root bound

4. Apply reduction: LLL first, then BKZ (block size 20, 30, 40)

5. Extract solution from reduced basis rows
```

### Embedding Technique (CVP -> SVP via Kannan's embedding)

```python
def cvp_to_svp(basis_matrix, target, scale=1):
    n = basis_matrix.nrows()
    m = basis_matrix.ncols()
    M = matrix(ZZ, n + 1, m + 1)
    for i in range(n):
        for j in range(m):
            M[i, j] = basis_matrix[i, j]
    for j in range(m):
        M[n, j] = target[j]
    M[n, m] = scale
    L = M.LLL()
    for row in L:
        if abs(row[m]) == scale:
            return vector(target) - vector(row[:m]) * (row[m] // abs(row[m]))
    return None
```

---

## 9. DECISION TREE

```
Lattice approach needed?
|
|-- RSA-related?
|   |-- Small unknown part of message -> Coppersmith univariate
|   |-- Partial factor knowledge -> Coppersmith mod p (beta=0.5)
|   |-- Small private exponent d -> Boneh-Durfee (d < N^0.292)
|   +-- Multiple related equations -> multivariate Coppersmith
|
|-- DSA/ECDSA-related?
|   |-- Reused nonce -> direct algebraic recovery (no lattice)
|   +-- Partial nonce leakage -> HNP -> CVP lattice
|
|-- Knapsack / subset sum?
|   |-- Low density (d < 0.9408) -> CJLOSS lattice attack
|   +-- Super-increasing -> greedy algorithm
|
|-- LCG / PRNG?
|   |-- Full outputs -> algebraic recovery
|   +-- Truncated outputs -> CVP on recurrence lattice
|
+-- Custom problem?
    |-- Find small root mod N -> Coppersmith
    |-- Find lattice point near target -> CVP
    +-- Find short vector -> SVP / LLL
```

---

## 10. COMMON PITFALLS

| Pitfall | Symptom | Fix |
|---|---|---|
| Root bound too large | `small_roots()` returns empty | Reduce X, increase epsilon |
| Wrong scaling | LLL finds irrelevant short vector | Scale columns for balanced entries |
| Wrong beta | Coppersmith doesn't find factor | beta=0.5 for half-size factor |
| Too few signatures (HNP) | Lattice attack fails | Collect more signatures with nonce bias |
| BKZ block size too small | Solution not short enough | Increase block size (25, 30, 40) |
