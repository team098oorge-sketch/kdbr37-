---
name: symbolic-execution-tools
description: >-
  Symbolic execution and constraint solving playbook. Use when solving CTF
  reversing challenges, recovering keys, bypassing checks, or automating
  binary analysis with angr, Z3, or Unicorn Engine.
---

# SKILL: Symbolic Execution Tools — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert symbolic execution using angr, Z3, and Unicorn Engine. Covers CTF challenge automation, constraint solving patterns, function hooking, SimProcedure replacement, and emulation-based unpacking. See [ANGR_COOKBOOK.md](./ANGR_COOKBOOK.md) for 15+ ready-to-use script patterns.

## 0. RELATED ROUTING

- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) for anti-debug bypass
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) for custom VM challenges

### Tool Selection

| Scenario | Best Tool |
|---|---|
| Pure math / equation system | Z3 |
| Binary with control flow | angr |
| Emulate specific code region | Unicorn |
| Complex binary + custom VM | angr + Unicorn |
| Kernel / firmware code | Qiling |

---

## 1. ANGR — CORE CONCEPTS

```python
import angr, claripy

proj = angr.Project('./challenge', auto_load_libs=False)

# State types
state = proj.factory.entry_state()
state = proj.factory.blank_state(addr=0x401000)
state = proj.factory.full_init_state(args=['./challenge', arg1_sym])

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    solution = simgr.found[0].solver.eval(symbolic_input, cast_to=bytes)
    print(f"Solution: {solution}")
```

### Symbolic Variables

```python
sym_input = claripy.BVS("input", 64)     # 64-bit symbolic
sym_buf = claripy.BVS("buffer", 8 * 32)  # 32-byte buffer
concrete = claripy.BVV(0x41, 8)          # concrete value

# Constrain to printable ASCII
for i in range(32):
    byte = sym_buf.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

# Symbolic stdin
sym_stdin = claripy.BVS("stdin", 8 * 32)
state = proj.factory.entry_state(stdin=sym_stdin)
```

### Hooking Functions

```python
# Hook by address
@proj.hook(0x401100, length=5)
def skip_check(state):
    state.regs.eax = 1  # force success

# SimProcedure: replace library function
class MyStrcmp(angr.SimProcedure):
    def run(self, s1, s2):
        return claripy.If(
            self.state.memory.load(s1, 32) == self.state.memory.load(s2, 32),
            claripy.BVV(0, 32), claripy.BVV(1, 32)
        )
proj.hook_symbol('strcmp', MyStrcmp())

# Hook common libc functions
proj.hook_symbol('printf', angr.SIM_PROCEDURES['libc']['printf']())
proj.hook_symbol('scanf', angr.SIM_PROCEDURES['libc']['scanf']())
```

---

## 2. Z3 CONSTRAINT SOLVING

```python
from z3 import *

# Core API
x = BitVec('x', 32)
y = Int('y')
s = Solver()
s.add(x + y == 42, x > 0, y > 0)
if s.check() == sat:
    m = s.model()
    print(f"x = {m[x]}, y = {m[y]}")

# CTF: serial key validation
key = [BitVec(f'k{i}', 8) for i in range(16)]
s = Solver()
for k in key:
    s.add(k >= 0x30, k <= 0x7a)

# XOR key recovery
key_byte = BitVec('key', 8)
for p, c in zip(plaintext, ciphertext):
    s.add(p ^ key_byte == c)

# System of equations
a, b, c = BitVecs('a b c', 32)
s.add(3*a + 5*b + 7*c == 0x12345678)
s.add(a ^ b ^ c == 0xCAFEBABE)

# Optimization
opt = Optimize()
opt.minimize(x)
opt.check()
```

---

## 3. UNICORN ENGINE — CODE EMULATION

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)

CODE_ADDR = 0x400000
STACK_ADDR = 0x7fff0000
STACK_SIZE = 0x10000

mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.mem_write(CODE_ADDR, code_bytes)
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x1000)

# Hook memory/code
def hook_code(uc, address, size, user_data):
    print(f"{address:#x}")
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

mu.emu_start(CODE_ADDR, CODE_ADDR + len(code_bytes))
result = mu.reg_read(UC_X86_REG_RAX)
```

Use cases: unpack shellcode, decrypt strings, brute-force short keys, analyze obfuscated functions.

---

## 4. ANGR EXPLORATION STRATEGIES

```python
# find/avoid by output
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1)
)

# Managing path explosion
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.use_technique(angr.exploration_techniques.Veritesting())
state.options.add(angr.options.LAZY_SOLVES)
# Use Unicorn for concrete regions:
state = proj.factory.entry_state(add_options={angr.options.UNICORN})
```

---

## 5. DECISION TREE

```
Reversing challenge?
├── Pure math / equations → Z3 (BitVec, Solver, Optimize)
├── Binary with clear success/fail → angr explore
│   ├── stdin input → symbolic stdin
│   ├── argv input → full_init_state
│   ├── path explosion → constraints + avoid + hook loops
│   └── complex lib calls → SimProcedure
├── Specific function to emulate → Unicorn
├── Firmware / exotic arch → Qiling
├── VM protection → angr (handler) + Z3 (bytecode)
└── Nothing working → Unicorn concrete + Z3 constraints combined
```

---

## 6. COMMON PITFALLS

| Problem | Fix |
|---|---|
| angr hangs | Path explosion: add `avoid=` for loop-back edges, hook loops |
| Z3 returns `unknown` | Simplify, split, `set_param("timeout", 5000)` |
| Unicorn crashes on syscall | Hook syscall interrupt, handle or skip |
| angr wrong result | Verify initial memory layout matches binary |
| angr can't load binary | Use `auto_load_libs=False` + hook needed symbols |

```bash
pip install angr z3-solver unicorn capstone keystone-engine
```
