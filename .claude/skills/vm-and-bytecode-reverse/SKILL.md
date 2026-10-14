---
name: vm-and-bytecode-reverse
description: >-
  VM and bytecode reverse engineering playbook. Use when reversing custom virtual machines, bytecode interpreters, esoteric ISAs, CTF VM challenges, or obfuscated code using VMProtect/Themida/Tigress. Covers dispatcher identification, opcode mapping, custom disassembler writing, maze solvers, and Ghidra Sleigh.
---

# SKILL: VM & Bytecode Reverse Engineering

## 0. RELATED ROUTING

- [reverse-engineering-binary](../reverse-engineering-binary/SKILL.md) for standard x86/ARM binary analysis before recognizing a VM layer
- [symbolic-execution-angr](../symbolic-execution-angr/SKILL.md) for angr-based VM opcode solving
- [obfuscation-deobfuscation](../obfuscation-deobfuscation/SKILL.md) when obfuscation wraps the VM

---

## 1. VM IDENTIFICATION

### Dispatcher Patterns

```
switch(opcode) { ... }          // switch-based dispatcher
jmp_table[opcode]()             // function-pointer table
if (op==X) ... else if (op==Y) // if-chain dispatcher
```

### Signals

- Large switch/jump table with many cases
- PC/IP register incremented in a loop
- Fetch → decode → execute pattern
- Custom stack pointer (not RSP/ESP)
- Opcode array + operand array in .data

---

## 2. ANALYSIS METHODOLOGY

1. **Find the fetch loop**: locate where PC is read and incremented
2. **Map the dispatcher**: identify switch/table/chain structure
3. **Enumerate opcodes**: list each case label and its handler
4. **Name registers**: identify VM registers (often array indices or struct fields)
5. **Write disassembler**: translate bytecode → readable pseudocode

---

## 3. CUSTOM DISASSEMBLER TEMPLATE

```python
import sys

OPCODES = {
    0x00: ('NOP',  0),
    0x01: ('PUSH', 1),   # (mnemonic, operand_bytes)
    0x02: ('POP',  0),
    0x03: ('ADD',  0),
    0x04: ('SUB',  0),
    0x05: ('MUL',  0),
    0x06: ('JMP',  2),
    0x07: ('JZ',   2),
    0x08: ('LOAD', 1),
    0x09: ('STORE',1),
    0x0A: ('CMP',  0),
    0x0B: ('HALT', 0),
    # Add more from your analysis
}

def disassemble(bytecode):
    pc = 0
    while pc < len(bytecode):
        op = bytecode[pc]
        if op not in OPCODES:
            print(f"{pc:04x}: UNKNOWN({op:#04x})")
            pc += 1
            continue
        mnem, operand_bytes = OPCODES[op]
        operands = bytecode[pc+1:pc+1+operand_bytes]
        operand_str = ' '.join(f"{b:#04x}" for b in operands)
        print(f"{pc:04x}: {mnem:<8} {operand_str}")
        pc += 1 + operand_bytes

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        disassemble(f.read())
```

---

## 4. STACK-BASED VM OPCODE TABLE

| Opcode | Name    | Effect                          |
|--------|---------|---------------------------------|
| PUSH n | Push    | stack.push(n)                   |
| POP    | Pop     | stack.pop()                     |
| ADD    | Add     | b=pop(); a=pop(); push(a+b)     |
| SUB    | Sub     | b=pop(); a=pop(); push(a-b)     |
| MUL    | Mul     | b=pop(); a=pop(); push(a*b)     |
| DIV    | Div     | b=pop(); a=pop(); push(a//b)    |
| DUP    | Dup     | push(stack[-1])                 |
| SWAP   | Swap    | a,b=pop(),pop(); push(a); push(b)|
| LOAD a | Load    | push(mem[a])                    |
| STORE a| Store   | mem[a]=pop()                    |
| JMP a  | Jump    | pc=a                            |
| JZ a   | Jump-0  | if pop()==0: pc=a               |
| CALL a | Call    | push(pc+1); pc=a                |
| RET    | Return  | pc=pop()                        |
| HALT   | Halt    | exit                            |

---

## 5. REGISTER-BASED VM OPCODE TABLE

| Opcode          | Effect                    |
|-----------------|---------------------------|
| MOV  Rd, Rs     | Rd = Rs                   |
| MOV  Rd, #imm   | Rd = imm                  |
| ADD  Rd, Rs, Rt | Rd = Rs + Rt              |
| CMP  Rs, Rt     | flags = Rs - Rt           |
| JE   addr       | if ZF: pc = addr          |
| JNE  addr       | if !ZF: pc = addr         |
| LOAD Rd, [Rs]   | Rd = mem[Rs]              |
| STORE [Rd], Rs  | mem[Rd] = Rs              |

---

## 6. MAZE CHALLENGE SOLVER

```python
from collections import deque

MAZE = [
    "#########",
    "#S......#",
    "#.###.#.#",
    "#.#...#.#",
    "#...###.#",
    "#######E#",
]

# Direction encoding (from VM opcode analysis)
DIRS = {
    0: (-1, 0),  # UP    (opcode 0x00 or 'U')
    1: (1,  0),  # DOWN  (opcode 0x01 or 'D')
    2: (0, -1),  # LEFT  (opcode 0x02 or 'L')
    3: (0,  1),  # RIGHT (opcode 0x03 or 'R')
}
DIR_NAMES = {0:'U', 1:'D', 2:'L', 3:'R'}

def solve_maze(maze):
    rows, cols = len(maze), len(maze[0])
    start = end = None
    for r in range(rows):
        for c in range(cols):
            if maze[r][c] == 'S': start = (r, c)
            if maze[r][c] == 'E': end   = (r, c)
    
    queue = deque([(start, [])])
    visited = {start}
    while queue:
        pos, path = queue.popleft()
        if pos == end:
            return path
        for d, (dr, dc) in DIRS.items():
            nr, nc = pos[0]+dr, pos[1]+dc
            if 0<=nr<rows and 0<=nc<cols and (nr,nc) not in visited and maze[nr][nc]!='#':
                visited.add((nr, nc))
                queue.append(((nr, nc), path + [d]))
    return None

path = solve_maze(MAZE)
print('Path:', ''.join(DIR_NAMES[d] for d in path))
print('Opcodes:', path)  # submit these opcode values to the VM
```

---

## 7. PROTECTION DIFFICULTY TABLE

| Protection    | Difficulty | Key Technique                        |
|---------------|------------|--------------------------------------|
| VMProtect     | High       | Identify VM entry, trace handlers, use Triton/miasm |
| Themida       | High       | Dump + fix IAT, OEP hunting          |
| Tigress        | Medium     | Source-level; trace with PIN/Unicorn |
| Custom CTF VM | Low-Med    | Manual opcode mapping + disassembler |

---

## 8. TOOLS

| Tool    | Use                                      |
|---------|------------------------------------------|
| IDA Pro | Graph view for dispatcher, xref analysis |
| Ghidra  | Free; Sleigh for custom ISA              |
| angr    | Symbolic execution through VM            |
| PIN     | Dynamic tracing of VM execution          |
| Unicorn | Emulate VM handler code                  |
| miasm   | IR lifting + disassembler framework      |

### Ghidra Sleigh Example (custom 8-bit ISA)

```sleigh
:PUSH imm8  is op=0x01; imm8 { SP = SP - 1; *:1 SP = imm8; }
:ADD        is op=0x03         { tmp:1 = *:1 SP; SP=SP+1; *:1 SP = *:1 SP + tmp; }
:HALT       is op=0x0B         { goto inst_next; }  # model halt
```

---

## 9. CTF SOLVING WORKFLOW

1. Run binary → observe: reads bytecode file, prints flag based on input
2. Identify VM loop in IDA/Ghidra
3. Map all opcodes (static analysis or `strace`/`ltrace` hints)
4. Write Python disassembler → disassemble the bytecode
5. Read disassembly → understand flag check logic
6. Solve constraint (angr, z3, BFS for maze) → get input
7. Submit input to binary → confirm flag
8. Write clean writeup with disassembler + solver

---

## 10. DECISION TREE

```
Binary to reverse
|
+-- Obvious VM dispatch loop?
|   +-- switch(opcode) / jmp table → map opcodes (§1)
|   +-- Write disassembler (§3)
|   +-- Disassemble bytecode → read logic (§9)
|
+-- Commercial protector?
|   +-- VMProtect → Triton/miasm trace
|   +-- Themida → dump + IAT fix
|   +-- Check §7 difficulty table
|
+-- Maze/path challenge?
|   +-- BFS solver (§6)
|   +-- Map opcodes to directions (§6 direction encoding)
|
+-- Need symbolic execution?
    +-- angr: claripy constraints over VM state
    +-- Unicorn: emulate with hooks per opcode
```
