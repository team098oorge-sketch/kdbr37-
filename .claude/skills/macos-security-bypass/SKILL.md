---
name: macos-security-bypass
description: >-
  macOS security bypass playbook. Use when targeting macOS endpoints and need to bypass TCC, Gatekeeper, SIP, sandbox, code signing, or entitlement-based protections during authorized red team or pentest engagements.
---

# SKILL: macOS Security Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert macOS security bypass techniques. Covers TCC bypass, Gatekeeper evasion, SIP restrictions, sandbox escape, and entitlement abuse. Base models miss version-specific bypass nuances and protection interaction effects.

## 0. RELATED ROUTING

- [macos-process-injection](../macos-process-injection/SKILL.md) for dylib injection, XPC exploitation, or Electron abuse
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) for Unix-layer privesc (SUID, cron, writable paths)
- [linux-security-bypass](../linux-security-bypass/SKILL.md) for shared Unix security bypass concepts

### Advanced Reference

Also load [TCC_BYPASS_MATRIX.md](./TCC_BYPASS_MATRIX.md) for per-macOS-version TCC bypass mapping and MDM/PPPC abuse patterns.

---

## 1. TCC (TRANSPARENCY, CONSENT, CONTROL) OVERVIEW

### 1.1 TCC Database Locations

| Database | Path | Controls | Protection |
|---|---|---|---|
| User-level | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user consent decisions | SIP-protected since Catalina |
| System-level | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide consent decisions | SIP-protected |
| MDM-managed | Via configuration profiles | Push PPPC | Device management |

```sql
-- Query TCC database (requires FDA or SIP off)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access;"
```

### 1.2 TCC Bypass Categories

| Category | Mechanism | Typical Prerequisite |
|---|---|---|
| FDA app exploitation | Piggyback on apps already granted Full Disk Access | Write access to FDA app's bundle or plugin dir |
| Direct DB modification | Edit TCC.db to grant consent | SIP disabled or FDA |
| Inherited permissions | Child process inherits parent's TCC grants | Code execution in context of FDA-granted app |
| Automation abuse | Apple Events / osascript to control TCC-granted app | Automation permission |
| SQL injection in TCC | Malformed bundle IDs triggering SQL injection | CVE-2023-32364 and similar |

### 1.3 Known TCC Bypass Patterns

**Terminal / iTerm FDA inheritance**: Terminal.app granted FDA -> any command run inherits FDA.

```bash
# If Terminal has FDA, this reads protected files directly
cat ~/Library/Mail/V*/MailData/Envelope\ Index
cat ~/Library/Messages/chat.db
```

**Finder automation**: Automate Finder (lower permission bar) to access files in protected locations.

```applescript
tell application "Finder"
  set f to POSIX file "/Users/target/Library/Mail/V9/MailData/Envelope Index"
  duplicate f to desktop
end tell
```

**MDM profile abuse**: PPPC profiles can pre-approve TCC permissions without user consent.

---

## 2. GATEKEEPER BYPASS

### 2.1 Quarantine Attribute Removal

```bash
# Check quarantine attribute
xattr -l /path/to/app

# Remove quarantine (requires write access)
xattr -d com.apple.quarantine /path/to/app
# Recursive for app bundles
xattr -rd com.apple.quarantine /path/to/MyApp.app
```

### 2.2 Bypass Techniques

| Technique | How It Works | macOS Version |
|---|---|---|
| `xattr -d` removal | Remove quarantine before execution | All (requires local access) |
| Unsigned code in signed bundle | Notarized app bundles with unsigned nested helpers | Pre-Ventura (CVE-2022-42821) |
| BOM (Bill of Materials) bypass | Crafted BOM in pkg skips quarantine for extracted files | CVE-2022-22616 |
| Archive tools that strip quarantine | Some unarchiver apps don't propagate quarantine | Varies by tool |

### 2.3 Gatekeeper Check Flow

```
App launched
+-- com.apple.quarantine attribute present?
|   +-- No -> execute (no Gatekeeper check)
|   +-- Yes ->
+-- Code signature valid?
|   +-- No -> block
|   +-- Yes ->
+-- Notarized?
|   +-- No -> block (Catalina+)
|   +-- Yes -> execute
+-- User override: right-click -> Open -> confirm
    +-- Bypasses Gatekeeper once for this app
```

---

## 3. SIP (SYSTEM INTEGRITY PROTECTION)

### 3.1 SIP-Protected Locations

```
/System/
/usr/ (except /usr/local/)
/bin/
/sbin/
/Applications/ (pre-installed Apple apps)
```

### 3.2 SIP Status & Configuration

```bash
csrutil status              # Check SIP status
csrutil disable             # Recovery Mode only
```

### 3.3 Entitlements That Bypass SIP

| Entitlement | Effect |
|---|---|
| `com.apple.rootless.install` | Write to SIP-protected paths |
| `com.apple.rootless.install.heritable` | Child processes inherit SIP bypass |
| `com.apple.security.cs.allow-unsigned-executable-memory` | JIT/unsigned code in memory |
| `com.apple.private.security.clear-library-validation` | Load unsigned libraries |

### 3.4 Historical SIP Bypasses

| CVE | macOS | Technique |
|---|---|---|
| CVE-2021-30892 (Shrootless) | Monterey pre-12.0.1 | `system_installd` + post-install script in signed pkg |
| CVE-2022-22583 | Monterey pre-12.2 | `packagekit` + mount point manipulation |
| CVE-2022-46689 (MacDirtyCow) | Ventura pre-13.1 | COW race condition, overwrite SIP files |
| CVE-2023-32369 (Migraine) | Ventura pre-13.4 | Migration Assistant TCC/SIP bypass |
| CVE-2024-44243 | Sequoia pre-15.2 | StorageKit daemon exploitation |

---

## 4. SANDBOX ESCAPE

### 4.1 Office Sandbox Escape Patterns

| Vector | Description |
|---|---|
| Open/Save dialog abuse | User grants file access via dialog -> macro reads/writes beyond sandbox |
| `~/Library/LaunchAgents/` persistence | Some sandbox profiles allow writing LaunchAgent plists |
| Login Items manipulation | Add login item pointing to payload outside sandbox |
| Shared container exploitation | Multiple apps sharing the same App Group container |

### 4.2 IPC-Based Escape

| IPC Mechanism | Escape Vector |
|---|---|
| XPC Services | Connect to privileged XPC service with insufficient client validation |
| Mach Ports | Obtain send right to privileged task port |
| Apple Events | Automate unsandboxed app to perform actions |
| Pasteboard | Write payload to pasteboard, have unsandboxed app consume it |

---

## 5. CODE SIGNING & ENTITLEMENTS

### 5.1 Inspecting Signatures and Entitlements

```bash
codesign -dv --verbose=4 /path/to/app       # Signature details
codesign -d --entitlements :- /path/to/app   # Dump entitlements

# Verify signature validity
codesign --verify --deep --strict /path/to/app
spctl --assess --type execute /path/to/app   # Gatekeeper assessment
```

### 5.2 Entitlement Abuse for Privilege Escalation

| Entitlement | Abuse Scenario |
|---|---|
| `com.apple.security.cs.disable-library-validation` | Load attacker dylib into entitled process |
| `com.apple.security.cs.allow-dyld-environment-variables` | DYLD_INSERT_LIBRARIES injection |
| `com.apple.security.get-task-allow` | Attach debugger, inject code |
| `com.apple.security.cs.debugger` | Debug any process |

### 5.3 Finding Exploitable Entitlements

```bash
# Find apps with library validation disabled
find /Applications -name "*.app" -exec sh -c \
  'codesign -d --entitlements :- "$1" 2>/dev/null | \
  grep -q "disable-library-validation" && echo "$1"' _ {} \;
```

---

## 6. PERSISTENCE AFTER BYPASS

| Method | Location | Survives Reboot | Notes |
|---|---|---|---|
| LaunchAgent | `~/Library/LaunchAgents/` | Yes | User-level, runs at login |
| LaunchDaemon | `/Library/LaunchDaemons/` | Yes | Root-level, runs at boot |
| Login Items | System Settings | Yes | Visible in System Settings |
| Cron | `crontab -e` | Yes | Often overlooked by defenders |
| Dylib hijack | Writable dylib search path | Yes | Triggered when target app launches |

---

## 7. macOS SECURITY BYPASS DECISION TREE

```
Target is macOS endpoint
+-- Need to execute untrusted binary?
|   +-- Quarantine attribute present?
|   |   +-- Yes -> xattr -d com.apple.quarantine (2.1)
|   |   +-- No -> execute directly
|   +-- Gatekeeper still blocks?
|       +-- Signed but not notarized -> right-click -> Open override
|       +-- Unsigned -> embed in signed bundle or use archive tricks (2.2)
+-- Need access to TCC-protected resources?
|   +-- FDA-granted app available? -> exploit FDA app context (1.3)
|   +-- Automation permission obtainable? -> Apple Events to TCC-granted app (1.3)
|   +-- SIP disabled? -> direct TCC.db modification (1.2)
|   +-- Check version-specific TCC bypass -> TCC_BYPASS_MATRIX.md
|   +-- MDM present? -> Compromised MDM -> push PPPC profile (1.3)
+-- Need to bypass SIP?
|   +-- Check macOS version -> historical SIP CVE? (3.4)
|   +-- Find entitled Apple binary -> piggyback SIP-bypass entitlement (3.3)
|   +-- Recovery Mode access? -> csrutil disable (3.2)
+-- Need sandbox escape?
|   +-- Office macro context -> dialog/LaunchAgent tricks (4.1)
|   +-- XPC service with weak validation -> IPC escape (4.2)
+-- Need to inject into signed process?
|   +-- disable-library-validation entitlement? -> dylib injection
|   +-- allow-dyld-environment-variables? -> DYLD_INSERT_LIBRARIES
|   +-- get-task-allow? -> debugger attach
|   +-- None -> check macos-process-injection SKILL.md
+-- Need persistence? -> Choose method by access level (6)
```

---

## 8. QUICK REFERENCE: TOOL COMMANDS

```bash
# Enumerate TCC permissions
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "SELECT * FROM access;"

# Gatekeeper status
spctl --status
spctl --assess -v /path/to/app

# SIP status
csrutil status

# Find interesting entitlements across system
find /Applications -name "*.app" -exec sh -c \
  'codesign -d --entitlements :- "$1" 2>/dev/null | \
  grep -q "disable-library-validation" && echo "$1"' _ {} \;

# List loaded kexts (kernel extensions)
kextstat | grep -v com.apple
```
