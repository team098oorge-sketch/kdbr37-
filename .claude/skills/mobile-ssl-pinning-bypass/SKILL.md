---
name: mobile-ssl-pinning-bypass
description: >-
  Mobile SSL pinning bypass playbook. Use when performing authorized mobile app security testing and need to bypass certificate pinning on Android or iOS to intercept HTTPS traffic.
---

# SKILL: Mobile SSL Pinning Bypass — Expert Playbook

## 0. PINNING TYPES

| Type | What is Pinned | Resilience | Common Frameworks |
|---|---|---|---|
| Certificate | Full DER cert bytes | Low — breaks on cert renewal | Custom, old apps |
| Public Key | SubjectPublicKeyInfo bytes | Medium — survives cert rotation | OkHttp, Volley |
| SPKI Hash | SHA-256 of SPKI | Medium-High | TrustKit, modern OkHttp |
| CA Pin | Intermediate/root CA cert | Low-Medium | Enterprise |
| Multi-pin | Multiple of above | High | Banks, fintech |

---

## 1. ANDROID BYPASS

### 1.1 Frida Universal SSL Bypass

```javascript
// universal-ssl-bypass.js — hooks multiple TLS stacks
Java.perform(function() {
  // TrustManagerImpl (AOSP)
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      return untrustedChain;
    };
  } catch(e) {}

  // X509TrustManager
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.bypass.TrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function(chain, authType) {},
        checkServerTrusted: function(chain, authType) {},
        getAcceptedIssuers: function() { return []; }
      }
    });
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
      SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };
  } catch(e) {}

  // OkHttp3 CertificatePinner
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
      return;
    };
    CertificatePinner['check$okhttp'].implementation = function(hostname, peerCertificates) {
      return;
    };
  } catch(e) {}

  // OkHttpClient.Builder.certificatePinner
  try {
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');
    Builder.certificatePinner.implementation = function(pinner) {
      return this;
    };
  } catch(e) {}

  // Volley HurlStack
  try {
    var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
    HurlStack.createConnection.implementation = function(url) {
      var connection = this.createConnection(url);
      if (connection instanceof Java.use('javax.net.ssl.HttpsURLConnection').$class) {
        connection.setSSLSocketFactory(
          Java.use('javax.net.ssl.SSLContext').getInstance('TLS').getSocketFactory()
        );
      }
      return connection;
    };
  } catch(e) {}

  // Conscrypt
  try {
    var Platform = Java.use('com.android.org.conscrypt.Platform');
    Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function() {};
    Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function() {};
  } catch(e) {}

  // Apache HttpClient
  try {
    var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
    AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function() {};
  } catch(e) {}

  // HostnameVerifier
  try {
    var HostnameVerifier = Java.use('javax.net.ssl.HttpsURLConnection');
    HostnameVerifier.setDefaultHostnameVerifier.implementation = function(verifier) {};
  } catch(e) {}
});
```

```bash
# Run with frida
frida -U -f com.target.app -l universal-ssl-bypass.js --no-pause
# Or attach to running app
frida -U com.target.app -l universal-ssl-bypass.js
```

### 1.2 Objection — One Command

```bash
# Start app and bypass all pinning
objection -g com.target.app explore
# Inside objection:
android sslpinning disable

# Or inject on startup
objection -g com.target.app explore --startup-command 'android sslpinning disable'
```

### 1.3 Network Security Config

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>
```

```bash
# Decompile APK
apktool d app.apk -o app_decompiled

# Edit AndroidManifest.xml to add networkSecurityConfig
# android:networkSecurityConfig="@xml/network_security_config"

# Add the XML file above
mkdir -p app_decompiled/res/xml
vim app_decompiled/res/xml/network_security_config.xml

# Recompile and sign
apktool b app_decompiled -o app_patched.apk
keytool -genkey -v -keystore my.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my.keystore app_patched.apk alias_name
zipalign -v 4 app_patched.apk app_patched_aligned.apk
adb install app_patched_aligned.apk
```

### 1.4 Xposed/LSPosed Modules

| Module | Scope | Notes |
|---|---|---|
| TrustMeAlready | System-wide | Disables SSL validation globally |
| SSLUnpinning | Per-app | Targets known pinning implementations |
| JustTrustMe | Per-app | Hooks ~20 pinning implementations |
| MagiskTrustUserCerts | System | Installs user certs as system certs |

### 1.5 Magisk — System CA Installation

```bash
# Install Magisk module: MagiskTrustUserCerts
# Or manually:
adb push burp.der /data/local/tmp/
adb shell
su
# Convert to PEM
openssl x509 -inform DER -in /data/local/tmp/burp.der -out /data/local/tmp/burp.pem
# Get hash name
hash=$(openssl x509 -inform PEM -subject_hash_old -in /data/local/tmp/burp.pem | head -1)
cp /data/local/tmp/burp.pem /data/local/tmp/${hash}.0
# Mount system partition as writable (Magisk)
mount -o rw,remount /system
cp /data/local/tmp/${hash}.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/${hash}.0
```

### 1.6 Manual Decompile + Patch

```bash
# Decompile with jadx for analysis
jadx -d output/ app.apk

# Find pinning code
grep -r 'CertificatePinner\|checkServerTrusted\|TrustManager\|pinnedCertificate' output/

# Decompile with apktool for smali patching
apktool d app.apk -o smali_out

# Find smali files for pinning class
grep -r 'checkServerTrusted\|CertificatePinner' smali_out/

# Patch smali: replace validation with return-void
# Original:
# invoke-virtual {p0, p1, p2}, Lcom/target/Pinning;->checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
# Add after method prologue:
# return-void
```

---

## 2. iOS BYPASS

### 2.1 Frida SecTrust Hooks

```javascript
// ios-ssl-bypass.js
if (ObjC.available) {
  // SecTrustEvaluateWithError (iOS 12+)
  try {
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
      if (error != 0) Memory.writePointer(error, NULL);
      return 1;
    }, 'int', ['pointer', 'pointer']));
  } catch(e) {}

  // SecTrustEvaluate (legacy)
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
      Memory.writeU32(result, 4); // kSecTrustResultProceed
      return 0;
    }, 'int', ['pointer', 'pointer']));
  } catch(e) {}

  // SSLHandshake (TLS 1.2 and below)
  try {
    var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
    Interceptor.replace(SSLHandshake, new NativeCallback(function(context) {
      return 0; // noErr
    }, 'int', ['pointer']));
  } catch(e) {}

  // NSURLSession delegate enumeration
  var delegates = [];
  ObjC.enumerateLoadedClasses({
    onMatch: function(name, handle) {
      try {
        var cls = ObjC.classes[name];
        if (cls.respondsToSelector_(ObjC.selector('URLSession:didReceiveChallenge:completionHandler:'))) {
          delegates.push(name);
        }
      } catch(e) {}
    },
    onComplete: function() {}
  });
  delegates.forEach(function(name) {
    try {
      var cls = ObjC.classes[name];
      cls['- URLSession:didReceiveChallenge:completionHandler:'].implementation = ObjC.implement(
        cls['- URLSession:didReceiveChallenge:completionHandler:'],
        function(self, sel, session, challenge, completionHandler) {
          var credential = ObjC.classes.NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
          completionHandler(0, credential); // NSURLSessionAuthChallengeUseCredential
        }
      );
    } catch(e) {}
  });
}
```

### 2.2 Objection iOS

```bash
objection -g com.target.app explore
# Inside:
ios sslpinning disable
```

### 2.3 SSL Kill Switch 2

```bash
# Install via Cydia/Sileo on jailbroken device
# Package: com.nablac0d3.sslkillswitch2
# Activator: toggle via Settings > SSL Kill Switch 2

# Or inject with frida-gadget in IPA
```

### 2.4 Library-Specific Hooks

| Library | Hook Target | Notes |
|---|---|---|
| AFNetworking | `AFSecurityPolicy.evaluateServerTrust:forDomain:` | Most common iOS HTTP lib |
| Alamofire | `ServerTrustManager.serverTrustEvaluator` | Swift-native |
| TrustKit | `TSKPinningValidator.evaluateTrust:forHostname:` | Explicit hook needed |
| NSURLSession | Delegate `URLSession:didReceiveChallenge:completionHandler:` | Generic iOS |

### 2.5 Manual Binary Patch

```bash
# Find pinning function in binary
otool -tV TargetApp.app/TargetApp | grep -A5 'checkTrust\|evaluateTrust'

# LLDB breakpoint + return bypass
lldb
attach com.target.app
breakpoint set -n "SecTrustEvaluateWithError"
breakpoint command add
  thread return 1
DONE
continue
```

---

## 3. FRAMEWORK-SPECIFIC BYPASSES

### 3.1 Flutter

Flutter uses BoringSSL directly — Java/ObjC hooks don't work.

```javascript
// Flutter BoringSSL hook
// Find ssl_crypto_x509_session_verify_cert_chain via pattern scan
var boringssl = Process.getModuleByName('libflutter.so'); // Android
// var boringssl = Process.getModuleByName('Flutter'); // iOS

// Pattern scan for ssl_verify_peer_cert
var pattern = '2d e9 f0 4f a3 b0';
Memory.scan(boringssl.base, boringssl.size, pattern, {
  onMatch: function(address) {
    Interceptor.replace(address, new NativeCallback(function(ssl, out_alert) {
      return 0;
    }, 'int', ['pointer', 'pointer']));
  },
  onError: function(reason) {},
  onComplete: function() {}
});
```

```bash
# reflutter — automated Flutter SSL bypass
pip install reflutter
# Patch APK:
reflutter app.apk
# Sign and install patched APK, configure Burp on 8083
```

### 3.2 React Native

Android: hooks OkHttp3 (see §1.1)
iOS: hooks NSURLSession (see §2.4)

```javascript
// React Native specific
Java.perform(function() {
  var ReactInstanceManager = Java.use('com.facebook.react.ReactInstanceManager');
  // Patch OkHttpClient builder used by RN
});
```

### 3.3 Xamarin

```javascript
// Xamarin hooks Mono runtime
var monoModule = Process.getModuleByName('libmonosgen-2.0.so');
// Hook mono_security_x509_verify_certificate or native TLS stack
// Objection has built-in support:
// android sslpinning disable --quiet
```

---

## 4. CERTIFICATE TRANSPARENCY & HPKP

| Mechanism | Bypass | Notes |
|---|---|---|
| Certificate Transparency | Not a client-enforced pinning; bypass n/a | Server-side feature |
| HPKP (deprecated) | Use Frida to disable HPKP check class | Chrome removed HPKP in 2018 |
| Public Key Pinning (custom) | Hook comparison function | Same as SPKI hash bypass |

---

## 5. TROUBLESHOOTING

| Symptom | Cause | Fix |
|---|---|---|
| Frida hooks applied but traffic still fails | Multiple pinning stacks | Add more hooks, use objection dump to find all |
| App crashes on hook | Hook incorrect signature | Use `frida-trace -U -i "*SSL*" com.target.app` to discover |
| OkHttp hook fails | OkHttp4 vs OkHttp3 API change | Try both class names |
| Hooks work but cert invalid | Wrong Burp listener IP/port | Check proxy settings in device |
| iOS hook fails on arm64e | PAC pointer authentication | Use Frida 16+ on A12+ devices |
| App detects Frida | Frida detection | Use Frida with re-Frida or custom gadget |
| APK repackaging fails | Play Protect check | Use Magisk or Frida without repackaging |

```bash
# Diagnostic: trace SSL calls
frida-trace -U -i "*SSL*" -i "*Trust*" -i "*Certificate*" com.target.app

# List loaded Java classes related to SSL
frida -U com.target.app -e "Java.perform(function(){ Java.enumerateLoadedClasses({ onMatch: function(n){ if(n.includes('SSL')||n.includes('Trust')) console.log(n); }, onComplete: function(){} }); })"
```

---

## 6. DECISION TREE

```
Need to intercept SSL traffic from mobile app
│
├── Android?
│   ├── Quick bypass needed → objection: android sslpinning disable (§1.2)
│   ├── Custom pinning implementation?
│   │   ├── OkHttp3 → hook CertificatePinner.check (§1.1)
│   │   ├── Volley → hook HurlStack (§1.1)
│   │   ├── Custom TrustManager → hook checkServerTrusted (§1.1)
│   │   └── Unknown → frida-trace to discover (§5)
│   ├── Can't use Frida? → Network Security Config patch (§1.3)
│   ├── Root available? → Magisk system CA (§1.5)
│   └── Flutter app? → BoringSSL hook or reflutter (§3.1)
│
├── iOS?
│   ├── Quick bypass → objection: ios sslpinning disable (§2.2)
│   ├── Jailbroken? → SSL Kill Switch 2 (§2.3)
│   ├── AFNetworking → hook evaluateServerTrust (§2.4)
│   ├── TrustKit → hook TSKPinningValidator (§2.4)
│   └── SecTrust level → Frida SecTrust hooks (§2.1)
│
└── Pinning persists after all hooks?
    ├── Check for certificate transparency enforcement
    ├── Check for background services with separate HTTP stack
    └── Use reflutter / binary patching (§2.5, §3.1)
```

---

## 7. PROXY SETUP QUICK REFERENCE

| Proxy | Android Port | iOS Port | Listener |
|---|---|---|---|
| Burp Suite | 8080 | 8080 | All interfaces |
| mitmproxy | 8080 | 8080 | 0.0.0.0 |
| Charles Proxy | 8888 | 8888 | All interfaces |

```bash
# Set Android proxy via ADB
adb shell settings put global http_proxy PROXY_IP:8080

# Remove Android proxy
adb shell settings put global http_proxy :0

# Export mitmproxy CA for Android
# Visit http://mitm.it on the device through the proxy
```
