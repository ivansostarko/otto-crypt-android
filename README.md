# OTTO Crypt — Java & Android

**Modules:**
- `:otto-crypt-java` — pure Java library (JDK 11+)
- `:otto-crypt-android` — Android wrapper depending on Java core + `lazysodium-android`

**License:** MIT  
**Author:** Ivan Doe  
**Interop:** ✅ Compatible with Laravel `ivansostarko/otto-crypt-php`, Node `otto-crypt-js`, Python `otto-crypt-py`, and .NET `IvanSostarko.OttoCrypt`

Implements **OTTO-256-GCM-HKDF-SIV** with **AES-256-GCM**, **HKDF(SHA-256)**, **Argon2id** (`crypto_pwhash`), and **X25519**. Supports **streaming** for large files and **E2E** sessions (ephemeral X25519).

> ⚠️ Custom composition. Get an **independent cryptographic review** before production use.

## Install

### Java
```gradle
repositories { mavenCentral() }
dependencies {
    implementation("com.ivansostarko:otto-crypt-java:0.1.0") // when published
    implementation("com.goterl:lazysodium-java:5.1.0")
    implementation("net.java.dev.jna:jna:5.13.0")
}
```

### Android
```gradle
dependencies {
    implementation(project(":otto-crypt-android"))        // if using this repo
    implementation("com.goterl:lazysodium-android:5.1.0") // sodium JNI for Android
}
```

## Usage (Java)

```java
import com.ivansostarko.ottocrypt.OttoCrypt;
import com.ivansostarko.ottocrypt.OttoCrypt.Options;

var o = new OttoCrypt();

// Strings
var opt = new Options(); opt.password = "P@ssw0rd!";
var enc = o.encryptString("hello".getBytes(StandardCharsets.UTF_8), opt);
var plain = o.decryptString(enc.cipherAndTag, enc.header, opt);

// Files
o.encryptFile("in.mp4", "in.mp4.otto", opt);
o.decryptFile("in.mp4.otto", "in.dec.mp4", opt);

// X25519 (E2E)
var encOpt = new Options(); encOpt.recipientPublic = "<BASE64_OR_HEX_PUBLIC>";
var decOpt = new Options(); decOpt.senderSecret = "<BASE64_OR_HEX_SECRET>";
o.encryptFile("photo.jpg", "photo.jpg.otto", encOpt);
o.decryptFile("photo.jpg.otto", "photo.jpg", decOpt);
```

## Algorithm & Format

**Header:**
```
OTTO1 | 0xA1 | kdf | flags | 0x00 | hlen(2) | file_salt(16) | (pw_salt+ops+memKiB | eph_pubkey)
```
**Chunks:** `[len(4-be)] [ciphertext] [tag(16)]`, **AD** = full header.

**Keys & Nonces:**
```
enc_key   = HKDF(master, 32, "OTTO-ENC-KEY",  file_salt)
nonce_key = HKDF(master, 32, "OTTO-NONCE-KEY", file_salt)
nonce_i   = HKDF(nonce_key, 12, "OTTO-CHUNK-NONCE" || counter64be, "")
```

**Master key** from **Argon2id**, **raw 32-byte key**, or **X25519** ECDH (ephemeral sender public in header).

## Interoperability

Matches the Laravel/Node/Python/.NET OTTO implementations byte-for-byte: same header, AD, HKDF labels, deterministic nonce derivation, and streaming wire format.

## Security Notes

- AES-GCM (16B tag) with header-bound AD
- Deterministic nonces mitigate nonce reuse errors
- Strong passwords + Argon2id required; prefer E2E for messengers
- JVM/Android memory may retain copies despite zeroing
- Audit recommended

## Build

```bash
./gradlew :otto-crypt-java:build
./gradlew :otto-crypt-android:assembleRelease
```

MIT © 2025 Ivan Doe
