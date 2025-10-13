# OTTO Crypt — Java & Android

**Modules:**
- `:otto-crypt-java` — pure Java library (JDK 11+)
- `:otto-crypt-android` — Android wrapper depending on Java core + `lazysodium-android`


Implements **OTTO-256-GCM-HKDF-SIV** with **AES-256-GCM**, **HKDF(SHA-256)**, **Argon2id** (`crypto_pwhash`), and **X25519**. Supports **streaming** for large files and **E2E** sessions (ephemeral X25519).

> ⚠️ Custom composition. Get an **independent cryptographic review** before production use.

## Install


### Android
```gradle
dependencies {
    implementation(project(":otto-crypt-android"))        // if using this repo
    implementation("com.goterl:lazysodium-android:5.1.0") // sodium JNI for Android
}
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

MIT © 2025 Ivan Sostarko
