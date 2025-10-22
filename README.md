# otto-crypt-android

Android library (Kotlin) implementing the **OTTO** encryption format — **wire-compatible with the Laravel/PHP SDK**.

- AES-256-GCM (tag 16B), AAD = OTTO header
- HKDF-SHA256 per-object keys (`encKey`, `nonceKey`)
- HKDF-SIV-style 12B nonces per chunk (`"OTTO-CHUNK-NONCE" || counter_be64`)
- Streaming container for large files: `header || [u32_be ct_len || ct || tag16]*`
- Optional X25519 helpers (API 28+)

## Import
Open the folder in **Android Studio** and include the module `:ottocrypt-android` in your app.
Or publish the AAR from `:ottocrypt-android` and depend on it.

## Usage

### Text
```kotlin
import com.ivansostarko.ottocrypt.android.Otto
import java.security.SecureRandom
import android.util.Base64

val rawKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
val enc = Otto.encryptString("Hello OTTO".toByteArray(), rawKey)
val headerB64 = Base64.encodeToString(enc.header, Base64.NO_WRAP)
val cipherB64 = Base64.encodeToString(enc.cipherAndTag, Base64.NO_WRAP)

// later
val header = Base64.decode(headerB64, Base64.NO_WRAP)
val cipher = Base64.decode(cipherB64, Base64.NO_WRAP)
val plain = Otto.decryptString(cipher, header, rawKey)
```

### Files (photo/audio/video/any)
```kotlin
val key = rawKey // 32B
Otto.encryptFile(File("/sdcard/Download/movie.mp4"), File("/sdcard/Download/movie.mp4.otto"), key)
Otto.decryptFile(File("/sdcard/Download/movie.mp4.otto"), File("/sdcard/Download/movie.dec.mp4"), key)
```

### Optional X25519 (API 28+)
```kotlin
val kp = Otto.x25519Generate() ?: error("X25519 requires API 28+")
val session = Otto.hkdfSession(
    shared = Otto.x25519Shared(kp.private, kp.public),
    salt = "room-salt".toByteArray()
)
```

## Interop (Laravel ↔ Android)
- **Header**: `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- **Keys**: `encKey = HKDF(rawKey, salt=file_salt, info="OTTO-ENC-KEY", 32)`; `nonceKey = HKDF(rawKey, salt=file_salt, info="OTTO-NONCE-KEY", 32)`
- **Nonces**: `HKDF(nonceKey, salt="", info="OTTO-CHUNK-NONCE"||counter_be64, 12)`
- **AEAD**: AES-256-GCM (tag 16B), AAD = header
- **Container**: `header || [u32_be ct_len || ct || tag16]*`

MIT © 2025 Ivan Doe
