package com.ivansostarko.ottocrypt.android

import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Arrays

import com.ivansostarko.ottocrypt.android.Utils.*

object Otto {
    const val DEFAULT_CHUNK_SIZE: Int = 1 shl 20 // 1 MiB

    // ===== In-memory message =====

    @JvmStatic
    fun encryptString(plaintext: ByteArray, rawKey32: ByteArray): OttoResult {
        check(rawKey32.size == 32) { "rawKey32 must be 32 bytes" }
        val fileSalt = random16()
        val header = buildHeader(fileSalt, chunked = false)
        val (encKey, nonceKey) = deriveKeys(rawKey32, fileSalt)
        val nonce = deriveChunkNonce(nonceKey, 0)
        val cipher = encryptAesGcm(encKey, nonce, header, plaintext)
        return OttoResult(header, cipher)
    }

    @JvmStatic
    fun decryptString(cipherAndTag: ByteArray, header: ByteArray, rawKey32: ByteArray): ByteArray {
        check(rawKey32.size == 32) { "rawKey32 must be 32 bytes" }
        val ph = parseHeader(header)
        val (encKey, nonceKey) = deriveKeys(rawKey32, ph.fileSalt)
        val nonce = deriveChunkNonce(nonceKey, 0)
        return decryptAesGcm(encKey, nonce, header, cipherAndTag)
    }

    // ===== Files / streaming =====

    @JvmStatic
    fun encryptFile(input: File, output: File, rawKey32: ByteArray, chunkBytes: Int = DEFAULT_CHUNK_SIZE) {
        check(rawKey32.size == 32) { "rawKey32 must be 32 bytes" }
        val fileSalt = random16()
        val header = buildHeader(fileSalt, chunked = true)
        val (encKey, nonceKey) = deriveKeys(rawKey32, fileSalt)

        FileInputStream(input).use { fin ->
            FileOutputStream(output).use { fout ->
                fout.write(header)
                val buf = ByteArray(chunkBytes)
                var counter = 0L
                while (true) {
                    val n = fin.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    val pt = Arrays.copyOf(buf, n)
                    val nonce = deriveChunkNonce(nonceKey, counter++)
                    val ctTag = encryptAesGcm(encKey, nonce, header, pt) // ct||tag
                    val ctLen = ctTag.size - TAG_LEN
                    fout.write(u32be(ctLen))
                    fout.write(ctTag, 0, ctLen)
                    fout.write(ctTag, ctLen, TAG_LEN)
                }
                fout.flush()
            }
        }
    }

    @JvmStatic
    fun decryptFile(input: File, output: File, rawKey32: ByteArray) {
        check(rawKey32.size == 32) { "rawKey32 must be 32 bytes" }
        FileInputStream(input).use { fin ->
            FileOutputStream(output).use { fout ->
                val fixed = fin.readNBytes(FIXED_HDR_LEN)
                check(fixed.size == FIXED_HDR_LEN) { "bad header" }
                check(fixed.copyOfRange(0,5).contentEquals(MAGIC)) { "bad magic" }
                check(fixed[5] == ALGO_ID && fixed[6] == KDF_RAW) { "algo/kdf mismatch" }
                val varLen = beU16(fixed, 9)
                val varp = fin.readNBytes(varLen)
                check(varp.size == varLen) { "truncated header" }
                val header = ByteBuffer.allocate(FIXED_HDR_LEN + varLen).put(fixed).put(varp).array()

                val ph = parseHeader(header)
                val (encKey, nonceKey) = deriveKeys(rawKey32, ph.fileSalt)

                var counter = 0L
                while (true) {
                    val lenb = fin.readNBytes(4)
                    if (lenb.isEmpty()) break // EOF
                    check(lenb.size == 4) { "truncated chunk length" }
                    val clen = beU32(lenb, 0)
                    if (clen == 0) break
                    val ct = fin.readNBytes(clen)
                    check(ct.size == clen) { "truncated ciphertext" }
                    val tag = fin.readNBytes(TAG_LEN)
                    check(tag.size == TAG_LEN) { "missing tag" }

                    val nonce = deriveChunkNonce(nonceKey, counter++)
                    val cat = ByteBuffer.allocate(ct.size + TAG_LEN).put(ct).put(tag).array()
                    val pt = decryptAesGcm(encKey, nonce, header, cat)
                    fout.write(pt)
                }
                fout.flush()
            }
        }
    }

    // ===== Optional X25519 (API 28+) =====

    @JvmStatic
    fun x25519Generate(): KeyPair? {
        if (Build.VERSION.SDK_INT < 28) return null
        val kpg = KeyPairGenerator.getInstance("X25519")
        kpg.initialize(NamedParameterSpec("X25519"))
        return kpg.generateKeyPair()
    }

    @JvmStatic
    fun x25519Shared(mySecret: PrivateKey, theirPublic: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(mySecret)
        ka.doPhase(theirPublic, true)
        return ka.generateSecret()
    }

    @JvmStatic
    fun hkdfSession(shared: ByteArray, salt: ByteArray): ByteArray =
        HKDF.derive(shared, salt, "OTTO-P2P-SESSION".toByteArray(), 32)

    // ===== Internals =====

    private data class ParsedHeader(val fileSalt: ByteArray, val chunked: Boolean)

    private fun buildHeader(fileSalt16: ByteArray, chunked: Boolean): ByteArray {
        check(fileSalt16.size == FILE_SALT_LEN) { "file salt must be 16 bytes" }
        return ByteBuffer.allocate(FIXED_HDR_LEN + FILE_SALT_LEN).apply {
            put(MAGIC)
            put(ALGO_ID)
            put(KDF_RAW)
            put(if (chunked) FLAG_CHUNKED else 0x00)
            put(0x00)
            put(u16be(FILE_SALT_LEN))
            put(fileSalt16)
        }.array()
    }

    private fun parseHeader(header: ByteArray): ParsedHeader {
        check(header.size >= FIXED_HDR_LEN) { "header too short" }
        check(header.copyOfRange(0,5).contentEquals(MAGIC)) { "bad magic" }
        check(header[5] == ALGO_ID) { "algo mismatch" }
        check(header[6] == KDF_RAW) { "kdf mismatch" }
        val varLen = beU16(header, 9)
        check(header.size == FIXED_HDR_LEN + varLen) { "header length mismatch" }
        check(varLen >= FILE_SALT_LEN) { "missing file salt" }
        val fileSalt = header.copyOfRange(FIXED_HDR_LEN, FIXED_HDR_LEN + FILE_SALT_LEN)
        val chunked = (header[7].toInt() and FLAG_CHUNKED.toInt()) != 0
        return ParsedHeader(fileSalt, chunked)
    }

    private data class DerivedKeys(val encKey: ByteArray, val nonceKey: ByteArray)

    private fun deriveKeys(rawKey32: ByteArray, fileSalt: ByteArray): DerivedKeys {
        val encKey = HKDF.derive(rawKey32, fileSalt, "OTTO-ENC-KEY".toByteArray(), 32)
        val nonceKey = HKDF.derive(rawKey32, fileSalt, "OTTO-NONCE-KEY".toByteArray(), 32)
        return DerivedKeys(encKey, nonceKey)
    }

    private fun deriveChunkNonce(nonceKey32: ByteArray, counter: Long): ByteArray {
        val label = "OTTO-CHUNK-NONCE".toByteArray()
        val info = ByteBuffer.allocate(label.size + 8).put(label).put(HKDF.be64(counter)).array()
        return HKDF.expandNonce(nonceKey32, info, NONCE_LEN)
    }

    private fun encryptAesGcm(encKey32: ByteArray, nonce12: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = SecretKeySpec(encKey32, "AES")
        val gcm = GCMParameterSpec(8 * TAG_LEN, nonce12)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcm)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(pt) // ct||tag
    }

    private fun decryptAesGcm(encKey32: ByteArray, nonce12: ByteArray, aad: ByteArray, ctAndTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = SecretKeySpec(encKey32, "AES")
        val gcm = GCMParameterSpec(8 * TAG_LEN, nonce12)
        cipher.init(Cipher.DECRYPT_MODE, key, gcm)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ctAndTag)
    }
}
