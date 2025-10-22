package com.ivansostarko.ottocrypt.android

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.util.Arrays

/** RFC 5869 HKDF (HMAC-SHA256) */
internal object HKDF {
    private const val HMAC = "HmacSHA256"

    private fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC)
        mac.init(SecretKeySpec(salt ?: ByteArray(0), HMAC))
        return mac.doFinal(ikm)
    }

    private fun expand(prk: ByteArray, info: ByteArray?, len: Int): ByteArray {
        val mac = Mac.getInstance(HMAC)
        mac.init(SecretKeySpec(prk, HMAC))
        val out = ByteArray(len)
        var t = ByteArray(0)
        var pos = 0
        var counter: Byte = 1
        while (pos < len) {
            mac.reset()
            mac.update(t)
            if (info != null) mac.update(info)
            mac.update(counter)
            t = mac.doFinal()
            val copy = minOf(t.size, len - pos)
            System.arraycopy(t, 0, out, pos, copy)
            pos += copy
            counter = (counter + 1).toByte()
        }
        Arrays.fill(t, 0)
        return out
    }

    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val prk = extract(salt, ikm)
        val okm = expand(prk, info, len)
        Arrays.fill(prk, 0)
        return okm
    }

    fun expandNonce(nonceKey32: ByteArray, info: ByteArray, len: Int): ByteArray {
        // HKDF-SIV-style: use nonceKey as IKM and empty salt to produce deterministic nonce
        val prk = extract(ByteArray(0), nonceKey32)
        val out = expand(prk, info, len)
        Arrays.fill(prk, 0)
        return out
    }

    fun be64(v: Long): ByteArray =
        ByteBuffer.allocate(8).putLong(v).array()
}
