package com.ivansostarko.ottocrypt.android

import java.nio.ByteBuffer
import java.security.SecureRandom

internal object Utils {
    val MAGIC = byteArrayOf('O'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(), 'O'.code.toByte(), '1'.code.toByte())
    const val ALGO_ID: Byte = 0xA1.toByte()
    const val KDF_RAW: Byte = 0x02
    const val FLAG_CHUNKED: Byte = 0x01

    const val FIXED_HDR_LEN = 11 // 5 magic + 1 algo + 1 kdf + 1 flags + 1 reserved + 2 var-len
    const val FILE_SALT_LEN = 16
    const val TAG_LEN = 16
    const val NONCE_LEN = 12

    private val rng = SecureRandom()

    fun random16(): ByteArray = ByteArray(16).also { rng.nextBytes(it) }

    fun u16be(v: Int): ByteArray = ByteBuffer.allocate(2).putShort((v and 0xffff).toShort()).array()
    fun u32be(v: Int): ByteArray = ByteBuffer.allocate(4).putInt(v).array()

    fun beU16(v: ByteArray, off: Int): Int =
        ((v[off].toInt() and 0xff) shl 8) or (v[off+1].toInt() and 0xff)

    fun beU32(v: ByteArray, off: Int): Int =
        ((v[off].toInt() and 0xff) shl 24) or
        ((v[off+1].toInt() and 0xff) shl 16) or
        ((v[off+2].toInt() and 0xff) shl 8) or
        (v[off+3].toInt() and 0xff)

    fun check(cond: Boolean, msg: String) {
        if (!cond) throw IllegalArgumentException(msg)
    }
}
