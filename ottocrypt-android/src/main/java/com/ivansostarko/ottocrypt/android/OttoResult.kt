package com.ivansostarko.ottocrypt.android

data class OttoResult(
    val header: ByteArray,         // AAD header
    val cipherAndTag: ByteArray    // ct || tag[16]
)
