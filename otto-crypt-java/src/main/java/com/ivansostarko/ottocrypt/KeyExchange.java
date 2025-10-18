package com.ivansostarko.ottocrypt;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.ScalarMult;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class KeyExchange {
    private final LazySodiumJava ls;
    private static final SecureRandom RNG = new SecureRandom();

    public KeyExchange(LazySodiumJava ls) { this.ls = ls; }

    public static final class Keypair {
        public final byte[] secret;
        public final byte[] pub;
        Keypair(byte[] sk, byte[] pk){ this.secret = sk; this.pub = pk; }
    }

    public Keypair generateKeypair() {
        byte[] sk = new byte[ScalarMult.SCALARBYTES];
        RNG.nextBytes(sk);
        byte[] pk = new byte[ScalarMult.BYTES];
        ls.cryptoScalarMultBase(pk, sk);
        return new Keypair(sk, pk);
    }

    public byte[] deriveSharedSecret(byte[] mySecret, byte[] theirPublic) {
        byte[] shared = new byte[ScalarMult.BYTES];
        if (!ls.cryptoScalarMult(shared, mySecret, theirPublic)) {
            throw new IllegalStateException("crypto_scalarmult failed");
        }
        return shared;
    }

    public byte[] deriveSessionKey(byte[] shared, byte[] salt, String context) throws Exception {
        return HKDF.derive(shared, 32, context.getBytes(StandardCharsets.US_ASCII), salt);
    }
}
