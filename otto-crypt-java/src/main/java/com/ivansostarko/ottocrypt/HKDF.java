package com.ivansostarko.ottocrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

final class HKDF {
    static byte[] derive(byte[] ikm, int length, byte[] info, byte[] salt) throws GeneralSecurityException {
        byte[] prk = extract(ikm, salt);
        return expand(prk, info, length);
    }

    static byte[] extract(byte[] ikm, byte[] salt) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        if (salt == null || salt.length == 0) salt = new byte[32];
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    static byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        int hashLen = 32;
        int n = (int)Math.ceil((double)length / hashLen);
        byte[] t = new byte[0];
        byte[] okm = new byte[n * hashLen];
        int pos = 0;
        for (int i = 1; i <= n; i++) {
            mac.reset();
            mac.update(t);
            mac.update(info);
            mac.update((byte)i);
            t = mac.doFinal();
            System.arraycopy(t, 0, okm, pos, t.length);
            pos += t.length;
        }
        return Arrays.copyOf(okm, length);
    }
}
