package com.ivansostarko.ottocrypt;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.PasswordHash;
import com.goterl.lazysodium.interfaces.ScalarMult;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class OttoCrypt {
    public static final byte[] MAGIC = "OTTO1".getBytes(StandardCharsets.US_ASCII);
    public static final byte ALGO_ID = (byte)0xA1;
    public static final byte KDF_PASSWORD = 0x01;
    public static final byte KDF_RAWKEY   = 0x02;
    public static final byte KDF_X25519   = 0x03;
    public static final byte FLAG_CHUNKED = 0x01;

    private final int chunkSize;
    private final LazySodiumJava ls;
    private final SecureRandom rng = new SecureRandom();

    public static final class Options {
        public String password;
        public String recipientPublic;
        public String senderSecret;
        public String rawKey;
        public Long opslimit;
        public Long memlimit;
    }

    public static final class EncResult {
        public final byte[] cipherAndTag;
        public final byte[] header;
        EncResult(byte[] ct, byte[] h){ this.cipherAndTag = ct; this.header = h; }
    }

    public OttoCrypt() { this(1024 * 1024, new LazySodiumJava(new SodiumJava())); }
    public OttoCrypt(int chunkSize, LazySodiumJava lazy) { this.chunkSize = chunkSize; this.ls = lazy; }

    public EncResult encryptString(byte[] plaintext, Options opt) throws Exception {
        Ctx ctx = initContext(opt, false);
        byte[] nonce = chunkNonce(ctx.nonceKey, 0);
        AesOut a = aesGcmEncrypt(ctx.encKey, nonce, ctx.header, plaintext);
        byte[] out = new byte[a.cipher.length + a.tag.length];
        System.arraycopy(a.cipher, 0, out, 0, a.cipher.length);
        System.arraycopy(a.tag, 0, out, a.cipher.length, a.tag.length);
        zero(ctx.masterKey);
        return new EncResult(out, ctx.header);
    }

    public byte[] decryptString(byte[] cipherAndTag, byte[] header, Options opt) throws Exception {
        if (cipherAndTag.length < 16) throw new IllegalArgumentException("ciphertext too short");
        Ctx ctx = initContextForDecryption(header, opt);
        byte[] cipher = Arrays.copyOfRange(cipherAndTag, 0, cipherAndTag.length - 16);
        byte[] tag = Arrays.copyOfRange(cipherAndTag, cipherAndTag.length - 16, cipherAndTag.length);
        byte[] nonce = chunkNonce(ctx.nonceKey, 0);
        byte[] plain = aesGcmDecrypt(ctx.encKey, nonce, ctx.aad, cipher, tag);
        zero(ctx.masterKey);
        return plain;
    }

    public void encryptFile(String inPath, String outPath, Options opt) throws Exception {
        Ctx ctx = initContext(opt, true);
        try (InputStream fin = new BufferedInputStream(new FileInputStream(inPath));
             OutputStream fout = new BufferedOutputStream(new FileOutputStream(outPath))) {
            fout.write(ctx.header);
            byte[] buf = new byte[chunkSize];
            long counter = 0;
            while (true) {
                int read = fin.read(buf);
                if (read < 0) break;
                byte[] chunk = (read == buf.length) ? buf : Arrays.copyOf(buf, read);
                byte[] nonce = chunkNonce(ctx.nonceKey, counter);
                AesOut a = aesGcmEncrypt(ctx.encKey, nonce, ctx.header, chunk);
                fout.write(Util.be32(a.cipher.length));
                fout.write(a.cipher);
                fout.write(a.tag);
                counter++;
            }
        } finally {
            zero(ctx.masterKey);
        }
    }

    public void decryptFile(String inPath, String outPath, Options opt) throws Exception {
        try (InputStream fin = new BufferedInputStream(new FileInputStream(inPath))) {
            byte[] header = readHeader(fin);
            Ctx ctx = initContextForDecryption(header, opt);
            try (OutputStream fout = new BufferedOutputStream(new FileOutputStream(outPath))) {
                long counter = 0;
                byte[] lenBuf = new byte[4];
                while (true) {
                    int r = fin.read(lenBuf);
                    if (r == -1) break;
                    if (r < 4) throw new IOException("truncated chunk length");
                    int clen = (int) Util.readU32(lenBuf, 0);
                    if (clen <= 0) break;
                    byte[] cipher = fin.readNBytes(clen);
                    if (cipher.length < clen) throw new IOException("truncated cipher");
                    byte[] tag = fin.readNBytes(16);
                    if (tag.length < 16) throw new IOException("missing tag");
                    byte[] nonce = chunkNonce(ctx.nonceKey, counter);
                    byte[] plain = aesGcmDecrypt(ctx.encKey, nonce, ctx.aad, cipher, tag);
                    fout.write(plain);
                    counter++;
                }
            } finally {
                zero(ctx.masterKey);
            }
        }
    }

    private static final class Ctx {
        final byte[] header; final byte[] aad; final byte[] encKey; final byte[] nonceKey; final byte[] masterKey;
        Ctx(byte[] h, byte[] e, byte[] n, byte[] m){ this.header=h; this.aad=h; this.encKey=e; this.nonceKey=n; this.masterKey=m; }
    }

    private byte[] readHeader(InputStream in) throws IOException {
        byte[] fixed = in.readNBytes(11);
        if (fixed.length < 11) throw new IOException("bad header");
        if (!Arrays.equals(Arrays.copyOfRange(fixed, 0, 5), MAGIC)) throw new IOException("bad magic");
        if (fixed[5] != ALGO_ID) throw new IOException("unsupported algo");
        int hlen = ByteBuffer.wrap(fixed, 9, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
        byte[] varPart = in.readNBytes(hlen);
        if (varPart.length < hlen) throw new IOException("truncated header");
        byte[] header = new byte[11 + hlen];
        System.arraycopy(fixed, 0, header, 0, 11);
        System.arraycopy(varPart, 0, header, 11, hlen);
        return header;
    }

    private Ctx initContext(Options opt, boolean chunked) throws Exception {
        byte[] fileSalt = random(16);
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(MAGIC);
        header.write(ALGO_ID);

        byte kdf;
        ByteArrayOutputStream headerExtra = new ByteArrayOutputStream();
        byte[] master;

        if (opt.password != null && !opt.password.isEmpty()) {
            kdf = KDF_PASSWORD;
            byte[] pwSalt = random(16);
            long ops = opt.opslimit != null ? opt.opslimit : PasswordHash.OPSLIMIT_MODERATE;
            long mem = opt.memlimit != null ? opt.memlimit : PasswordHash.MEMLIMIT_MODERATE;
            master = new byte[32];
            boolean ok = ls.cryptoPwHash(master, master.length, opt.password.getBytes(StandardCharsets.UTF_8),
                    opt.password.length(), pwSalt, (int)ops, (long)mem, PasswordHash.Alg.PWHASH_ALG_ARGON2ID13);
            if (!ok) throw new IllegalStateException("crypto_pwhash failed");
            headerExtra.write(pwSalt);
            headerExtra.write(Util.be32(ops));
            headerExtra.write(Util.be32(mem / 1024));
            header.write(kdf);
        } else if (opt.rawKey != null && !opt.rawKey.isEmpty()) {
            kdf = KDF_RAWKEY;
            master = Util.decodeKey(opt.rawKey);
            if (master.length != 32) throw new IllegalArgumentException("raw_key must be 32 bytes");
            header.write(kdf);
        } else if (opt.recipientPublic != null && !opt.recipientPublic.isEmpty()) {
            kdf = KDF_X25519;
            byte[] rcpt = Util.decodeKey(opt.recipientPublic);
            if (rcpt.length != ScalarMult.BYTES) throw new IllegalArgumentException("recipient_public length");
            byte[] ephSk = random(32);
            byte[] ephPk = new byte[ScalarMult.BYTES];
            ls.cryptoScalarMultBase(ephPk, ephSk);
            byte[] shared = new byte[ScalarMult.BYTES];
            if (!ls.cryptoScalarMult(shared, ephSk, rcpt)) throw new IllegalStateException("scalarmult failed");
            byte[] masterTmp = HKDF.derive(shared, 32, "OTTO-E2E-MASTER".getBytes(StandardCharsets.US_ASCII), fileSalt);
            master = masterTmp;
            headerExtra.write(ephPk);
            zero(ephSk); zero(shared);
            header.write(kdf);
        } else {
            throw new IllegalArgumentException("Provide one of: password, rawKey, recipientPublic");
        }

        header.write(chunked ? FLAG_CHUNKED : 0x00);
        header.write(0x00);

        ByteArrayOutputStream var = new ByteArrayOutputStream();
        var.write(fileSalt);
        var.write(headerExtra.toByteArray());
        byte[] varPart = var.toByteArray();
        header.write(Util.be16(varPart.length));
        header.write(varPart);
        byte[] headerBytes = header.toByteArray();

        byte[] encKey = HKDF.derive(master, 32, "OTTO-ENC-KEY".getBytes(StandardCharsets.US_ASCII), fileSalt);
        byte[] nonceKey = HKDF.derive(master, 32, "OTTO-NONCE-KEY".getBytes(StandardCharsets.US_ASCII), fileSalt);
        return new Ctx(headerBytes, encKey, nonceKey, master);
    }

    private Ctx initContextForDecryption(byte[] header, Options opt) throws Exception {
        if (header.length < 11) throw new IllegalArgumentException("header too short");
        if (!Arrays.equals(Arrays.copyOfRange(header, 0, 5), MAGIC)) throw new IllegalArgumentException("bad magic");
        if (header[5] != ALGO_ID) throw new IllegalArgumentException("unsupported algo");
        byte kdf = header[6];
        int hlen = ByteBuffer.wrap(header, 9, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xffff;
        byte[] varPart = Arrays.copyOfRange(header, 11, 11 + hlen);
        int off = 0;
        byte[] fileSalt = Arrays.copyOfRange(varPart, off, off + 16); off += 16;
        byte[] master;

        if (kdf == KDF_PASSWORD) {
            byte[] pwSalt = Arrays.copyOfRange(varPart, off, off + 16); off += 16;
            long ops = Util.readU32(varPart, off); off += 4;
            long memKiB = Util.readU32(varPart, off); off += 4;
            long mem = memKiB * 1024L;
            if (opt.password == null || opt.password.isEmpty()) throw new IllegalArgumentException("Password required");
            master = new byte[32];
            boolean ok = ls.cryptoPwHash(master, master.length, opt.password.getBytes(StandardCharsets.UTF_8),
                    opt.password.length(), pwSalt, (int)ops, (long)mem, PasswordHash.Alg.PWHASH_ALG_ARGON2ID13);
            if (!ok) throw new IllegalStateException("crypto_pwhash failed");
        } else if (kdf == KDF_RAWKEY) {
            byte[] rk = Util.decodeKey(opt.rawKey);
            if (rk.length != 32) throw new IllegalArgumentException("raw_key (32 bytes) required");
            master = rk;
        } else if (kdf == KDF_X25519) {
            byte[] ephPk = Arrays.copyOfRange(varPart, off, off + 32); off += 32;
            byte[] sk = Util.decodeKey(opt.senderSecret);
            if (sk.length != 32) throw new IllegalArgumentException("sender_secret length");
            byte[] shared = new byte[32];
            if (!ls.cryptoScalarMult(shared, sk, ephPk)) throw new IllegalStateException("scalarmult failed");
            master = HKDF.derive(shared, 32, "OTTO-E2E-MASTER".getBytes(StandardCharsets.US_ASCII), fileSalt);
        } else {
            throw new IllegalArgumentException("Unknown KDF");
        }

        byte[] encKey = HKDF.derive(master, 32, "OTTO-ENC-KEY".getBytes(StandardCharsets.US_ASCII), fileSalt);
        byte[] nonceKey = HKDF.derive(master, 32, "OTTO-NONCE-KEY".getBytes(StandardCharsets.US_ASCII), fileSalt);
        return new Ctx(Arrays.copyOfRange(header, 0, 11+hlen), encKey, nonceKey, master);
    }

    private static final class AesOut { final byte[] cipher, tag; AesOut(byte[] c, byte[] t){ cipher=c; tag=t; } }

    private AesOut aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null) c.updateAAD(aad);
        byte[] out = c.doFinal(plain);
        byte[] cipher = Arrays.copyOf(out, out.length - 16);
        byte[] tag = Arrays.copyOfRange(out, out.length - 16, out.length);
        return new AesOut(cipher, tag);
    }

    private byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] cipher, byte[] tag) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null) c.updateAAD(aad);
        byte[] ct = new byte[cipher.length + tag.length];
        System.arraycopy(cipher, 0, ct, 0, cipher.length);
        System.arraycopy(tag, 0, ct, cipher.length, tag.length);
        return c.doFinal(ct);
    }

    private byte[] chunkNonce(byte[] nonceKey, long counter) throws GeneralSecurityException {
        byte[] ctr = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(counter).array();
        byte[] info = new byte["OTTO-CHUNK-NONCE".length() + 8];
        System.arraycopy("OTTO-CHUNK-NONCE".getBytes(StandardCharsets.US_ASCII), 0, info, 0, "OTTO-CHUNK-NONCE".length());
        System.arraycopy(ctr, 0, info, "OTTO-CHUNK-NONCE".length(), 8);
        return HKDF.derive(nonceKey, 12, info, new byte[0]);
    }

    private byte[] random(int n){ byte[] b = new byte[n]; rng.nextBytes(b); return b; }
    private void zero(byte[] b){ if (b != null) Arrays.fill(b, (byte)0); }
}
