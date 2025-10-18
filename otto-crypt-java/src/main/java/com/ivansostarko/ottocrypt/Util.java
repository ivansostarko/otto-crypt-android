package com.ivansostarko.ottocrypt;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;

final class Util {
    static byte[] hexDecode(String s) {
        int len = s.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("hex length");
        byte[] out = new byte[len/2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2*i), 16);
            int lo = Character.digit(s.charAt(2*i+1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("bad hex");
            out[i] = (byte)((hi<<4) | lo);
        }
        return out;
    }

    static byte[] decodeKey(String s) {
        if (s == null) return new byte[0];
        s = s.trim();
        if (s.matches("^[0-9a-fA-F]+$") && (s.length() % 2 == 0)) {
            try { return hexDecode(s); } catch (Exception ignored) {}
        }
        try {
            byte[] b = Base64.getDecoder().decode(s);
            if (b.length > 0) return b;
        } catch (Exception ignored) {}
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static byte[] be16(int v) {
        ByteBuffer bb = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
        bb.putShort((short)(v & 0xFFFF));
        return bb.array();
    }

    static byte[] be32(long v) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        bb.putInt((int)(v & 0xFFFFFFFFL));
        return bb.array();
    }

    static long readU32(byte[] b, int off) {
        return ((b[off] & 0xffL) << 24) | ((b[off+1] & 0xffL) << 16) | ((b[off+2] & 0xffL) << 8) | (b[off+3] & 0xffL);
    }
}
