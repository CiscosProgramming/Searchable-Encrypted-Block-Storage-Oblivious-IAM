package io.oblivious.obss;

import java.util.Locale;

/**
 * Runtime-configurable authenticated encryption modes for OBSS blocks and manifests.
 * Each encrypted frame carries a 1-byte authenticated mode header so switching modes at
 * runtime never breaks decryption of previously uploaded files.
 */
public enum CipherMode {
    AES_256_GCM((byte) 0x01),
    CHACHA20_POLY1305((byte) 0x02),
    AES_256_CBC_HMAC_SHA256((byte) 0x03);

    private final byte wireId;

    CipherMode(byte wireId) {
        this.wireId = wireId;
    }

    public byte wireId() {
        return wireId;
    }

    public static CipherMode fromWireId(byte id) {
        for (CipherMode mode : values()) {
            if (mode.wireId == id) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unknown CipherMode wire ID: " + id);
    }

    public static CipherMode parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("Cipher mode cannot be null");
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT)
                .replace('-', '_')
                .replace(' ', '_');
        return switch (normalized) {
            case "AES_256_GCM", "AES_GCM" -> AES_256_GCM;
            case "CHACHA20_POLY1305" -> CHACHA20_POLY1305;
            case "AES_256_CBC_HMAC_SHA256", "AES_CBC_PKCS5PADDING" -> AES_256_CBC_HMAC_SHA256;
            default -> throw new IllegalArgumentException("Unsupported cipher mode: " + raw);
        };
    }
}
