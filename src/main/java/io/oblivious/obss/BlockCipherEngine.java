package io.oblivious.obss;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.KeystoreManager;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Multi-cipher authenticated block encryption and trapdoor Searchable Encryption engine.
 *
 * <p>Cryptographic highlights:
 * <ul>
 *   <li>Supports {@code AES-256-GCM}, {@code ChaCha20-Poly1305}, and {@code AES-256-CBC} with
 *       Encrypt-then-MAC {@code HMAC-SHA256} verified in constant time prior to decryption</li>
 *   <li>Derives domain-separated encryption, MAC, and deduplication subkeys from each 256-bit
 *       per-file root key via RFC 5869 HKDF-SHA256, enabling seamless multi-cipher sharing</li>
 *   <li>Binds {@code AAD} (e.g. {@code blockId} or {@code fileId}) into AEAD / EtM-HMAC tags
 *       to defeat honest-but-curious server block-swapping attacks</li>
 *   <li>Computes keyed block IDs {@code HMAC-SHA256(dedupSubkey, plaintextChunk)} to prevent
 *       cross-key ciphertext collisions and cross-user confirmation-of-file side channels</li>
 * </ul>
 */
public final class BlockCipherEngine {

    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int CHACHA_NONCE_LEN = 12;
    private static final int CBC_IV_LEN = 16;
    private static final int HMAC_SHA256_LEN = 32;

    private static final String SE_PRF_ALIAS = "obss-se-prf";
    private static final String SE_META_ENC_ALIAS = "obss-se-meta-enc";

    private static final byte[] DEDUP_INFO = "OBSS-DEDUP-HMAC-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CBC_MAC_INFO = "OBSS-ETM-HMAC-SHA256-v1".getBytes(StandardCharsets.UTF_8);

    private BlockCipherEngine() {
    }

    public static SecretKey generateFileRootKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, CryptoPrimitives.secureRandom());
        return kg.generateKey();
    }

    /**
     * Computes a deterministic, key-scoped block identifier {@code Hex(HMAC-SHA256(dedupKey, chunk))}
     * so identical chunks within the same file deduplicate without cross-tenant collisions.
     */
    public static String computeKeyedBlockId(byte[] plaintextChunk, SecretKey fileRootKey)
            throws GeneralSecurityException {
        byte[] dedupKeyBytes = deriveSubkey(fileRootKey, DEDUP_INFO);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(dedupKeyBytes, "HmacSHA256"));
            byte[] tag = mac.doFinal(plaintextChunk);
            return HexFormat.of().withUpperCase().formatHex(tag);
        } finally {
            Arrays.fill(dedupKeyBytes, (byte) 0);
        }
    }

    public static byte[] encrypt(
            byte[] plaintext, SecretKey fileRootKey, CipherMode mode, byte[] contextAad)
            throws GeneralSecurityException {
        byte[] encKeyBytes = deriveSubkey(
                fileRootKey, ("OBSS-ENC-" + mode.name()).getBytes(StandardCharsets.UTF_8));
        byte[] boundAad = buildModeBoundAad(mode, contextAad);
        try {
            return switch (mode) {
                case AES_256_GCM -> {
                    byte[] iv = CryptoPrimitives.randomBytes(GCM_IV_LEN);
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(encKeyBytes, "AES"),
                            new GCMParameterSpec(GCM_TAG_BITS, iv));
                    cipher.updateAAD(boundAad);
                    byte[] ct = cipher.doFinal(plaintext);
                    yield ByteBuffer.allocate(1 + iv.length + ct.length)
                            .put(mode.wireId())
                            .put(iv)
                            .put(ct)
                            .array();
                }
                case CHACHA20_POLY1305 -> {
                    byte[] nonce = CryptoPrimitives.randomBytes(CHACHA_NONCE_LEN);
                    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                    cipher.init(
                            Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(encKeyBytes, "ChaCha20"),
                            new IvParameterSpec(nonce));
                    cipher.updateAAD(boundAad);
                    byte[] ct = cipher.doFinal(plaintext);
                    yield ByteBuffer.allocate(1 + nonce.length + ct.length)
                            .put(mode.wireId())
                            .put(nonce)
                            .put(ct)
                            .array();
                }
                case AES_256_CBC_HMAC_SHA256 -> {
                    byte[] macKeyBytes = deriveSubkey(fileRootKey, CBC_MAC_INFO);
                    try {
                        byte[] iv = CryptoPrimitives.randomBytes(CBC_IV_LEN);
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(
                                Cipher.ENCRYPT_MODE,
                                new SecretKeySpec(encKeyBytes, "AES"),
                                new IvParameterSpec(iv));
                        byte[] ct = cipher.doFinal(plaintext);

                        Mac mac = Mac.getInstance("HmacSHA256");
                        mac.init(new SecretKeySpec(macKeyBytes, "HmacSHA256"));
                        mac.update(boundAad);
                        mac.update(iv);
                        byte[] tag = mac.doFinal(ct);

                        yield ByteBuffer.allocate(1 + iv.length + ct.length + tag.length)
                                .put(mode.wireId())
                                .put(iv)
                                .put(ct)
                                .put(tag)
                                .array();
                    } finally {
                        Arrays.fill(macKeyBytes, (byte) 0);
                    }
                }
            };
        } finally {
            Arrays.fill(encKeyBytes, (byte) 0);
        }
    }

    public static byte[] decrypt(byte[] frame, SecretKey fileRootKey, byte[] contextAad)
            throws GeneralSecurityException {
        if (frame == null || frame.length < 1 + GCM_IV_LEN + 16) {
            throw new GeneralSecurityException("Truncated cipher frame");
        }
        CipherMode mode = CipherMode.fromWireId(frame[0]);
        byte[] encKeyBytes = deriveSubkey(
                fileRootKey, ("OBSS-ENC-" + mode.name()).getBytes(StandardCharsets.UTF_8));
        byte[] boundAad = buildModeBoundAad(mode, contextAad);
        ByteBuffer buf = ByteBuffer.wrap(frame, 1, frame.length - 1);
        try {
            return switch (mode) {
                case AES_256_GCM -> {
                    if (buf.remaining() < GCM_IV_LEN + 16) {
                        throw new GeneralSecurityException("Truncated AES-GCM frame");
                    }
                    byte[] iv = new byte[GCM_IV_LEN];
                    buf.get(iv);
                    byte[] ct = new byte[buf.remaining()];
                    buf.get(ct);
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            new SecretKeySpec(encKeyBytes, "AES"),
                            new GCMParameterSpec(GCM_TAG_BITS, iv));
                    cipher.updateAAD(boundAad);
                    yield cipher.doFinal(ct);
                }
                case CHACHA20_POLY1305 -> {
                    if (buf.remaining() < CHACHA_NONCE_LEN + 16) {
                        throw new GeneralSecurityException("Truncated ChaCha20-Poly1305 frame");
                    }
                    byte[] nonce = new byte[CHACHA_NONCE_LEN];
                    buf.get(nonce);
                    byte[] ct = new byte[buf.remaining()];
                    buf.get(ct);
                    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            new SecretKeySpec(encKeyBytes, "ChaCha20"),
                            new IvParameterSpec(nonce));
                    cipher.updateAAD(boundAad);
                    yield cipher.doFinal(ct);
                }
                case AES_256_CBC_HMAC_SHA256 -> {
                    if (buf.remaining() < CBC_IV_LEN + 16 + HMAC_SHA256_LEN) {
                        throw new GeneralSecurityException("Truncated AES-CBC+HMAC frame");
                    }
                    byte[] macKeyBytes = deriveSubkey(fileRootKey, CBC_MAC_INFO);
                    try {
                        byte[] iv = new byte[CBC_IV_LEN];
                        buf.get(iv);
                        int ctLen = buf.remaining() - HMAC_SHA256_LEN;
                        byte[] ct = new byte[ctLen];
                        buf.get(ct);
                        byte[] receivedTag = new byte[HMAC_SHA256_LEN];
                        buf.get(receivedTag);

                        // Encrypt-then-MAC: verify HMAC in constant time BEFORE CBC decryption
                        Mac mac = Mac.getInstance("HmacSHA256");
                        mac.init(new SecretKeySpec(macKeyBytes, "HmacSHA256"));
                        mac.update(boundAad);
                        mac.update(iv);
                        byte[] computedTag = mac.doFinal(ct);
                        if (!CryptoPrimitives.constantTimeEquals(receivedTag, computedTag)) {
                            throw new SecurityException("HMAC-SHA256 integrity verification failed");
                        }

                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(
                                Cipher.DECRYPT_MODE,
                                new SecretKeySpec(encKeyBytes, "AES"),
                                new IvParameterSpec(iv));
                        yield cipher.doFinal(ct);
                    } finally {
                        Arrays.fill(macKeyBytes, (byte) 0);
                    }
                }
            };
        } finally {
            Arrays.fill(encKeyBytes, (byte) 0);
        }
    }

    // =========================================================================
    // Trapdoor Searchable Encryption (Owner Server-Side Index)
    // =========================================================================

    public record SearchKeyMaterial(SecretKey prfKey, SecretKey metadataEncKey) {
    }

    public static SearchKeyMaterial ensureSearchKeys(Path keystorePath, char[] password)
            throws GeneralSecurityException, IOException {
        SecretKey prfKey = KeystoreManager.loadSecretKey(keystorePath, password, SE_PRF_ALIAS);
        if (prfKey == null) {
            KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
            kg.init(256, CryptoPrimitives.secureRandom());
            prfKey = kg.generateKey();
            KeystoreManager.saveSecretKey(keystorePath, password, SE_PRF_ALIAS, prfKey);
        }
        SecretKey metaEncKey = KeystoreManager.loadSecretKey(keystorePath, password, SE_META_ENC_ALIAS);
        if (metaEncKey == null) {
            metaEncKey = generateFileRootKey();
            KeystoreManager.saveSecretKey(keystorePath, password, SE_META_ENC_ALIAS, metaEncKey);
        }
        return new SearchKeyMaterial(prfKey, metaEncKey);
    }

    public static String computeKeywordTrapdoor(SecretKey prfKey, String rawKeyword)
            throws GeneralSecurityException {
        String normalized = rawKeyword.trim().toLowerCase(Locale.ROOT);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(prfKey);
        byte[] tag = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tag);
    }

    /**
     * Builds the trapdoor index mapping {@code trapdoorToken -> encryptedFileId} for a single upload.
     * Encrypts {@code fileId} once with AES-256-GCM so conjunctive multi-keyword intersection
     * works on the server without revealing {@code fileId} or keywords in plaintext.
     */
    public static Map<String, byte[]> buildFileSearchIndex(
            String fileId, List<String> keywords, SearchKeyMaterial seKeys)
            throws GeneralSecurityException {
        Map<String, byte[]> index = new LinkedHashMap<>();
        if (keywords == null || keywords.isEmpty()) {
            return index;
        }
        byte[] encryptedFileId = encrypt(
                fileId.getBytes(StandardCharsets.UTF_8),
                seKeys.metadataEncKey(),
                CipherMode.AES_256_GCM,
                "OBSS-SE-FILEID".getBytes(StandardCharsets.UTF_8));

        for (String kw : keywords) {
            if (kw != null && !kw.isBlank()) {
                String trapdoor = computeKeywordTrapdoor(seKeys.prfKey(), kw);
                index.put(trapdoor, encryptedFileId);
            }
        }
        return index;
    }

    public static String decryptSearchResultFileId(byte[] encryptedFileId, SearchKeyMaterial seKeys)
            throws GeneralSecurityException {
        byte[] plain = decrypt(
                encryptedFileId,
                seKeys.metadataEncKey(),
                "OBSS-SE-FILEID".getBytes(StandardCharsets.UTF_8));
        return new String(plain, StandardCharsets.UTF_8);
    }

    public static List<String> normalizeKeywords(List<String> rawKeywords) {
        List<String> out = new ArrayList<>();
        if (rawKeywords == null) {
            return out;
        }
        for (String kw : rawKeywords) {
            if (kw != null) {
                String norm = kw.trim().toLowerCase(Locale.ROOT);
                if (!norm.isEmpty() && !out.contains(norm)) {
                    out.add(norm);
                }
            }
        }
        return out;
    }

    private static byte[] deriveSubkey(SecretKey rootKey, byte[] info) throws GeneralSecurityException {
        byte[] raw = rootKey.getEncoded();
        try {
            return CryptoPrimitives.hkdfSha256(raw, null, info, 32);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static byte[] buildModeBoundAad(CipherMode mode, byte[] contextAad) {
        int extra = (contextAad == null) ? 0 : contextAad.length;
        ByteBuffer buf = ByteBuffer.allocate(1 + 4 + extra);
        buf.put(mode.wireId());
        buf.putInt(extra);
        if (extra > 0) {
            buf.put(contextAad);
        }
        return buf.array();
    }
}
