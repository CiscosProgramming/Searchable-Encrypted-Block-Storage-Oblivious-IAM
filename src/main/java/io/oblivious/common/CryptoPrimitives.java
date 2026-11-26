package io.oblivious.common;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hardened JCA/JCE cryptographic primitives:
 * <ul>
 *   <li>NIST P-256 ({@code secp256r1}) ECDSA signatures (ASN.1 DER and IEEE P1363 for RFC 7515 ES256)</li>
 *   <li>HPKE/ECIES-style key wrapping via ephemeral ECDH + RFC 5869 HKDF-SHA256 + AES-256-GCM with AAD binding</li>
 *   <li>Client pre-hashed + server salted &amp; peppered PBKDF2-HMAC-SHA256 password verifiers</li>
 *   <li>Constant-time byte and digest comparisons</li>
 * </ul>
 */
public final class CryptoPrimitives {

    public static final String EC_CURVE = "secp256r1";
    public static final int GCM_IV_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;
    public static final int SALT_BYTES = 16;
    public static final int DEFAULT_PBKDF2_ITERATIONS = 210_000;
    private static final byte[] KEYWRAP_HKDF_INFO =
            "OAMS-ECIES-KEYWRAP-AES256GCM-v1".getBytes(StandardCharsets.UTF_8);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoPrimitives() {
    }

    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        SECURE_RANDOM.nextBytes(out);
        return out;
    }

    public static byte[] generateSalt() {
        return randomBytes(SALT_BYTES);
    }

    public static String generateNonceBase64Url(int numBytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(numBytes));
    }

    public static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec(EC_CURVE), SECURE_RANDOM);
        return keyGen.generateKeyPair();
    }

    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey decodePublicKey(String base64X509) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(base64X509);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static byte[] signEcdsa(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey, SECURE_RANDOM);
        sig.update(message);
        return sig.sign();
    }

    public static boolean verifyEcdsa(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        if (publicKey == null || message == null || signatureBytes == null) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signatureBytes);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Signs using IEEE P1363 fixed 64-byte (R || S) format required by RFC 7515 ES256 JWT. */
    public static byte[] signEcdsaP1363(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
        sig.initSign(privateKey, SECURE_RANDOM);
        sig.update(message);
        return sig.sign();
    }

    /** Verifies an IEEE P1363 fixed 64-byte (R || S) signature for RFC 7515 ES256 JWT. */
    public static boolean verifyEcdsaP1363(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        if (publicKey == null || message == null || signatureBytes == null || signatureBytes.length != 64) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Client-side SHA-256 pre-hashing so the OAS server remains oblivious to the
     * user's raw password even during authentication. Zeroes transient byte buffers.
     */
    public static String preHashPassword(char[] password) {
        ByteBuffer byteBuf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] raw = new byte[byteBuf.remaining()];
        byteBuf.get(raw);
        try {
            byte[] digest = sha256(raw);
            return Base64.getEncoder().encodeToString(digest);
        } finally {
            Arrays.fill(raw, (byte) 0);
            if (byteBuf.hasArray()) {
                Arrays.fill(byteBuf.array(), (byte) 0);
            }
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String derivePasswordVerifier(String clientPreHash, String pepper, byte[] salt) {
        return derivePasswordVerifier(clientPreHash, pepper, salt, DEFAULT_PBKDF2_ITERATIONS);
    }

    public static String derivePasswordVerifier(
            String clientPreHash, String pepper, byte[] salt, int iterations) {
        char[] combined = (clientPreHash + ":" + pepper).toCharArray();
        PBEKeySpec spec = new PBEKeySpec(combined, salt, iterations, 256);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derived = skf.generateSecret(spec).getEncoded();
            try {
                return Base64.getEncoder().encodeToString(derived);
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 failed", e);
        } finally {
            spec.clearPassword();
            Arrays.fill(combined, '\0');
        }
    }

    public static boolean constantTimeEquals(String b64Expected, String b64Actual) {
        if (b64Expected == null || b64Actual == null) {
            return false;
        }
        byte[] a = b64Expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = b64Actual.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return a != null && b != null && MessageDigest.isEqual(a, b);
    }

    /**
     * RFC 5869 HKDF-SHA256 (Extract + Expand) for deriving uniform symmetric keys
     * from raw ECDH shared secrets.
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int lengthBytes)
            throws GeneralSecurityException {
        if (lengthBytes <= 0 || lengthBytes > 255 * 32) {
            throw new IllegalArgumentException("Invalid HKDF output length: " + lengthBytes);
        }
        byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
        byte[] prk = hmac.doFinal(ikm);

        byte[] okm = new byte[lengthBytes];
        byte[] previousT = new byte[0];
        int offset = 0;
        int counter = 1;
        try {
            while (offset < lengthBytes) {
                hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
                hmac.update(previousT);
                if (info != null && info.length > 0) {
                    hmac.update(info);
                }
                hmac.update((byte) counter);
                previousT = hmac.doFinal();
                int toCopy = Math.min(previousT.length, lengthBytes - offset);
                System.arraycopy(previousT, 0, okm, offset, toCopy);
                offset += toCopy;
                counter++;
            }
            return okm;
        } finally {
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(previousT, (byte) 0);
        }
    }

    /**
     * Wraps a symmetric key for {@code recipientPublicKey} using ephemeral P-256 ECDH +
     * HKDF-SHA256 (binding KEM context {@code ephemeralPub || recipientPub}) + AES-256-GCM
     * authenticated encryption with optional {@code aad} (e.g., {@code fileId || permission})
     * to prevent cross-file wrapped-key substitution attacks.
     */
    public static String wrapSymmetricKey(byte[] secretKeyBytes, PublicKey recipientPublicKey, byte[] aad)
            throws GeneralSecurityException {
        KeyPair ephemeral = generateEcKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ephemeral.getPrivate());
        ka.doPhase(recipientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        byte[] ephemeralPubEncoded = ephemeral.getPublic().getEncoded();
        byte[] recipientPubEncoded = recipientPublicKey.getEncoded();
        byte[] kemTranscript = ByteBuffer.allocate(ephemeralPubEncoded.length + recipientPubEncoded.length)
                .put(ephemeralPubEncoded)
                .put(recipientPubEncoded)
                .array();
        byte[] hkdfSalt = sha256(kemTranscript);

        byte[] wrappingKeyBytes = null;
        try {
            wrappingKeyBytes = hkdfSha256(sharedSecret, hkdfSalt, KEYWRAP_HKDF_INFO, 32);
            SecretKeySpec wrappingKey = new SecretKeySpec(wrappingKeyBytes, "AES");

            byte[] iv = randomBytes(GCM_IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertext = cipher.doFinal(secretKeyBytes);

            ByteBuffer wire = ByteBuffer.allocate(2 + ephemeralPubEncoded.length + GCM_IV_BYTES + ciphertext.length);
            wire.putShort((short) ephemeralPubEncoded.length);
            wire.put(ephemeralPubEncoded);
            wire.put(iv);
            wire.put(ciphertext);
            return Base64.getEncoder().encodeToString(wire.array());
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (wrappingKeyBytes != null) {
                Arrays.fill(wrappingKeyBytes, (byte) 0);
            }
        }
    }

    public static byte[] unwrapSymmetricKey(String wrappedBase64, KeyPair recipientKeyPair, byte[] aad)
            throws GeneralSecurityException {
        return unwrapSymmetricKey(
                wrappedBase64, recipientKeyPair.getPrivate(), recipientKeyPair.getPublic(), aad);
    }

    /**
     * Unwraps an ECIES-wrapped symmetric key and verifies its AES-256-GCM authentication tag + {@code aad}.
     */
    public static byte[] unwrapSymmetricKey(
            String wrappedBase64, PrivateKey recipientPrivateKey, PublicKey recipientPublicKey, byte[] aad)
            throws GeneralSecurityException {
        byte[] wireBytes;
        try {
            wireBytes = Base64.getDecoder().decode(wrappedBase64);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid Base64 in wrapped-key payload", e);
        }
        ByteBuffer wire = ByteBuffer.wrap(wireBytes);
        if (wire.remaining() < 2 + GCM_IV_BYTES + 16) {
            throw new GeneralSecurityException("Truncated wrapped-key payload");
        }
        int pubLen = Short.toUnsignedInt(wire.getShort());
        if (pubLen <= 0 || wire.remaining() < pubLen + GCM_IV_BYTES + 16) {
            throw new GeneralSecurityException("Malformed ephemeral public key length");
        }
        byte[] ephemeralPubEncoded = new byte[pubLen];
        wire.get(ephemeralPubEncoded);
        byte[] iv = new byte[GCM_IV_BYTES];
        wire.get(iv);
        byte[] ciphertext = new byte[wire.remaining()];
        wire.get(ciphertext);

        PublicKey ephemeralPub = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(ephemeralPubEncoded));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(recipientPrivateKey);
        ka.doPhase(ephemeralPub, true);
        byte[] sharedSecret = ka.generateSecret();

        byte[] recipientPubEncoded = recipientPublicKey.getEncoded();
        byte[] kemTranscript = ByteBuffer.allocate(ephemeralPubEncoded.length + recipientPubEncoded.length)
                .put(ephemeralPubEncoded)
                .put(recipientPubEncoded)
                .array();
        byte[] hkdfSalt = sha256(kemTranscript);

        byte[] wrappingKeyBytes = null;
        try {
            wrappingKeyBytes = hkdfSha256(sharedSecret, hkdfSalt, KEYWRAP_HKDF_INFO, 32);
            SecretKeySpec wrappingKey = new SecretKeySpec(wrappingKeyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (wrappingKeyBytes != null) {
                Arrays.fill(wrappingKeyBytes, (byte) 0);
            }
        }
    }
}
