package io.oblivious;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.JwtService;
import io.oblivious.common.KeystoreManager;
import io.oblivious.common.PathSanitizer;
import io.oblivious.obss.BlockCipherEngine;
import io.oblivious.obss.CipherMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class CryptoPrimitivesTest {

    @Test
    void ecdsaDerAndP1363SignVerifyAndTamperRejection() throws Exception {
        KeyPair kp = CryptoPrimitives.generateEcKeyPair();
        byte[] msg = "challenge-nonce-12345".getBytes(StandardCharsets.UTF_8);

        byte[] derSig = CryptoPrimitives.signEcdsa(kp.getPrivate(), msg);
        assertTrue(CryptoPrimitives.verifyEcdsa(kp.getPublic(), msg, derSig));
        assertFalse(CryptoPrimitives.verifyEcdsa(kp.getPublic(), "tampered".getBytes(StandardCharsets.UTF_8), derSig));

        byte[] p1363Sig = CryptoPrimitives.signEcdsaP1363(kp.getPrivate(), msg);
        assertEquals(64, p1363Sig.length, "RFC 7515 ES256 requires 64-byte IEEE P1363 R||S signature");
        assertTrue(CryptoPrimitives.verifyEcdsaP1363(kp.getPublic(), msg, p1363Sig));

        p1363Sig[10] ^= 0x01;
        assertFalse(CryptoPrimitives.verifyEcdsaP1363(kp.getPublic(), msg, p1363Sig));
    }

    @Test
    void eciesKeyWrapUnwrapAndCrossFileAadSubstitutionRejection() throws Exception {
        KeyPair bob = CryptoPrimitives.generateEcKeyPair();
        KeyPair mallory = CryptoPrimitives.generateEcKeyPair();
        SecretKey fileKey = BlockCipherEngine.generateFileRootKey();

        byte[] aadFileA = "OAMS-WRAP|report.pdf|READ".getBytes(StandardCharsets.UTF_8);
        byte[] aadFileB = "OAMS-WRAP|salaries.xlsx|READ".getBytes(StandardCharsets.UTF_8);
        byte[] aadEscalated = "OAMS-WRAP|report.pdf|SEARCH".getBytes(StandardCharsets.UTF_8);

        String wrapped1 = CryptoPrimitives.wrapSymmetricKey(fileKey.getEncoded(), bob.getPublic(), aadFileA);
        String wrapped2 = CryptoPrimitives.wrapSymmetricKey(fileKey.getEncoded(), bob.getPublic(), aadFileA);
        assertNotEquals(wrapped1, wrapped2, "Ephemeral ECDH + random GCM IV must be probabilistic (IND-CCA2)");

        byte[] unwrapped = CryptoPrimitives.unwrapSymmetricKey(wrapped1, bob, aadFileA);
        assertArrayEquals(fileKey.getEncoded(), unwrapped);

        // Cross-resource AAD swap or permission escalation must fail AEAD authentication
        assertThrows(GeneralSecurityException.class,
                () -> CryptoPrimitives.unwrapSymmetricKey(wrapped1, bob, aadFileB));
        assertThrows(GeneralSecurityException.class,
                () -> CryptoPrimitives.unwrapSymmetricKey(wrapped1, bob, aadEscalated));
        assertThrows(GeneralSecurityException.class,
                () -> CryptoPrimitives.unwrapSymmetricKey(wrapped1, mallory, aadFileA));
    }

    @Test
    void es256JwtIssuanceVerificationExpirationAndAlgNoneRejection() throws Exception {
        KeyPair oasKeys = CryptoPrimitives.generateEcKeyPair();
        KeyPair attackerKeys = CryptoPrimitives.generateEcKeyPair();
        String anonId = CryptoPrimitives.encodePublicKey(CryptoPrimitives.generateEcKeyPair().getPublic());

        String jwt = JwtService.issueToken(oasKeys.getPrivate(), anonId, 600);
        JwtService.VerifiedClaims claims = JwtService.verifyToken(oasKeys.getPublic(), jwt);
        assertNotNull(claims);
        assertEquals(anonId, claims.subject());

        // Expired token rejected
        long future = Instant.now().getEpochSecond() + 601;
        assertNull(JwtService.verifyTokenAt(oasKeys.getPublic(), jwt, future));

        // Wrong issuer key rejected
        assertNull(JwtService.verifyToken(attackerKeys.getPublic(), jwt));

        // alg:none downgrade attack rejected
        String noneHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String[] parts = jwt.split("\\.");
        assertNull(JwtService.verifyToken(oasKeys.getPublic(), noneHeader + "." + parts[1] + "." + parts[2]));
    }

    @Test
    void pbkdf2SaltedPepperedVerifierAndConstantTimeCheck() {
        String preHash = CryptoPrimitives.preHashPassword("CorrectHorseBatteryStaple!".toCharArray());
        byte[] salt1 = CryptoPrimitives.generateSalt();
        byte[] salt2 = CryptoPrimitives.generateSalt();

        String v1 = CryptoPrimitives.derivePasswordVerifier(preHash, "pepper-A", salt1, 10_000);
        String v1Repeat = CryptoPrimitives.derivePasswordVerifier(preHash, "pepper-A", salt1, 10_000);
        String vDifferentSalt = CryptoPrimitives.derivePasswordVerifier(preHash, "pepper-A", salt2, 10_000);
        String vDifferentPepper = CryptoPrimitives.derivePasswordVerifier(preHash, "pepper-B", salt1, 10_000);

        assertTrue(CryptoPrimitives.constantTimeEquals(v1, v1Repeat));
        assertFalse(CryptoPrimitives.constantTimeEquals(v1, vDifferentSalt));
        assertFalse(CryptoPrimitives.constantTimeEquals(v1, vDifferentPepper));
    }

    @ParameterizedTest
    @EnumSource(CipherMode.class)
    void allCipherModesRoundTripAndRejectBitFlipsAndBlockSwaps(CipherMode mode) throws Exception {
        SecretKey fileKey = BlockCipherEngine.generateFileRootKey();
        byte[] plaintext = "Confidential multi-cipher payload block #0".getBytes(StandardCharsets.UTF_8);
        byte[] aadBlock0 = "OBSS-BLOCK|0".getBytes(StandardCharsets.UTF_8);
        byte[] aadBlock1 = "OBSS-BLOCK|1".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = BlockCipherEngine.encrypt(plaintext, fileKey, mode, aadBlock0);
        assertArrayEquals(plaintext, BlockCipherEngine.decrypt(encrypted, fileKey, aadBlock0));

        // Server block-swap attack (valid ciphertext replayed under a different block ID AAD)
        assertThrows(Exception.class, () -> BlockCipherEngine.decrypt(encrypted, fileKey, aadBlock1));

        // Ciphertext/tag 1-bit corruption rejected before releasing plaintext
        byte[] corrupted = encrypted.clone();
        corrupted[corrupted.length - 3] ^= 0x04;
        assertThrows(Exception.class, () -> BlockCipherEngine.decrypt(corrupted, fileKey, aadBlock0));
    }

    @Test
    void keyScopedDeduplicationMatchesSameKeyAndIsolatesDistinctKeys() throws Exception {
        SecretKey keyA = BlockCipherEngine.generateFileRootKey();
        SecretKey keyB = BlockCipherEngine.generateFileRootKey();
        byte[] chunk = "identical-4k-header".getBytes(StandardCharsets.UTF_8);

        String idA1 = BlockCipherEngine.computeKeyedBlockId(chunk, keyA);
        String idA2 = BlockCipherEngine.computeKeyedBlockId(chunk, keyA);
        String idB = BlockCipherEngine.computeKeyedBlockId(chunk, keyB);

        assertEquals(idA1, idA2, "Same key + same chunk must deduplicate deterministically");
        assertNotEquals(idA1, idB, "Distinct file keys must never collide or leak block existence across tenants");
    }

    @Test
    void pkcs12KeystoreStoresBothEcKeyPairsAndSecretKeys(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("vault.p12");
        char[] pwd = "VaultPassword#2026".toCharArray();

        KeyPair ecPair = CryptoPrimitives.generateEcKeyPair();
        SecretKey aesKey = BlockCipherEngine.generateFileRootKey();

        KeystoreManager.saveKeyPair(ksPath, pwd, "identity", ecPair, "alice");
        KeystoreManager.saveSecretKey(ksPath, pwd, "owner-file-key:doc.pdf", aesKey);

        KeyPair loadedPair = KeystoreManager.loadKeyPair(ksPath, pwd, "identity");
        SecretKey loadedSecret = KeystoreManager.loadSecretKey(ksPath, pwd, "owner-file-key:doc.pdf");

        assertNotNull(loadedPair);
        assertNotNull(loadedSecret);
        assertArrayEquals(ecPair.getPublic().getEncoded(), loadedPair.getPublic().getEncoded());
        assertArrayEquals(aesKey.getEncoded(), loadedSecret.getEncoded());

        // Wrong password rejected
        assertThrows(Exception.class,
                () -> KeystoreManager.loadSecretKey(ksPath, "wrong".toCharArray(), "owner-file-key:doc.pdf"));
    }

    @Test
    void pathSanitizerBlocksTraversalNullBytesAndSeparators(@TempDir Path tempDir) {
        assertEquals("report_2026.pdf", PathSanitizer.sanitizeIdentifier("report_2026.pdf", "fileId"));
        assertThrows(SecurityException.class, () -> PathSanitizer.sanitizeIdentifier("../etc/passwd", "fileId"));
        assertThrows(SecurityException.class, () -> PathSanitizer.sanitizeIdentifier("..\\secret", "fileId"));
        assertThrows(SecurityException.class, () -> PathSanitizer.sanitizeIdentifier("sub/file.txt", "fileId"));
        assertThrows(SecurityException.class, () -> PathSanitizer.sanitizeIdentifier("file\0.txt", "fileId"));
        assertThrows(SecurityException.class, () -> PathSanitizer.resolveSafeChild(tempDir, "..", "fileId"));
    }
}
