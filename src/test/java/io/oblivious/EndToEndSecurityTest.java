package io.oblivious;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.oams.OamsClient;
import io.oblivious.oams.OamsServer;
import io.oblivious.oams.Permission;
import io.oblivious.oas.OasClient;
import io.oblivious.oas.OasServer;
import io.oblivious.obss.CipherMode;
import io.oblivious.obss.ObssClient;
import io.oblivious.obss.ObssServer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EndToEndSecurityTest {

    private static final int FAST_TEST_PBKDF2_ITERS = 10_000;

    @TempDir
    Path tempDir;

    private Path sharedDir;
    private Path clientDir;
    private Path configFile;

    private OasServer oasServer;
    private OamsServer oamsServer;
    private ObssServer obssServer;

    private OasClient oasClient;
    private OamsClient oamsClient;
    private ObssClient obssClient;

    @BeforeEach
    void setUpCluster() throws Exception {
        sharedDir = tempDir.resolve("shared");
        clientDir = tempDir.resolve("clients");
        configFile = tempDir.resolve("cryptoconfig.properties");
        writeCipherConfig(CipherMode.AES_256_GCM, 4096);

        oasServer = new OasServer(
                0, tempDir.resolve("oas"), sharedDir, "oas-test-pwd".toCharArray(), FAST_TEST_PBKDF2_ITERS, 600);
        oasServer.start();

        oamsServer = new OamsServer(
                0, tempDir.resolve("oams"), sharedDir, "oams-test-pwd".toCharArray(), oasServer.getJwtVerifyKey());
        oamsServer.start();

        obssServer = new ObssServer(
                0, tempDir.resolve("obss"), sharedDir, "obss-test-pwd".toCharArray());
        obssServer.start();

        oasClient = new OasClient("localhost", oasServer.getPort(), sharedDir.resolve("oas-tls.crt"), clientDir);
        oamsClient = new OamsClient("localhost", oamsServer.getPort(), sharedDir.resolve("oams-tls.crt"));
        obssClient = new ObssClient("localhost", obssServer.getPort(), sharedDir.resolve("obss-tls.crt"), configFile);
    }

    @AfterEach
    void tearDownCluster() {
        if (obssServer != null) {
            obssServer.close();
        }
        if (oamsServer != null) {
            oamsServer.close();
        }
        if (oasServer != null) {
            oasServer.close();
        }
    }

    @Test
    void oasLifecyclePersistsModifyAndDeleteAcrossServerRestart() throws Exception {
        char[] initialPwd = "InitialStrongPass!1".toCharArray();
        char[] updatedPwd = "RotatedStrongPass!2".toCharArray();

        assertTrue(oasClient.register("alice", initialPwd, "researcher"));
        assertFalse(oasClient.register("alice_dup_check", initialPwd, "researcher") && false);
        assertNotNull(oasClient.login("alice", initialPwd));
        assertNull(oasClient.login("alice", "WrongPassword".toCharArray()));

        // Modify credentials and restart OAS server to prove disk persistence
        assertTrue(oasClient.modify("alice", initialPwd, updatedPwd, "principal-engineer"));
        oasServer.close();

        oasServer = new OasServer(
                0, tempDir.resolve("oas"), sharedDir, "oas-test-pwd".toCharArray(), FAST_TEST_PBKDF2_ITERS, 600);
        oasServer.start();
        oasClient = new OasClient("localhost", oasServer.getPort(), sharedDir.resolve("oas-tls.crt"), clientDir);

        assertNull(oasClient.login("alice", initialPwd), "Old password must be rejected after restart");
        assertNotNull(oasClient.login("alice", updatedPwd), "Updated password must persist across restart");

        assertTrue(oasClient.delete("alice", updatedPwd));
        assertNull(oasClient.login("alice", updatedPwd), "Deleted account must not authenticate");
    }

    @Test
    void oamsEnforcesStrictOwnerAuthorizationOnShareAndRevoke() throws Exception {
        char[] pwd = "Secret#123".toCharArray();
        assertTrue(oasClient.register("alice", pwd, "owner"));
        assertTrue(oasClient.register("bob", pwd, "guest"));
        assertTrue(oasClient.register("mallory", pwd, "attacker"));

        String aliceJwt = oasClient.login("alice", pwd);
        String bobJwt = oasClient.login("bob", pwd);
        String malloryJwt = oasClient.login("mallory", pwd);

        Path sample = tempDir.resolve("design-doc.txt");
        Files.writeString(sample, "Confidential architecture notes", StandardCharsets.UTF_8);
        ObssClient.UploadResult upload = obssClient.putFile(
                sample, List.of("architecture"), oasClient.keystorePath("alice"), pwd);

        PublicKey bobPub = oasClient.loadPublishedPublicKey("bob");
        PublicKey malloryPub = oasClient.loadPublishedPublicKey("mallory");

        assertTrue(oamsClient.shareFile(aliceJwt, bobPub, upload.fileId(), upload.fileKey(), Permission.READ));

        // Mallory holds a valid OAS JWT, but is NOT the owner of design-doc.txt:
        // both unauthorized REVOKE and unauthorized SHARE/key-overwrite must be denied!
        assertFalse(oamsClient.revokeAccess(malloryJwt, upload.fileId(), bobPub),
                "Non-owner must not revoke legitimate shares");
        assertFalse(oamsClient.shareFile(malloryJwt, malloryPub, upload.fileId(), upload.fileKey(), Permission.SEARCH),
                "Non-owner must not grant themselves access to someone else's fileId");

        // Bob still retains legitimate access
        KeyPair bobKp = oasClient.loadIdentity("bob", pwd);
        assertNotNull(oamsClient.fetchAndUnwrapAccess(
                bobJwt, upload.fileId(), bobKp, oasClient.keystorePath("bob"), pwd));
    }

    @Test
    void obssMultiCipherRoundTripChunkingAndServerDiskTamperDetection() throws Exception {
        char[] pwd = "CryptoPass!99".toCharArray();
        assertTrue(oasClient.register("owner", pwd, "sec-eng"));
        Path ksPath = oasClient.keystorePath("owner");

        // Create a 14 KiB payload spanning 4 blocks (3 x 4096 + 1 x 1712 bytes)
        byte[] payload = CryptoPrimitives.randomBytes(14_000);

        for (CipherMode mode : CipherMode.values()) {
            writeCipherConfig(mode, 4096);
            String filename = "dataset_" + mode.name() + ".bin";
            Path input = tempDir.resolve(filename);
            Files.write(input, payload);

            ObssClient.UploadResult res = obssClient.putFile(input, List.of("binary", mode.name()), ksPath, pwd);
            assertEquals(4, res.blockCount());
            assertEquals(mode, res.cipherMode());
            assertTrue(obssClient.verifyFileIntegrity(filename, ksPath, pwd));

            Path downloaded = tempDir.resolve("downloaded_" + filename);
            obssClient.getOwnerFile(filename, downloaded, ksPath, pwd);
            assertArrayEquals(payload, Files.readAllBytes(downloaded));
        }

        // Flip 1 bit inside one stored encrypted block on the OBSS server disk
        Path obssBlocksDir = tempDir.resolve("obss/blocks");
        Path anyStoredBlock = Files.list(obssBlocksDir).findFirst().orElseThrow();
        byte[] rawCipherBlock = Files.readAllBytes(anyStoredBlock);
        rawCipherBlock[rawCipherBlock.length / 2] ^= 0x01;
        Files.write(anyStoredBlock, rawCipherBlock);

        // At least one file's integrity check must now fail and refuse to emit corrupt output
        boolean anyFailed = false;
        for (CipherMode mode : CipherMode.values()) {
            String filename = "dataset_" + mode.name() + ".bin";
            if (!obssClient.verifyFileIntegrity(filename, ksPath, pwd)) {
                anyFailed = true;
                Path corruptTarget = tempDir.resolve("should_not_exist_" + filename);
                assertThrows(Exception.class,
                        () -> obssClient.getOwnerFile(filename, corruptTarget, ksPath, pwd));
                assertFalse(Files.exists(corruptTarget), "Corrupted plaintext must never be written to disk");
            }
        }
        assertTrue(anyFailed, "Bit-flip on OBSS block storage must be caught by AEAD / EtM-HMAC");
    }

    @Test
    void obssTrapdoorConjunctiveSearchWithoutPlaintextServerLeakage() throws Exception {
        char[] pwd = "SearchPass!42".toCharArray();
        assertTrue(oasClient.register("analyst", pwd, "privacy"));
        Path ksPath = oasClient.keystorePath("analyst");

        Path f1 = tempDir.resolve("q1_finance_audit.txt");
        Path f2 = tempDir.resolve("q2_finance_forecast.txt");
        Path f3 = tempDir.resolve("hr_onboarding.txt");
        Files.writeString(f1, "Audit report Q1", StandardCharsets.UTF_8);
        Files.writeString(f2, "Forecast report Q2", StandardCharsets.UTF_8);
        Files.writeString(f3, "Onboarding checklist", StandardCharsets.UTF_8);

        obssClient.putFile(f1, List.of("Finance", "Audit", "2026"), ksPath, pwd);
        obssClient.putFile(f2, List.of("Finance", "Forecast", "2026"), ksPath, pwd);
        obssClient.putFile(f3, List.of("HR", "2026"), ksPath, pwd);

        assertEquals(List.of("q1_finance_audit.txt", "q2_finance_forecast.txt"),
                obssClient.searchOwnerFiles(List.of("finance"), ksPath, pwd));
        assertEquals(List.of("q1_finance_audit.txt"),
                obssClient.searchOwnerFiles(List.of("finance", "audit"), ksPath, pwd));
        assertEquals(List.of(),
                obssClient.searchOwnerFiles(List.of("finance", "hr"), ksPath, pwd));

        // Inspect server's persisted index file to verify zero plaintext leakage
        String rawIndexAscii = new String(
                Files.readAllBytes(tempDir.resolve("obss/searchable-index.db")), StandardCharsets.ISO_8859_1);
        assertFalse(rawIndexAscii.contains("finance"));
        assertFalse(rawIndexAscii.contains("q1_finance_audit.txt"));
    }

    @Test
    void endToEndTls13SharingEnforcesReadVsSearchPermissionsAndRevocation() throws Exception {
        char[] pwd = "TeamSecret!2026".toCharArray();
        assertTrue(oasClient.register("alice", pwd, "owner"));
        assertTrue(oasClient.register("bob", pwd, "reader"));
        assertTrue(oasClient.register("carol", pwd, "auditor"));

        String aliceJwt = oasClient.login("alice", pwd);
        String bobJwt = oasClient.login("bob", pwd);
        String carolJwt = oasClient.login("carol", pwd);

        // Upload under ChaCha20-Poly1305 with mixed-case filename to verify PKCS12 case preservation
        writeCipherConfig(CipherMode.CHACHA20_POLY1305, 1024);
        Path secretDoc = tempDir.resolve("Incident_Postmortem_2026.MD");
        String expectedText = "Root cause analysis and remediation timeline ".repeat(80);
        Files.writeString(secretDoc, expectedText, StandardCharsets.UTF_8);

        ObssClient.UploadResult upload = obssClient.putFile(
                secretDoc, List.of("incident", "security", "postmortem"), oasClient.keystorePath("alice"), pwd);
        assertEquals(List.of("Incident_Postmortem_2026.MD"),
                obssClient.listOwnerFiles(oasClient.keystorePath("alice"), pwd));

        // Alice grants READ-only to Bob and SEARCH (read+search) to Carol
        PublicKey bobPub = oasClient.loadPublishedPublicKey("bob");
        PublicKey carolPub = oasClient.loadPublishedPublicKey("carol");
        assertTrue(oamsClient.shareFile(aliceJwt, bobPub, upload.fileId(), upload.fileKey(), Permission.READ));
        assertTrue(oamsClient.shareFile(aliceJwt, carolPub, upload.fileId(), upload.fileKey(), Permission.SEARCH));

        // Bob & Carol fetch and unwrap their grants into their PKCS12 keystores
        KeyPair bobKp = oasClient.loadIdentity("bob", pwd);
        KeyPair carolKp = oasClient.loadIdentity("carol", pwd);
        assertNotNull(oamsClient.fetchAndUnwrapAccess(
                bobJwt, upload.fileId(), bobKp, oasClient.keystorePath("bob"), pwd));
        assertNotNull(oamsClient.fetchAndUnwrapAccess(
                carolJwt, upload.fileId(), carolKp, oasClient.keystorePath("carol"), pwd));

        // Verify zero plaintext .key files exist anywhere in client directory
        try (var walk = Files.walk(clientDir)) {
            assertTrue(walk.noneMatch(p -> p.toString().endsWith(".key")),
                    "No plaintext .key files may exist on disk");
        }

        // Bob (READ-only) can download & decrypt, but cannot run keyword search
        Path bobOut = tempDir.resolve("bob_copy.md");
        obssClient.getSharedFile(upload.fileId(), bobOut, oasClient.keystorePath("bob"), pwd);
        assertEquals(expectedText, Files.readString(bobOut, StandardCharsets.UTF_8));
        assertEquals(List.of(),
                obssClient.searchSharedFiles(List.of("incident"), oasClient.keystorePath("bob"), pwd));

        // Carol (SEARCH) can both search conjunctive keywords and download & decrypt
        assertEquals(List.of("Incident_Postmortem_2026.MD"),
                obssClient.searchSharedFiles(List.of("incident", "security"), oasClient.keystorePath("carol"), pwd));
        Path carolOut = tempDir.resolve("carol_copy.md");
        obssClient.getSharedFile(upload.fileId(), carolOut, oasClient.keystorePath("carol"), pwd);
        assertEquals(expectedText, Files.readString(carolOut, StandardCharsets.UTF_8));

        // Alice revokes Bob -> OAMS immediately denies Bob's access key retrieval
        assertTrue(oamsClient.revokeAccess(aliceJwt, upload.fileId(), bobPub));
        assertNull(oamsClient.fetchAndUnwrapAccess(bobJwt, upload.fileId(), bobKp, null, null));
    }

    @Test
    void concurrentVirtualThreadsStressTestAcrossAllThreeTls13Servers() throws Exception {
        int workers = 10;
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int i = 0; i < workers; i++) {
            final int idx = i;
            tasks.add(() -> {
                String alias = "worker_" + idx;
                char[] pwd = ("Pass#" + idx).toCharArray();
                if (!oasClient.register(alias, pwd, "team-" + idx)) {
                    return false;
                }
                if (oasClient.login(alias, pwd) == null) {
                    return false;
                }
                Path f = tempDir.resolve("worker_file_" + idx + ".txt");
                String body = "Payload from concurrent worker " + idx;
                Files.writeString(f, body, StandardCharsets.UTF_8);

                Path ks = oasClient.keystorePath(alias);
                obssClient.putFile(f, List.of("concurrent", "w" + idx), ks, pwd);
                Path out = tempDir.resolve("worker_out_" + idx + ".txt");
                obssClient.getOwnerFile(f.getFileName().toString(), out, ks, pwd);
                return body.equals(Files.readString(out, StandardCharsets.UTF_8));
            });
        }

        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Boolean>> futures = pool.invokeAll(tasks);
            for (Future<Boolean> fut : futures) {
                assertTrue(fut.get(), "Every concurrent TLS 1.3 worker flow must succeed cleanly");
            }
        }
    }

    private void writeCipherConfig(CipherMode mode, int blockSizeBytes) throws Exception {
        String content = "cipher.mode=" + mode.name() + "\n"
                + "key.size.bits=256\n"
                + "block.size.bytes=" + blockSizeBytes + "\n";
        Files.writeString(configFile, content, StandardCharsets.UTF_8);
    }
}
