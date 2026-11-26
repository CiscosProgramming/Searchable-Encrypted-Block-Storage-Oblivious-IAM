package io.oblivious.obss;

import io.oblivious.common.Framing;
import io.oblivious.common.KeystoreManager;
import io.oblivious.common.PathSanitizer;
import io.oblivious.common.TlsChannelFactory;
import io.oblivious.oams.OamsClient;
import io.oblivious.oams.Permission;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;

/**
 * Client SDK for the Oblivious Block Storage Server (OBSS) over TLS 1.3.
 *
 * <p>Supports:
 * <ul>
 *   <li>Owner encrypted chunked uploads with runtime-configurable cipher suites
 *       ({@code AES-256-GCM}, {@code ChaCha20-Poly1305}, {@code AES-256-CBC+HMAC-SHA256})</li>
 *   <li>Key-scoped deduplication and AAD-bound block &amp; manifest integrity verification</li>
 *   <li>Trapdoor conjunctive server-side Searchable Encryption for file owners</li>
 *   <li>Manifest-based client-side search &amp; download for authorized OAMS shared recipients,
 *       strictly enforcing {@code READ} vs {@code SEARCH} permission scopes</li>
 * </ul>
 */
public final class ObssClient {

    public record UploadResult(String fileId, int blockCount, CipherMode cipherMode, SecretKey fileKey) {
    }

    private final String host;
    private final int port;
    private final Path obssTlsCertPath;
    private final Path cryptoConfigPath;

    public ObssClient(String host, int port, Path obssTlsCertPath, Path cryptoConfigPath) {
        this.host = host;
        this.port = port;
        this.obssTlsCertPath = obssTlsCertPath;
        this.cryptoConfigPath = cryptoConfigPath;
    }

    public UploadResult putFile(
            Path localFile,
            List<String> rawKeywords,
            Path ownerKeystorePath,
            char[] keystorePassword) throws GeneralSecurityException, IOException {
        if (!Files.isRegularFile(localFile)) {
            throw new IOException("Local file does not exist: " + localFile);
        }
        String fileId = PathSanitizer.sanitizeIdentifier(localFile.getFileName().toString(), "fileId");
        CryptoConfig cfg = CryptoConfig.load(cryptoConfigPath);
        List<String> keywords = BlockCipherEngine.normalizeKeywords(rawKeywords);

        // Reuse existing per-file key on overwrite so deduplication works across re-uploads,
        // or generate a fresh 256-bit key stored exclusively in the owner's PKCS12 keystore
        String keyAlias = OamsClient.ownerKeyAlias(fileId);
        SecretKey fileKey = KeystoreManager.loadSecretKey(ownerKeystorePath, keystorePassword, keyAlias);
        if (fileKey == null) {
            fileKey = BlockCipherEngine.generateFileRootKey();
            KeystoreManager.saveSecretKey(ownerKeystorePath, keystorePassword, keyAlias, fileKey);
        }

        BlockCipherEngine.SearchKeyMaterial seKeys =
                BlockCipherEngine.ensureSearchKeys(ownerKeystorePath, keystorePassword);
        Map<String, byte[]> searchIndex =
                BlockCipherEngine.buildFileSearchIndex(fileId, keywords, seKeys);

        List<String> blockIds = new ArrayList<>();
        try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, obssTlsCertPath);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // 1. Upload trapdoor searchable encryption metadata
            out.writeUTF("STORE_METADATA");
            out.writeInt(searchIndex.size());
            for (Map.Entry<String, byte[]> entry : searchIndex.entrySet()) {
                out.writeUTF(entry.getKey());
                out.writeInt(1);
                Framing.writeBytes(out, entry.getValue());
            }
            out.flush();
            if (!"METADATA_OK".equals(in.readUTF())) {
                throw new IOException("OBSS rejected searchable metadata");
            }

            // 2. Chunk, compute keyed blockId, encrypt with AAD=blockId, and upload blocks
            try (InputStream fileIn = Files.newInputStream(localFile)) {
                byte[] buffer = new byte[cfg.blockSizeBytes()];
                int read;
                while ((read = fileIn.readNBytes(buffer, 0, buffer.length)) > 0) {
                    byte[] chunk = (read == buffer.length) ? buffer : Arrays.copyOf(buffer, read);
                    uploadSingleChunk(chunk, fileKey, cfg.cipherMode(), out, in, blockIds);
                }
                // Handle empty (0-byte) files cleanly with a single empty authenticated block
                if (blockIds.isEmpty()) {
                    uploadSingleChunk(new byte[0], fileKey, cfg.cipherMode(), out, in, blockIds);
                }
            }

            // 3. Seal and upload authenticated per-file manifest
            EncryptedManifest manifest = new EncryptedManifest(fileId, blockIds, keywords);
            byte[] sealedManifest = manifest.seal(fileKey, cfg.cipherMode());
            out.writeUTF("STORE_MANIFEST");
            out.writeUTF(fileId);
            Framing.writeBytes(out, sealedManifest);
            out.flush();
            if (!"OK".equals(in.readUTF())) {
                throw new IOException("OBSS rejected encrypted manifest");
            }

            out.writeUTF("EXIT");
            out.flush();
        }
        return new UploadResult(fileId, blockIds.size(), cfg.cipherMode(), fileKey);
    }

    public void getOwnerFile(
            String fileId,
            Path destinationFile,
            Path ownerKeystorePath,
            char[] keystorePassword) throws GeneralSecurityException, IOException {
        String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
        SecretKey fileKey = KeystoreManager.loadSecretKey(
                ownerKeystorePath, keystorePassword, OamsClient.ownerKeyAlias(safeFileId));
        if (fileKey == null) {
            throw new SecurityException("No owner key found in keystore for file: " + safeFileId);
        }
        downloadAndVerifyFile(safeFileId, fileKey, destinationFile);
    }

    public void getSharedFile(
            String fileId,
            Path destinationFile,
            Path guestKeystorePath,
            char[] keystorePassword) throws GeneralSecurityException, IOException {
        String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
        SecretKey fileKey = loadAnySharedFileKey(guestKeystorePath, keystorePassword, safeFileId);
        if (fileKey == null) {
            throw new SecurityException("No shared access key found in keystore for file: " + safeFileId);
        }
        downloadAndVerifyFile(safeFileId, fileKey, destinationFile);
    }

    public void downloadAndVerifyFile(String safeFileId, SecretKey fileKey, Path destinationFile)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream reconstructed = new ByteArrayOutputStream();
        try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, obssTlsCertPath);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {

            EncryptedManifest manifest = fetchAndOpenManifest(safeFileId, fileKey, out, in);
            for (String blockId : manifest.blockIds()) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();

                int len = in.readInt();
                if (len < 0 || len > Framing.MAX_FRAME_BYTES) {
                    throw new IOException("Missing or invalid block on server: " + blockId);
                }
                byte[] cipherBlock = new byte[len];
                in.readFully(cipherBlock);

                byte[] plainChunk = BlockCipherEngine.decrypt(cipherBlock, fileKey, blockAad(blockId));
                // Verify content hash matches keyed blockId as defense-in-depth
                String recomputedId = BlockCipherEngine.computeKeyedBlockId(plainChunk, fileKey);
                if (!blockId.equals(recomputedId)) {
                    throw new SecurityException("Block content/ID mismatch detected on block " + blockId);
                }
                reconstructed.write(plainChunk);
            }
            out.writeUTF("EXIT");
            out.flush();
        }
        Framing.writeFileAtomically(destinationFile, reconstructed.toByteArray());
    }

    /**
     * Verifies cryptographic authenticity and integrity of all remote blocks and the manifest
     * for {@code fileId} without writing plaintext to disk ({@code GET CHECKINTEGRITY}).
     */
    public boolean verifyFileIntegrity(
            String fileId, Path keystorePath, char[] keystorePassword) {
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
            SecretKey fileKey = KeystoreManager.loadSecretKey(
                    keystorePath, keystorePassword, OamsClient.ownerKeyAlias(safeFileId));
            if (fileKey == null) {
                fileKey = loadAnySharedFileKey(keystorePath, keystorePassword, safeFileId);
            }
            if (fileKey == null) {
                return false;
            }
            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, obssTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                EncryptedManifest manifest = fetchAndOpenManifest(safeFileId, fileKey, out, in);
                for (String blockId : manifest.blockIds()) {
                    out.writeUTF("GET_BLOCK");
                    out.writeUTF(blockId);
                    out.flush();
                    int len = in.readInt();
                    if (len < 0 || len > Framing.MAX_FRAME_BYTES) {
                        return false;
                    }
                    byte[] cipherBlock = new byte[len];
                    in.readFully(cipherBlock);
                    byte[] plain = BlockCipherEngine.decrypt(cipherBlock, fileKey, blockAad(blockId));
                    if (!blockId.equals(BlockCipherEngine.computeKeyedBlockId(plain, fileKey))) {
                        return false;
                    }
                }
                out.writeUTF("EXIT");
                out.flush();
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Executes conjunctive trapdoor Searchable Encryption on OBSS for owner files.
     */
    public List<String> searchOwnerFiles(
            List<String> rawKeywords, Path ownerKeystorePath, char[] keystorePassword)
            throws GeneralSecurityException, IOException {
        List<String> keywords = BlockCipherEngine.normalizeKeywords(rawKeywords);
        if (keywords.isEmpty()) {
            return List.of();
        }
        BlockCipherEngine.SearchKeyMaterial seKeys =
                BlockCipherEngine.ensureSearchKeys(ownerKeystorePath, keystorePassword);
        List<String> trapdoors = new ArrayList<>(keywords.size());
        for (String kw : keywords) {
            trapdoors.add(BlockCipherEngine.computeKeywordTrapdoor(seKeys.prfKey(), kw));
        }

        Set<String> matchedFiles = new LinkedHashSet<>();
        try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, obssTlsCertPath);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {
            out.writeUTF("SEARCH");
            out.writeInt(trapdoors.size());
            for (String td : trapdoors) {
                out.writeUTF(td);
            }
            out.flush();

            int resultCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            for (int i = 0; i < resultCount; i++) {
                byte[] encFileId = Framing.readBoundedBytes(in, 4096);
                try {
                    matchedFiles.add(BlockCipherEngine.decryptSearchResultFileId(encFileId, seKeys));
                } catch (GeneralSecurityException otherTenantEntry) {
                    // Ignore entries belonging to another user's key if trapdoors ever collided
                }
            }
            out.writeUTF("EXIT");
            out.flush();
        }
        return List.copyOf(matchedFiles);
    }

    /**
     * Client-side conjunctive keyword search across shared files for which the recipient
     * explicitly holds {@link Permission#SEARCH} in their keystore ({@code READ}-only grants
     * are excluded).
     */
    public List<String> searchSharedFiles(
            List<String> rawKeywords, Path guestKeystorePath, char[] keystorePassword)
            throws GeneralSecurityException, IOException {
        List<String> queryKeywords = BlockCipherEngine.normalizeKeywords(rawKeywords);
        if (queryKeywords.isEmpty()) {
            return List.of();
        }
        String searchPrefix = OamsClient.SHARED_FILE_KEY_PREFIX
                + Permission.SEARCH.name().toLowerCase(Locale.ROOT) + ":";
        List<String> searchableAliases =
                KeystoreManager.listAliasesWithPrefix(guestKeystorePath, keystorePassword, searchPrefix);
        if (searchableAliases.isEmpty()) {
            return List.of();
        }

        List<String> matches = new ArrayList<>();
        try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, obssTlsCertPath);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {
            for (String alias : searchableAliases) {
                String fileId = OamsClient.decodeFileIdFromAliasSuffix(alias.substring(searchPrefix.length()));
                SecretKey fileKey = KeystoreManager.loadSecretKey(guestKeystorePath, keystorePassword, alias);
                if (fileKey == null) {
                    continue;
                }
                try {
                    EncryptedManifest manifest = fetchAndOpenManifest(fileId, fileKey, out, in);
                    if (manifest.keywords().containsAll(queryKeywords)) {
                        matches.add(fileId);
                    }
                } catch (Exception ignored) {
                }
            }
            out.writeUTF("EXIT");
            out.flush();
        }
        return matches;
    }

    public List<String> listOwnerFiles(Path ownerKeystorePath, char[] keystorePassword)
            throws GeneralSecurityException, IOException {
        List<String> aliases = KeystoreManager.listAliasesWithPrefix(
                ownerKeystorePath, keystorePassword, OamsClient.OWNER_FILE_KEY_PREFIX);
        List<String> files = new ArrayList<>(aliases.size());
        for (String alias : aliases) {
            files.add(OamsClient.decodeFileIdFromAliasSuffix(
                    alias.substring(OamsClient.OWNER_FILE_KEY_PREFIX.length())));
        }
        return files;
    }

    private void uploadSingleChunk(
            byte[] chunk,
            SecretKey fileKey,
            CipherMode mode,
            DataOutputStream out,
            DataInputStream in,
            List<String> blockIds) throws GeneralSecurityException, IOException {
        String blockId = BlockCipherEngine.computeKeyedBlockId(chunk, fileKey);
        byte[] encryptedBlock = BlockCipherEngine.encrypt(chunk, fileKey, mode, blockAad(blockId));
        out.writeUTF("STORE_BLOCK");
        out.writeUTF(blockId);
        Framing.writeBytes(out, encryptedBlock);
        out.flush();
        if (!"OK".equals(in.readUTF())) {
            throw new IOException("OBSS failed to store block " + blockId);
        }
        blockIds.add(blockId);
    }

    private EncryptedManifest fetchAndOpenManifest(
            String safeFileId, SecretKey fileKey, DataOutputStream out, DataInputStream in)
            throws GeneralSecurityException, IOException {
        out.writeUTF("GET_MANIFEST");
        out.writeUTF(safeFileId);
        out.flush();
        if (!"OK".equals(in.readUTF())) {
            throw new IOException("Manifest not found on OBSS for file: " + safeFileId);
        }
        byte[] sealedManifest = Framing.readBoundedBytes(in, Framing.MAX_FRAME_BYTES);
        return EncryptedManifest.open(safeFileId, sealedManifest, fileKey);
    }

    private static SecretKey loadAnySharedFileKey(
            Path keystorePath, char[] password, String safeFileId)
            throws GeneralSecurityException, IOException {
        SecretKey searchGrant = KeystoreManager.loadSecretKey(
                keystorePath, password, OamsClient.sharedKeyAlias(safeFileId, Permission.SEARCH));
        if (searchGrant != null) {
            return searchGrant;
        }
        return KeystoreManager.loadSecretKey(
                keystorePath, password, OamsClient.sharedKeyAlias(safeFileId, Permission.READ));
    }

    private static byte[] blockAad(String blockId) {
        return ("OBSS-BLOCK|" + blockId).getBytes(StandardCharsets.UTF_8);
    }
}
