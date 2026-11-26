package io.oblivious.obss;

import io.oblivious.common.Framing;
import io.oblivious.common.PathSanitizer;
import io.oblivious.common.TlsChannelFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Stream;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Honest-but-Curious Oblivious Block Storage Server (OBSS) over TLS 1.3.
 *
 * <p>Stores opaque encrypted 4 KiB blocks, opaque encrypted file manifests, and trapdoor
 * searchable encryption postings without ever learning plaintext data, filenames,
 * keywords, or user identities.
 */
public final class ObssServer implements AutoCloseable {

    public static final int DEFAULT_PORT = 5000;
    private static final byte[] META_MAGIC = "OBSSMD01".getBytes(StandardCharsets.US_ASCII);

    private final int configuredPort;
    private final Path dataDir;
    private final Path sharedTrustDir;
    private final char[] keystorePassword;

    private Path blockDir;
    private Path manifestDir;
    private Path metadataFile;

    private final Map<String, Set<String>> trapdoorIndex = new HashMap<>();
    private final ReentrantReadWriteLock indexLock = new ReentrantReadWriteLock();

    private X509Certificate tlsCertificate;
    private SSLServerSocket serverSocket;
    private ExecutorService clientExecutor;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public ObssServer(int port, Path dataDir, Path sharedTrustDir, char[] keystorePassword) {
        this.configuredPort = port;
        this.dataDir = dataDir;
        this.sharedTrustDir = sharedTrustDir;
        this.keystorePassword = keystorePassword.clone();
    }

    public void start() throws GeneralSecurityException, IOException {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        this.blockDir = dataDir.resolve("blocks");
        this.manifestDir = dataDir.resolve("manifests");
        this.metadataFile = dataDir.resolve("searchable-index.db");
        Files.createDirectories(blockDir);
        Files.createDirectories(manifestDir);
        loadMetadataIndex();

        Path keystorePath = dataDir.resolve("obss-server.p12");
        this.tlsCertificate = TlsChannelFactory.ensureServerTlsMaterial(
                keystorePath, keystorePassword, "tls-server", "localhost",
                sharedTrustDir.resolve("obss-tls.crt"));
        this.serverSocket = TlsChannelFactory.createServerSocket(configuredPort, keystorePath, keystorePassword);
        this.clientExecutor = Executors.newVirtualThreadPerTaskExecutor();
        this.acceptThread = Thread.ofPlatform().name("obss-acceptor").daemon(true).start(this::acceptLoop);
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public X509Certificate getTlsCertificate() {
        return tlsCertificate;
    }

    /** Exposed for security tamper tests verifying client-side AEAD / EtM-HMAC detection. */
    public Path resolveStoredBlockPath(String blockId) {
        return PathSanitizer.resolveSafeChild(blockDir, blockId, "blockId");
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                clientExecutor.submit(() -> handleConnection(socket));
            } catch (SocketException closed) {
                if (running.get()) {
                    System.err.println("[OBSS] Socket accept error: " + closed.getMessage());
                }
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("[OBSS] Accept I/O error: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(SSLSocket socket) {
        try (socket;
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            socket.setSoTimeout(30_000);
            while (running.get()) {
                String command;
                try {
                    command = in.readUTF();
                } catch (IOException eof) {
                    return;
                }
                switch (command) {
                    case "STORE_METADATA" -> handleStoreMetadata(in, out);
                    case "STORE_BLOCK" -> handleStoreBlock(in, out);
                    case "GET_BLOCK" -> handleGetBlock(in, out);
                    case "LIST_BLOCKS" -> handleListBlocks(out);
                    case "SEARCH" -> handleSearch(in, out);
                    case "STORE_MANIFEST" -> handleStoreManifest(in, out);
                    case "GET_MANIFEST" -> handleGetManifest(in, out);
                    case "EXIT" -> {
                        return;
                    }
                    default -> {
                        out.writeUTF("NOK");
                        out.flush();
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void handleStoreMetadata(DataInputStream in, DataOutputStream out) throws IOException {
        int entryCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
        Map<String, List<String>> incoming = new HashMap<>();
        for (int i = 0; i < entryCount; i++) {
            String trapdoorToken = in.readUTF();
            int listSize = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            List<String> encodedIds = new ArrayList<>(listSize);
            for (int j = 0; j < listSize; j++) {
                byte[] encFileId = Framing.readBoundedBytes(in, 4096);
                encodedIds.add(Base64.getEncoder().encodeToString(encFileId));
            }
            incoming.put(trapdoorToken, encodedIds);
        }

        indexLock.writeLock().lock();
        try {
            for (Map.Entry<String, List<String>> e : incoming.entrySet()) {
                trapdoorIndex.computeIfAbsent(e.getKey(), k -> new LinkedHashSet<>()).addAll(e.getValue());
            }
            saveMetadataIndexLocked();
        } finally {
            indexLock.writeLock().unlock();
        }
        out.writeUTF("METADATA_OK");
        out.flush();
    }

    private void handleStoreBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String rawBlockId = in.readUTF();
        byte[] cipherBlock = Framing.readBoundedBytes(in, Framing.MAX_FRAME_BYTES);
        try {
            Path blockPath = PathSanitizer.resolveSafeChild(blockDir, rawBlockId, "blockId");
            if (!Files.exists(blockPath)) {
                Framing.writeFileAtomically(blockPath, cipherBlock);
            }
            out.writeUTF("OK");
        } catch (SecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleGetBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String rawBlockId = in.readUTF();
        try {
            Path blockPath = PathSanitizer.resolveSafeChild(blockDir, rawBlockId, "blockId");
            if (!Files.exists(blockPath)) {
                out.writeInt(-1);
            } else {
                byte[] data = Files.readAllBytes(blockPath);
                Framing.writeBytes(out, data);
            }
        } catch (SecurityException e) {
            out.writeInt(-1);
        }
        out.flush();
    }

    private void handleListBlocks(DataOutputStream out) throws IOException {
        List<String> names = new ArrayList<>();
        try (Stream<Path> stream = Files.list(blockDir)) {
            stream.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> !n.endsWith(".tmp"))
                    .forEach(names::add);
        }
        out.writeInt(names.size());
        for (String name : names) {
            out.writeUTF(name);
        }
        out.flush();
    }

    private void handleSearch(DataInputStream in, DataOutputStream out) throws IOException {
        int tokenCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
        if (tokenCount == 0) {
            out.writeInt(0);
            out.flush();
            return;
        }
        List<String> queryTokens = new ArrayList<>(tokenCount);
        for (int i = 0; i < tokenCount; i++) {
            queryTokens.add(in.readUTF());
        }

        Set<String> intersection = null;
        indexLock.readLock().lock();
        try {
            for (String token : queryTokens) {
                Set<String> postings = trapdoorIndex.get(token);
                if (postings == null || postings.isEmpty()) {
                    intersection = Set.of();
                    break;
                }
                if (intersection == null) {
                    intersection = new LinkedHashSet<>(postings);
                } else {
                    intersection.retainAll(postings);
                    if (intersection.isEmpty()) {
                        break;
                    }
                }
            }
        } finally {
            indexLock.readLock().unlock();
        }

        if (intersection == null || intersection.isEmpty()) {
            out.writeInt(0);
            out.flush();
            return;
        }
        out.writeInt(intersection.size());
        for (String b64EncFileId : intersection) {
            byte[] decoded = Base64.getDecoder().decode(b64EncFileId);
            Framing.writeBytes(out, decoded);
        }
        out.flush();
    }

    private void handleStoreManifest(DataInputStream in, DataOutputStream out) throws IOException {
        String rawFileId = in.readUTF();
        byte[] encryptedManifest = Framing.readBoundedBytes(in, Framing.MAX_FRAME_BYTES);
        try {
            Path manifestPath = PathSanitizer.resolveSafeChild(manifestDir, rawFileId, "fileId");
            Framing.writeFileAtomically(manifestPath, encryptedManifest);
            out.writeUTF("OK");
        } catch (SecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleGetManifest(DataInputStream in, DataOutputStream out) throws IOException {
        String rawFileId = in.readUTF();
        try {
            Path manifestPath = PathSanitizer.resolveSafeChild(manifestDir, rawFileId, "fileId");
            if (Files.exists(manifestPath)) {
                out.writeUTF("OK");
                Framing.writeBytes(out, Files.readAllBytes(manifestPath));
            } else {
                out.writeUTF("NOK");
            }
        } catch (SecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void saveMetadataIndexLocked() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(META_MAGIC);
            out.writeInt(trapdoorIndex.size());
            for (Map.Entry<String, Set<String>> entry : trapdoorIndex.entrySet()) {
                out.writeUTF(entry.getKey());
                Set<String> postings = entry.getValue();
                out.writeInt(postings.size());
                for (String b64 : postings) {
                    out.writeUTF(b64);
                }
            }
        }
        Framing.writeFileAtomically(metadataFile, bos.toByteArray());
    }

    private void loadMetadataIndex() throws IOException {
        if (!Files.exists(metadataFile)) {
            return;
        }
        byte[] raw = Files.readAllBytes(metadataFile);
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw))) {
            byte[] magic = new byte[META_MAGIC.length];
            in.readFully(magic);
            for (int i = 0; i < META_MAGIC.length; i++) {
                if (magic[i] != META_MAGIC[i]) {
                    throw new IOException("Invalid OBSS metadata header");
                }
            }
            int tokenCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            for (int i = 0; i < tokenCount; i++) {
                String token = in.readUTF();
                int postingCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
                Set<String> postings = new LinkedHashSet<>(postingCount);
                for (int j = 0; j < postingCount; j++) {
                    postings.add(in.readUTF());
                }
                trapdoorIndex.put(token, postings);
            }
        }
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
        if (clientExecutor != null) {
            clientExecutor.close();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        String pwd = System.getenv().getOrDefault("OBSS_KEYSTORE_PASSWORD", "changeit-obss-local");
        Path dataDir = Path.of("runtime/obss");
        Path sharedDir = Path.of("runtime/shared");

        ObssServer server = new ObssServer(port, dataDir, sharedDir, pwd.toCharArray());
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        System.out.println("[OBSS] Oblivious Block Storage Server listening on TLS 1.3 port " + server.getPort());
        server.acceptThread.join();
    }
}
