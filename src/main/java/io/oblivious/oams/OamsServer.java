package io.oblivious.oams;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.JwtService;
import io.oblivious.common.PathSanitizer;
import io.oblivious.common.TlsChannelFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Oblivious Access Management Server (OAMS) over TLS 1.3.
 *
 * <p>Statelessly validates OAS {@code ES256} JWTs using the pinned OAS public key,
 * enforces strict resource-owner authorization on {@code SHARE} and {@code REVOKE},
 * and stores only ECIES-wrapped file keys indexed by anonymous public keys.
 */
public final class OamsServer implements AutoCloseable {

    public static final int DEFAULT_PORT = 5002;

    private final int configuredPort;
    private final Path dataDir;
    private final Path sharedTrustDir;
    private final char[] keystorePassword;
    private PublicKey oasJwtVerifyKey;

    private ShareStore shareStore;
    private X509Certificate tlsCertificate;
    private SSLServerSocket serverSocket;
    private ExecutorService clientExecutor;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public OamsServer(
            int port,
            Path dataDir,
            Path sharedTrustDir,
            char[] keystorePassword) {
        this(port, dataDir, sharedTrustDir, keystorePassword, null);
    }

    public OamsServer(
            int port,
            Path dataDir,
            Path sharedTrustDir,
            char[] keystorePassword,
            PublicKey pinnedOasJwtKey) {
        this.configuredPort = port;
        this.dataDir = dataDir;
        this.sharedTrustDir = sharedTrustDir;
        this.keystorePassword = keystorePassword.clone();
        this.oasJwtVerifyKey = pinnedOasJwtKey;
    }

    public void start() throws GeneralSecurityException, IOException {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        if (this.oasJwtVerifyKey == null) {
            Path oasPubPath = sharedTrustDir.resolve("oas-jwt.pub");
            if (!Files.exists(oasPubPath)) {
                throw new IOException("OAS public key not found at " + oasPubPath + ". Start OAS first.");
            }
            String b64 = Files.readString(oasPubPath, StandardCharsets.UTF_8).trim();
            this.oasJwtVerifyKey = CryptoPrimitives.decodePublicKey(b64);
        }

        this.shareStore = new ShareStore(dataDir.resolve("sharing.db"));
        Path keystorePath = dataDir.resolve("oams-server.p12");
        this.tlsCertificate = TlsChannelFactory.ensureServerTlsMaterial(
                keystorePath, keystorePassword, "tls-server", "localhost",
                sharedTrustDir.resolve("oams-tls.crt"));
        this.serverSocket = TlsChannelFactory.createServerSocket(configuredPort, keystorePath, keystorePassword);
        this.clientExecutor = Executors.newVirtualThreadPerTaskExecutor();
        this.acceptThread = Thread.ofPlatform().name("oams-acceptor").daemon(true).start(this::acceptLoop);
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public X509Certificate getTlsCertificate() {
        return tlsCertificate;
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                clientExecutor.submit(() -> handleConnection(socket));
            } catch (SocketException closed) {
                if (running.get()) {
                    System.err.println("[OAMS] Socket accept error: " + closed.getMessage());
                }
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("[OAMS] Accept I/O error: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(SSLSocket socket) {
        try (socket;
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            socket.setSoTimeout(15_000);
            String command = in.readUTF();
            switch (command) {
                case "SHARE" -> handleShare(in, out);
                case "GET_ACCESS" -> handleGetAccess(in, out);
                case "REVOKE" -> handleRevoke(in, out);
                case "LIST_SHARED" -> handleListShared(in, out);
                default -> {
                    out.writeUTF("NOK");
                    out.flush();
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void handleShare(DataInputStream in, DataOutputStream out) throws IOException {
        String ownerJwt = in.readUTF();
        String rawFileId = in.readUTF();
        String targetAnonId = in.readUTF();
        String wrappedKeyPayload = in.readUTF();
        String rawPermission = in.readUTF();

        JwtService.VerifiedClaims claims = JwtService.verifyToken(oasJwtVerifyKey, ownerJwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(rawFileId, "fileId");
            PublicKey targetPub = CryptoPrimitives.decodePublicKey(targetAnonId);
            String canonicalTarget = CryptoPrimitives.encodePublicKey(targetPub);
            Permission permission = Permission.parse(rawPermission);

            boolean stored = shareStore.upsertGrant(
                    claims.subject(), safeFileId, canonicalTarget, wrappedKeyPayload, permission);
            out.writeUTF(stored ? "OK" : "NOK");
        } catch (Exception e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleGetAccess(DataInputStream in, DataOutputStream out) throws IOException {
        String guestJwt = in.readUTF();
        String rawFileId = in.readUTF();

        JwtService.VerifiedClaims claims = JwtService.verifyToken(oasJwtVerifyKey, guestJwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(rawFileId, "fileId");
            ShareStore.AccessGrant grant = shareStore.getGrant(claims.subject(), safeFileId);
            if (grant == null) {
                out.writeUTF("NOK");
            } else {
                out.writeUTF("OK");
                out.writeUTF(grant.wrappedKeyPayload());
                out.writeUTF(grant.permission().name());
            }
        } catch (SecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleRevoke(DataInputStream in, DataOutputStream out) throws IOException {
        String ownerJwt = in.readUTF();
        String rawFileId = in.readUTF();
        String targetAnonId = in.readUTF();

        JwtService.VerifiedClaims claims = JwtService.verifyToken(oasJwtVerifyKey, ownerJwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(rawFileId, "fileId");
            PublicKey targetPub = CryptoPrimitives.decodePublicKey(targetAnonId);
            String canonicalTarget = CryptoPrimitives.encodePublicKey(targetPub);

            boolean revoked = shareStore.revokeGrant(claims.subject(), safeFileId, canonicalTarget);
            out.writeUTF(revoked ? "OK" : "NOK");
        } catch (Exception e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleListShared(DataInputStream in, DataOutputStream out) throws IOException {
        String guestJwt = in.readUTF();
        JwtService.VerifiedClaims claims = JwtService.verifyToken(oasJwtVerifyKey, guestJwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        List<String> fileIds = shareStore.listSharedFileIdsForGuest(claims.subject());
        out.writeUTF("OK");
        out.writeInt(fileIds.size());
        for (String id : fileIds) {
            out.writeUTF(id);
        }
        out.flush();
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
        String pwd = System.getenv().getOrDefault("OAMS_KEYSTORE_PASSWORD", "changeit-oams-local");
        Path dataDir = Path.of("runtime/oams");
        Path sharedDir = Path.of("runtime/shared");

        OamsServer server = new OamsServer(port, dataDir, sharedDir, pwd.toCharArray());
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        System.out.println("[OAMS] Oblivious Access Management Server listening on TLS 1.3 port " + server.getPort());
        server.acceptThread.join();
    }
}
