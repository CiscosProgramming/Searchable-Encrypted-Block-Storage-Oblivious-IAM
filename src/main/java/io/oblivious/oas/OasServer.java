package io.oblivious.oas;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.Framing;
import io.oblivious.common.JwtService;
import io.oblivious.common.KeystoreManager;
import io.oblivious.common.TlsChannelFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Oblivious Authentication Server (OAS) over TLS 1.3.
 *
 * <p>Security properties:
 * <ul>
 *   <li>Anonymous P-256 public-key identities (no usernames or PII)</li>
 *   <li>Fresh 128-bit server challenges on {@code REGISTER}, {@code LOGIN}, {@code MODIFY}, and {@code DELETE}</li>
 *   <li>Anti-enumeration {@code LOGIN}: performs dummy PBKDF2 work when an {@code anonId} is unknown</li>
 *   <li>Per-deployment random 256-bit server pepper persisted in PKCS12 keystore (never hardcoded)</li>
 *   <li>RFC 7515 {@code ES256} signed JWT issuance for stateless downstream verification</li>
 * </ul>
 */
public final class OasServer implements AutoCloseable {

    public static final int DEFAULT_PORT = 5001;
    private static final long DEFAULT_TOKEN_TTL_SECONDS = 600L;
    private static final int MAX_SIGNATURE_BYTES = 256;

    private final int configuredPort;
    private final Path dataDir;
    private final Path sharedTrustDir;
    private final char[] keystorePassword;
    private final int pbkdf2Iterations;
    private final long tokenTtlSeconds;

    private UserStore userStore;
    private KeyPair jwtSigningKeys;
    private String serverPepper;
    private X509Certificate tlsCertificate;
    private SSLServerSocket serverSocket;
    private ExecutorService clientExecutor;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public OasServer(
            int port,
            Path dataDir,
            Path sharedTrustDir,
            char[] keystorePassword) {
        this(port, dataDir, sharedTrustDir, keystorePassword,
                CryptoPrimitives.DEFAULT_PBKDF2_ITERATIONS, DEFAULT_TOKEN_TTL_SECONDS);
    }

    public OasServer(
            int port,
            Path dataDir,
            Path sharedTrustDir,
            char[] keystorePassword,
            int pbkdf2Iterations,
            long tokenTtlSeconds) {
        this.configuredPort = port;
        this.dataDir = dataDir;
        this.sharedTrustDir = sharedTrustDir;
        this.keystorePassword = keystorePassword.clone();
        this.pbkdf2Iterations = pbkdf2Iterations;
        this.tokenTtlSeconds = tokenTtlSeconds;
    }

    public void start() throws GeneralSecurityException, IOException {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        this.userStore = new UserStore(dataDir.resolve("users.db"));
        Path keystorePath = dataDir.resolve("oas-server.p12");

        // 1. Load or generate ES256 JWT signing key pair
        this.jwtSigningKeys = KeystoreManager.loadKeyPair(keystorePath, keystorePassword, "jwt-signing");
        if (this.jwtSigningKeys == null) {
            this.jwtSigningKeys = CryptoPrimitives.generateEcKeyPair();
            KeystoreManager.saveKeyPair(keystorePath, keystorePassword, "jwt-signing", jwtSigningKeys, "oas-jwt");
        }
        String encodedJwtPub = CryptoPrimitives.encodePublicKey(jwtSigningKeys.getPublic());
        Framing.writeFileAtomically(
                sharedTrustDir.resolve("oas-jwt.pub"),
                encodedJwtPub.getBytes(StandardCharsets.UTF_8));

        // 2. Load or generate deployment-unique 256-bit pepper inside keystore
        String envPepper = System.getenv("OAS_PEPPER");
        if (envPepper != null && !envPepper.isBlank()) {
            this.serverPepper = envPepper;
        } else {
            SecretKey pepperKey = KeystoreManager.loadSecretKey(keystorePath, keystorePassword, "pwd-pepper");
            if (pepperKey == null) {
                pepperKey = new SecretKeySpec(CryptoPrimitives.randomBytes(32), "HmacSHA256");
                KeystoreManager.saveSecretKey(keystorePath, keystorePassword, "pwd-pepper", pepperKey);
            }
            this.serverPepper = Base64.getEncoder().encodeToString(pepperKey.getEncoded());
        }

        // 3. Provision TLS 1.3 certificate and start SSLServerSocket
        this.tlsCertificate = TlsChannelFactory.ensureServerTlsMaterial(
                keystorePath, keystorePassword, "tls-server", "localhost",
                sharedTrustDir.resolve("oas-tls.crt"));
        this.serverSocket = TlsChannelFactory.createServerSocket(configuredPort, keystorePath, keystorePassword);
        this.clientExecutor = Executors.newVirtualThreadPerTaskExecutor();

        this.acceptThread = Thread.ofPlatform().name("oas-acceptor").daemon(true).start(this::acceptLoop);
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public X509Certificate getTlsCertificate() {
        return tlsCertificate;
    }

    public PublicKey getJwtVerifyKey() {
        return jwtSigningKeys.getPublic();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                clientExecutor.submit(() -> handleConnection(socket));
            } catch (SocketException closed) {
                if (running.get()) {
                    System.err.println("[OAS] Socket accept error: " + closed.getMessage());
                }
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("[OAS] Accept I/O error: " + e.getMessage());
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
                case "REGISTER" -> handleRegister(in, out);
                case "LOGIN" -> handleLogin(in, out);
                case "MODIFY" -> handleModify(in, out);
                case "DELETE" -> handleDelete(in, out);
                default -> {
                    out.writeUTF("NOK");
                    out.flush();
                }
            }
        } catch (Exception ignored) {
            // Preserve obliviousness: close quietly without leaking stack traces to peer
        }
    }

    private void handleRegister(DataInputStream in, DataOutputStream out) throws IOException {
        String anonId = in.readUTF();
        PublicKey pubKey;
        try {
            pubKey = CryptoPrimitives.decodePublicKey(anonId);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        // Canonicalize anonId from decoded SPKI to prevent non-canonical Base64 duplicates
        String canonicalAnonId = CryptoPrimitives.encodePublicKey(pubKey);
        if (!canonicalAnonId.equals(anonId) || userStore.exists(canonicalAnonId)) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        String challenge = CryptoPrimitives.generateNonceBase64Url(16);
        out.writeUTF("CHALLENGE:" + challenge);
        out.flush();

        String clientPreHash = in.readUTF();
        String hashedAttribute = in.readUTF();
        byte[] signature = Framing.readBoundedBytes(in, MAX_SIGNATURE_BYTES);

        byte[] transcript = ("REGISTER|" + canonicalAnonId + "|" + challenge + "|"
                + clientPreHash + "|" + hashedAttribute).getBytes(StandardCharsets.UTF_8);
        if (!CryptoPrimitives.verifyEcdsa(pubKey, transcript, signature)) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        byte[] salt = CryptoPrimitives.generateSalt();
        String verifier = CryptoPrimitives.derivePasswordVerifier(
                clientPreHash, serverPepper, salt, pbkdf2Iterations);
        UserRecord record = new UserRecord(canonicalAnonId, verifier, salt, hashedAttribute);
        out.writeUTF(userStore.putIfAbsent(record) ? "OK" : "NOK");
        out.flush();
    }

    private void handleLogin(DataInputStream in, DataOutputStream out) throws IOException {
        String anonId = in.readUTF();
        String challenge = CryptoPrimitives.generateNonceBase64Url(16);
        out.writeUTF("CHALLENGE:" + challenge);
        out.flush();

        byte[] signature = Framing.readBoundedBytes(in, MAX_SIGNATURE_BYTES);
        String clientPreHash = in.readUTF();

        UserRecord user = userStore.get(anonId);
        if (user == null) {
            // Anti-enumeration: execute dummy PBKDF2 work so unknown AnonIDs take uniform time
            CryptoPrimitives.derivePasswordVerifier(
                    clientPreHash, serverPepper, new byte[CryptoPrimitives.SALT_BYTES], pbkdf2Iterations);
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        try {
            PublicKey pubKey = CryptoPrimitives.decodePublicKey(user.anonId());
            byte[] transcript = ("LOGIN|" + user.anonId() + "|" + challenge).getBytes(StandardCharsets.UTF_8);
            boolean sigOk = CryptoPrimitives.verifyEcdsa(pubKey, transcript, signature);
            String computedVerifier = CryptoPrimitives.derivePasswordVerifier(
                    clientPreHash, serverPepper, user.salt(), pbkdf2Iterations);
            boolean pwdOk = CryptoPrimitives.constantTimeEquals(user.passwordVerifier(), computedVerifier);

            if (sigOk && pwdOk) {
                String jwt = JwtService.issueToken(jwtSigningKeys.getPrivate(), user.anonId(), tokenTtlSeconds);
                out.writeUTF("OK:" + jwt);
            } else {
                out.writeUTF("NOK");
            }
        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleModify(DataInputStream in, DataOutputStream out) throws IOException {
        String jwt = in.readUTF();
        JwtService.VerifiedClaims claims = JwtService.verifyToken(jwtSigningKeys.getPublic(), jwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        UserRecord current = userStore.get(claims.subject());
        if (current == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        String challenge = CryptoPrimitives.generateNonceBase64Url(16);
        out.writeUTF("CHALLENGE:" + challenge);
        out.flush();

        String currentPreHash = in.readUTF();
        String newPreHash = in.readUTF();
        String newAttrHash = in.readUTF();
        byte[] signature = Framing.readBoundedBytes(in, MAX_SIGNATURE_BYTES);

        try {
            PublicKey pubKey = CryptoPrimitives.decodePublicKey(current.anonId());
            byte[] transcript = ("MODIFY|" + current.anonId() + "|" + challenge + "|"
                    + newPreHash + "|" + newAttrHash).getBytes(StandardCharsets.UTF_8);
            boolean sigOk = CryptoPrimitives.verifyEcdsa(pubKey, transcript, signature);
            String currentComputed = CryptoPrimitives.derivePasswordVerifier(
                    currentPreHash, serverPepper, current.salt(), pbkdf2Iterations);
            boolean pwdOk = CryptoPrimitives.constantTimeEquals(current.passwordVerifier(), currentComputed);
            if (!sigOk || !pwdOk) {
                out.writeUTF("NOK");
                out.flush();
                return;
            }

            // Rotate salt on password update
            byte[] freshSalt = CryptoPrimitives.generateSalt();
            String newVerifier = CryptoPrimitives.derivePasswordVerifier(
                    newPreHash, serverPepper, freshSalt, pbkdf2Iterations);
            UserRecord updated = new UserRecord(current.anonId(), newVerifier, freshSalt, newAttrHash);
            out.writeUTF(userStore.replace(updated) ? "OK" : "NOK");
        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
        }
        out.flush();
    }

    private void handleDelete(DataInputStream in, DataOutputStream out) throws IOException {
        String jwt = in.readUTF();
        JwtService.VerifiedClaims claims = JwtService.verifyToken(jwtSigningKeys.getPublic(), jwt);
        if (claims == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }
        UserRecord current = userStore.get(claims.subject());
        if (current == null) {
            out.writeUTF("NOK");
            out.flush();
            return;
        }

        String challenge = CryptoPrimitives.generateNonceBase64Url(16);
        out.writeUTF("CHALLENGE:" + challenge);
        out.flush();

        String currentPreHash = in.readUTF();
        byte[] signature = Framing.readBoundedBytes(in, MAX_SIGNATURE_BYTES);

        try {
            PublicKey pubKey = CryptoPrimitives.decodePublicKey(current.anonId());
            byte[] transcript = ("DELETE|" + current.anonId() + "|" + challenge).getBytes(StandardCharsets.UTF_8);
            boolean sigOk = CryptoPrimitives.verifyEcdsa(pubKey, transcript, signature);
            String currentComputed = CryptoPrimitives.derivePasswordVerifier(
                    currentPreHash, serverPepper, current.salt(), pbkdf2Iterations);
            boolean pwdOk = CryptoPrimitives.constantTimeEquals(current.passwordVerifier(), currentComputed);
            if (!sigOk || !pwdOk) {
                out.writeUTF("NOK");
                out.flush();
                return;
            }
            out.writeUTF(userStore.remove(current.anonId()) ? "OK" : "NOK");
        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
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
        String pwd = System.getenv().getOrDefault("OAS_KEYSTORE_PASSWORD", "changeit-oas-local");
        Path dataDir = Path.of("runtime/oas");
        Path sharedDir = Path.of("runtime/shared");

        OasServer server = new OasServer(port, dataDir, sharedDir, pwd.toCharArray());
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        System.out.println("[OAS] Oblivious Authentication Server listening on TLS 1.3 port " + server.getPort());
        server.acceptThread.join();
    }
}
