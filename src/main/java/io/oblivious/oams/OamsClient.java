package io.oblivious.oams;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.KeystoreManager;
import io.oblivious.common.PathSanitizer;
import io.oblivious.common.TlsChannelFactory;
import io.oblivious.oas.OasClient;
import io.oblivious.oas.OasServer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;

/**
 * Client SDK and interactive CLI for the Oblivious Access Management Server (OAMS).
 *
 * <p>Wraps per-file AES-256 keys via ECIES (ephemeral P-256 ECDH + HKDF-SHA256 + AES-256-GCM)
 * with AAD {@code "OAMS-WRAP|" + fileId + "|" + permission} and stores unwrapped shared keys
 * exclusively inside the recipient's password-protected {@code PKCS12} keystore.
 */
public final class OamsClient {

    public static final String OWNER_FILE_KEY_PREFIX = "owner-file-key:";
    public static final String SHARED_FILE_KEY_PREFIX = "shared-file-key:";

    public record UnwrappedGrant(String fileId, SecretKey fileKey, Permission permission) {
    }

    private final String host;
    private final int port;
    private final Path oamsTlsCertPath;

    public OamsClient(String host, int port, Path oamsTlsCertPath) {
        this.host = host;
        this.port = port;
        this.oamsTlsCertPath = oamsTlsCertPath;
    }

    public static byte[] buildWrapAad(String fileId, Permission permission) {
        return ("OAMS-WRAP|" + fileId + "|" + permission.name()).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * PKCS12 keystores normalize entry aliases to lowercase; hex-encoding {@code fileId}
     * preserves exact case sensitivity and prevents case-folding collisions.
     */
    public static String ownerKeyAlias(String fileId) {
        return OWNER_FILE_KEY_PREFIX + HexFormat.of().formatHex(fileId.getBytes(StandardCharsets.UTF_8));
    }

    public static String sharedKeyAlias(String fileId, Permission permission) {
        return SHARED_FILE_KEY_PREFIX
                + permission.name().toLowerCase(Locale.ROOT)
                + ":"
                + HexFormat.of().formatHex(fileId.getBytes(StandardCharsets.UTF_8));
    }

    public static String decodeFileIdFromAliasSuffix(String hexSuffix) {
        return new String(HexFormat.of().parseHex(hexSuffix), StandardCharsets.UTF_8);
    }

    public boolean shareFile(
            String ownerJwt,
            PublicKey recipientPublicKey,
            String fileId,
            SecretKey fileKey,
            Permission permission) {
        if (ownerJwt == null || recipientPublicKey == null || fileId == null
                || fileKey == null || permission == null) {
            return false;
        }
        byte[] rawKeyBytes = fileKey.getEncoded();
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
            byte[] aad = buildWrapAad(safeFileId, permission);
            String wrappedKey = CryptoPrimitives.wrapSymmetricKey(rawKeyBytes, recipientPublicKey, aad);
            String targetAnonId = CryptoPrimitives.encodePublicKey(recipientPublicKey);

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oamsTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("SHARE");
                out.writeUTF(ownerJwt);
                out.writeUTF(safeFileId);
                out.writeUTF(targetAnonId);
                out.writeUTF(wrappedKey);
                out.writeUTF(permission.name());
                out.flush();
                return "OK".equals(in.readUTF());
            }
        } catch (Exception e) {
            return false;
        } finally {
            if (rawKeyBytes != null) {
                Arrays.fill(rawKeyBytes, (byte) 0);
            }
        }
    }

    /**
     * Fetches the caller's wrapped grant from OAMS, verifies &amp; unwraps it using the
     * caller's EC {@link KeyPair} and AAD binding, and persists the unwrapped key inside
     * {@code recipientKeystorePath} (never as a plaintext {@code .key} file).
     */
    public UnwrappedGrant fetchAndUnwrapAccess(
            String guestJwt,
            String fileId,
            KeyPair guestKeyPair,
            Path recipientKeystorePath,
            char[] keystorePassword) {
        if (guestJwt == null || fileId == null || guestKeyPair == null) {
            return null;
        }
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
            String wrappedPayload;
            Permission grantedPerm;

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oamsTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("GET_ACCESS");
                out.writeUTF(guestJwt);
                out.writeUTF(safeFileId);
                out.flush();

                if (!"OK".equals(in.readUTF())) {
                    return null;
                }
                wrappedPayload = in.readUTF();
                grantedPerm = Permission.parse(in.readUTF());
            }

            byte[] aad = buildWrapAad(safeFileId, grantedPerm);
            byte[] unwrappedBytes = CryptoPrimitives.unwrapSymmetricKey(wrappedPayload, guestKeyPair, aad);
            try {
                SecretKey fileKey = new SecretKeySpec(unwrappedBytes, "AES");
                if (recipientKeystorePath != null && keystorePassword != null) {
                    saveSharedKeyToKeystore(recipientKeystorePath, keystorePassword, safeFileId, fileKey, grantedPerm);
                }
                return new UnwrappedGrant(safeFileId, fileKey, grantedPerm);
            } finally {
                Arrays.fill(unwrappedBytes, (byte) 0);
            }
        } catch (Exception e) {
            return null;
        }
    }

    public boolean revokeAccess(String ownerJwt, String fileId, PublicKey targetPublicKey) {
        if (ownerJwt == null || fileId == null || targetPublicKey == null) {
            return false;
        }
        try {
            String safeFileId = PathSanitizer.sanitizeIdentifier(fileId, "fileId");
            String targetAnonId = CryptoPrimitives.encodePublicKey(targetPublicKey);

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oamsTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("REVOKE");
                out.writeUTF(ownerJwt);
                out.writeUTF(safeFileId);
                out.writeUTF(targetAnonId);
                out.flush();
                return "OK".equals(in.readUTF());
            }
        } catch (Exception e) {
            return false;
        }
    }

    public List<String> listSharedFiles(String guestJwt) {
        List<String> files = new ArrayList<>();
        if (guestJwt == null) {
            return files;
        }
        try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oamsTlsCertPath);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {
            out.writeUTF("LIST_SHARED");
            out.writeUTF(guestJwt);
            out.flush();
            if ("OK".equals(in.readUTF())) {
                int count = in.readInt();
                for (int i = 0; i < count; i++) {
                    files.add(in.readUTF());
                }
            }
        } catch (IOException | GeneralSecurityException ignored) {
        }
        return files;
    }

    public static void saveSharedKeyToKeystore(
            Path keystorePath, char[] password, String fileId, SecretKey fileKey, Permission permission)
            throws GeneralSecurityException, IOException {
        KeystoreManager.saveSecretKey(keystorePath, password, sharedKeyAlias(fileId, permission), fileKey);
    }

    public static void main(String[] args) {
        Path sharedDir = Path.of("runtime/shared");
        Path clientDir = Path.of("runtime/client");
        OasClient oasClient = new OasClient(
                "localhost", OasServer.DEFAULT_PORT, sharedDir.resolve("oas-tls.crt"), clientDir);
        OamsClient oamsClient = new OamsClient(
                "localhost", OamsServer.DEFAULT_PORT, sharedDir.resolve("oams-tls.crt"));

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("=== Oblivious Access Management Client (TLS 1.3) ===");
            while (true) {
                System.out.println("\n1. Share File  2. Fetch Shared Access  3. Revoke Access  0. Exit");
                System.out.print("> ");
                String choice = scanner.nextLine().trim();
                try {
                    switch (choice) {
                        case "1" -> {
                            System.out.print("Owner alias: ");
                            String ownerAlias = scanner.nextLine().trim();
                            System.out.print("Owner password: ");
                            char[] ownerPwd = scanner.nextLine().toCharArray();
                            String jwt = oasClient.loadToken(ownerAlias);
                            System.out.print("File ID: ");
                            String fileId = scanner.nextLine().trim();
                            SecretKey fileKey = KeystoreManager.loadSecretKey(
                                    oasClient.keystorePath(ownerAlias), ownerPwd, ownerKeyAlias(fileId));
                            System.out.print("Recipient alias: ");
                            String targetAlias = scanner.nextLine().trim();
                            PublicKey targetPub = oasClient.loadPublishedPublicKey(targetAlias);
                            System.out.print("Permission (READ / SEARCH): ");
                            Permission perm = Permission.parse(scanner.nextLine());
                            boolean ok = oamsClient.shareFile(jwt, targetPub, fileId, fileKey, perm);
                            System.out.println(ok ? "OK" : "NOK");
                        }
                        case "2" -> {
                            System.out.print("Guest alias: ");
                            String guestAlias = scanner.nextLine().trim();
                            System.out.print("Guest password: ");
                            char[] guestPwd = scanner.nextLine().toCharArray();
                            String jwt = oasClient.loadToken(guestAlias);
                            KeyPair kp = oasClient.loadIdentity(guestAlias, guestPwd);
                            System.out.print("File ID: ");
                            String fileId = scanner.nextLine().trim();
                            UnwrappedGrant grant = oamsClient.fetchAndUnwrapAccess(
                                    jwt, fileId, kp, oasClient.keystorePath(guestAlias), guestPwd);
                            System.out.println(grant != null ? "OK (" + grant.permission() + ")" : "NOK");
                        }
                        case "3" -> {
                            System.out.print("Owner alias: ");
                            String ownerAlias = scanner.nextLine().trim();
                            String jwt = oasClient.loadToken(ownerAlias);
                            System.out.print("File ID: ");
                            String fileId = scanner.nextLine().trim();
                            System.out.print("Recipient alias to revoke: ");
                            String targetAlias = scanner.nextLine().trim();
                            PublicKey targetPub = oasClient.loadPublishedPublicKey(targetAlias);
                            System.out.println(oamsClient.revokeAccess(jwt, fileId, targetPub) ? "OK" : "NOK");
                        }
                        case "0" -> {
                            return;
                        }
                        default -> System.out.println("NOK");
                    }
                } catch (Exception e) {
                    System.out.println("NOK");
                }
            }
        }
    }
}
