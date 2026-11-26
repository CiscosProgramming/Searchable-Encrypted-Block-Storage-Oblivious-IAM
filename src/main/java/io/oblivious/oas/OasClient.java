package io.oblivious.oas;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.Framing;
import io.oblivious.common.KeystoreManager;
import io.oblivious.common.PathSanitizer;
import io.oblivious.common.TlsChannelFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;

/**
 * Client SDK and interactive CLI for the Oblivious Authentication Server (OAS).
 * Stores EC identity private keys inside password-protected {@code PKCS12} keystores.
 */
public final class OasClient {

    public static final String IDENTITY_KEY_ALIAS = "identity";

    private final String host;
    private final int port;
    private final Path oasTlsCertPath;
    private final Path clientDataDir;

    public OasClient(String host, int port, Path oasTlsCertPath, Path clientDataDir) {
        this.host = host;
        this.port = port;
        this.oasTlsCertPath = oasTlsCertPath;
        this.clientDataDir = clientDataDir;
    }

    public boolean register(String localAlias, char[] password, String attribute) {
        try {
            String safeAlias = PathSanitizer.sanitizeIdentifier(localAlias, "alias");
            KeyPair kp = CryptoPrimitives.generateEcKeyPair();
            String anonId = CryptoPrimitives.encodePublicKey(kp.getPublic());
            String preHashedPwd = CryptoPrimitives.preHashPassword(password);
            String hashedAttr = Base64.getEncoder().encodeToString(
                    CryptoPrimitives.sha256(attribute.getBytes(StandardCharsets.UTF_8)));

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oasTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("REGISTER");
                out.writeUTF(anonId);
                out.flush();

                String challengeResp = in.readUTF();
                if (!challengeResp.startsWith("CHALLENGE:")) {
                    return false;
                }
                String challenge = challengeResp.substring("CHALLENGE:".length());
                byte[] transcript = ("REGISTER|" + anonId + "|" + challenge + "|"
                        + preHashedPwd + "|" + hashedAttr).getBytes(StandardCharsets.UTF_8);
                byte[] sig = CryptoPrimitives.signEcdsa(kp.getPrivate(), transcript);

                out.writeUTF(preHashedPwd);
                out.writeUTF(hashedAttr);
                Framing.writeBytes(out, sig);
                out.flush();

                if ("OK".equals(in.readUTF())) {
                    saveIdentity(safeAlias, kp, password);
                    return true;
                }
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    public String login(String localAlias, char[] password) {
        try {
            String safeAlias = PathSanitizer.sanitizeIdentifier(localAlias, "alias");
            KeyPair kp = loadIdentity(safeAlias, password);
            if (kp == null) {
                return null;
            }
            String anonId = CryptoPrimitives.encodePublicKey(kp.getPublic());
            String preHashedPwd = CryptoPrimitives.preHashPassword(password);

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oasTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("LOGIN");
                out.writeUTF(anonId);
                out.flush();

                String challengeResp = in.readUTF();
                if (!challengeResp.startsWith("CHALLENGE:")) {
                    return null;
                }
                String challenge = challengeResp.substring("CHALLENGE:".length());
                byte[] transcript = ("LOGIN|" + anonId + "|" + challenge).getBytes(StandardCharsets.UTF_8);
                byte[] sig = CryptoPrimitives.signEcdsa(kp.getPrivate(), transcript);

                Framing.writeBytes(out, sig);
                out.writeUTF(preHashedPwd);
                out.flush();

                String result = in.readUTF();
                if (result.startsWith("OK:")) {
                    String jwt = result.substring(3);
                    saveToken(safeAlias, jwt);
                    return jwt;
                }
                return null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    public boolean modify(String localAlias, char[] currentPassword, char[] newPassword, String newAttribute) {
        try {
            String safeAlias = PathSanitizer.sanitizeIdentifier(localAlias, "alias");
            KeyPair kp = loadIdentity(safeAlias, currentPassword);
            String jwt = loadToken(safeAlias);
            if (kp == null || jwt == null) {
                return false;
            }
            String anonId = CryptoPrimitives.encodePublicKey(kp.getPublic());
            String currentPreHash = CryptoPrimitives.preHashPassword(currentPassword);
            String newPreHash = CryptoPrimitives.preHashPassword(newPassword);
            String newAttrHash = Base64.getEncoder().encodeToString(
                    CryptoPrimitives.sha256(newAttribute.getBytes(StandardCharsets.UTF_8)));

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oasTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("MODIFY");
                out.writeUTF(jwt);
                out.flush();

                String challengeResp = in.readUTF();
                if (!challengeResp.startsWith("CHALLENGE:")) {
                    return false;
                }
                String challenge = challengeResp.substring("CHALLENGE:".length());
                byte[] transcript = ("MODIFY|" + anonId + "|" + challenge + "|"
                        + newPreHash + "|" + newAttrHash).getBytes(StandardCharsets.UTF_8);
                byte[] sig = CryptoPrimitives.signEcdsa(kp.getPrivate(), transcript);

                out.writeUTF(currentPreHash);
                out.writeUTF(newPreHash);
                out.writeUTF(newAttrHash);
                Framing.writeBytes(out, sig);
                out.flush();

                if ("OK".equals(in.readUTF())) {
                    // Re-encrypt local PKCS12 keystore under the new password
                    Path ksPath = keystorePath(safeAlias);
                    Files.deleteIfExists(ksPath);
                    saveIdentity(safeAlias, kp, newPassword);
                    return true;
                }
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    public boolean delete(String localAlias, char[] password) {
        try {
            String safeAlias = PathSanitizer.sanitizeIdentifier(localAlias, "alias");
            KeyPair kp = loadIdentity(safeAlias, password);
            String jwt = loadToken(safeAlias);
            if (kp == null || jwt == null) {
                return false;
            }
            String anonId = CryptoPrimitives.encodePublicKey(kp.getPublic());
            String currentPreHash = CryptoPrimitives.preHashPassword(password);

            try (SSLSocket socket = TlsChannelFactory.connectClientSocket(host, port, oasTlsCertPath);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {
                out.writeUTF("DELETE");
                out.writeUTF(jwt);
                out.flush();

                String challengeResp = in.readUTF();
                if (!challengeResp.startsWith("CHALLENGE:")) {
                    return false;
                }
                String challenge = challengeResp.substring("CHALLENGE:".length());
                byte[] transcript = ("DELETE|" + anonId + "|" + challenge).getBytes(StandardCharsets.UTF_8);
                byte[] sig = CryptoPrimitives.signEcdsa(kp.getPrivate(), transcript);

                out.writeUTF(currentPreHash);
                Framing.writeBytes(out, sig);
                out.flush();

                if ("OK".equals(in.readUTF())) {
                    Files.deleteIfExists(keystorePath(safeAlias));
                    Files.deleteIfExists(publicKeyPath(safeAlias));
                    Files.deleteIfExists(tokenPath(safeAlias));
                    return true;
                }
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    public KeyPair loadIdentity(String localAlias, char[] password)
            throws GeneralSecurityException, IOException {
        return KeystoreManager.loadKeyPair(keystorePath(localAlias), password, IDENTITY_KEY_ALIAS);
    }

    public PublicKey loadPublishedPublicKey(String targetAlias)
            throws GeneralSecurityException, IOException {
        Path pubFile = publicKeyPath(targetAlias);
        if (!Files.exists(pubFile)) {
            return null;
        }
        String b64 = Files.readString(pubFile, StandardCharsets.UTF_8).trim();
        return CryptoPrimitives.decodePublicKey(b64);
    }

    public String loadToken(String localAlias) throws IOException {
        Path path = tokenPath(localAlias);
        if (!Files.exists(path)) {
            return null;
        }
        return Files.readString(path, StandardCharsets.UTF_8).trim();
    }

    public Path keystorePath(String localAlias) {
        return PathSanitizer.resolveSafeChild(
                clientDataDir.resolve("keys"), localAlias + ".p12", "keystore");
    }

    private Path publicKeyPath(String localAlias) {
        return PathSanitizer.resolveSafeChild(
                clientDataDir.resolve("pubkeys"), localAlias + ".pub", "publicKey");
    }

    private Path tokenPath(String localAlias) {
        return PathSanitizer.resolveSafeChild(
                clientDataDir.resolve("tokens"), localAlias + ".jwt", "token");
    }

    private void saveIdentity(String safeAlias, KeyPair kp, char[] password)
            throws GeneralSecurityException, IOException {
        KeystoreManager.saveKeyPair(keystorePath(safeAlias), password, IDENTITY_KEY_ALIAS, kp, safeAlias);
        String b64Pub = CryptoPrimitives.encodePublicKey(kp.getPublic());
        Framing.writeFileAtomically(publicKeyPath(safeAlias), b64Pub.getBytes(StandardCharsets.UTF_8));
    }

    private void saveToken(String safeAlias, String jwt) throws IOException {
        Framing.writeFileAtomically(tokenPath(safeAlias), jwt.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) {
        OasClient client = new OasClient(
                "localhost",
                OasServer.DEFAULT_PORT,
                Path.of("runtime/shared/oas-tls.crt"),
                Path.of("runtime/client"));
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("=== Oblivious Authentication Client (TLS 1.3) ===");
            while (true) {
                System.out.println("\n1. Register  2. Login  3. Modify  4. Delete  0. Exit");
                System.out.print("> ");
                String choice = scanner.nextLine().trim();
                switch (choice) {
                    case "1" -> {
                        System.out.print("Local alias: ");
                        String alias = scanner.nextLine().trim();
                        System.out.print("Password: ");
                        char[] pwd = scanner.nextLine().toCharArray();
                        System.out.print("Attribute: ");
                        String attr = scanner.nextLine().trim();
                        System.out.println(client.register(alias, pwd, attr) ? "OK" : "NOK");
                    }
                    case "2" -> {
                        System.out.print("Local alias: ");
                        String alias = scanner.nextLine().trim();
                        System.out.print("Password: ");
                        char[] pwd = scanner.nextLine().toCharArray();
                        System.out.println(client.login(alias, pwd) != null ? "OK" : "NOK");
                    }
                    case "3" -> {
                        System.out.print("Local alias: ");
                        String alias = scanner.nextLine().trim();
                        System.out.print("Current password: ");
                        char[] curPwd = scanner.nextLine().toCharArray();
                        System.out.print("New password: ");
                        char[] newPwd = scanner.nextLine().toCharArray();
                        System.out.print("New attribute: ");
                        String newAttr = scanner.nextLine().trim();
                        System.out.println(client.modify(alias, curPwd, newPwd, newAttr) ? "OK" : "NOK");
                    }
                    case "4" -> {
                        System.out.print("Local alias: ");
                        String alias = scanner.nextLine().trim();
                        System.out.print("Password: ");
                        char[] pwd = scanner.nextLine().toCharArray();
                        System.out.println(client.delete(alias, pwd) ? "OK" : "NOK");
                    }
                    case "0" -> {
                        return;
                    }
                    default -> System.out.println("NOK");
                }
            }
        }
    }
}
