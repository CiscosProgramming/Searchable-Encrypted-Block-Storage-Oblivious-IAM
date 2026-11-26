package io.oblivious.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.SecretKey;

/**
 * Password-protected {@code PKCS12} keystore manager for both asymmetric EC identity/TLS
 * key pairs and symmetric keys (master cipher keys, HMAC keys, Searchable Encryption keys,
 * and per-file keys).
 *
 * <p>Eliminates plaintext {@code .key} files on disk and avoids legacy {@code JCEKS} +
 * Java object-serialization hacks. All updates persist via atomic temp-file renames.
 */
public final class KeystoreManager {

    private static final String KEYSTORE_TYPE = "PKCS12";

    private KeystoreManager() {
    }

    public static synchronized void saveKeyPair(
            Path keystorePath, char[] password, String alias, KeyPair keyPair, String commonName)
            throws GeneralSecurityException, IOException {
        KeyStore ks = loadOrCreateKeyStore(keystorePath, password);
        X509Certificate cert = X509CertBuilder.generateSelfSignedEcCert(keyPair, commonName, 3650);
        ks.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[] {cert});
        persistKeyStore(ks, keystorePath, password);
    }

    public static synchronized KeyPair loadKeyPair(Path keystorePath, char[] password, String alias)
            throws GeneralSecurityException, IOException {
        if (!Files.exists(keystorePath)) {
            return null;
        }
        KeyStore ks = loadExistingKeyStore(keystorePath, password);
        Key key = ks.getKey(alias, password);
        Certificate cert = ks.getCertificate(alias);
        if (key instanceof PrivateKey privateKey && cert != null) {
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    public static synchronized X509Certificate loadCertificate(Path keystorePath, char[] password, String alias)
            throws GeneralSecurityException, IOException {
        if (!Files.exists(keystorePath)) {
            return null;
        }
        KeyStore ks = loadExistingKeyStore(keystorePath, password);
        Certificate cert = ks.getCertificate(alias);
        return (cert instanceof X509Certificate x509) ? x509 : null;
    }

    public static synchronized void saveSecretKey(
            Path keystorePath, char[] password, String alias, SecretKey secretKey)
            throws GeneralSecurityException, IOException {
        KeyStore ks = loadOrCreateKeyStore(keystorePath, password);
        KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(password);
        ks.setEntry(alias, new KeyStore.SecretKeyEntry(secretKey), prot);
        persistKeyStore(ks, keystorePath, password);
    }

    public static synchronized SecretKey loadSecretKey(Path keystorePath, char[] password, String alias)
            throws GeneralSecurityException, IOException {
        if (!Files.exists(keystorePath)) {
            return null;
        }
        KeyStore ks = loadExistingKeyStore(keystorePath, password);
        if (!ks.containsAlias(alias)) {
            return null;
        }
        KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(password);
        KeyStore.Entry entry = ks.getEntry(alias, prot);
        if (entry instanceof KeyStore.SecretKeyEntry ske) {
            return ske.getSecretKey();
        }
        return null;
    }

    public static synchronized List<String> listAliasesWithPrefix(
            Path keystorePath, char[] password, String prefix)
            throws GeneralSecurityException, IOException {
        List<String> matches = new ArrayList<>();
        if (!Files.exists(keystorePath)) {
            return matches;
        }
        KeyStore ks = loadExistingKeyStore(keystorePath, password);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (alias.startsWith(prefix)) {
                matches.add(alias);
            }
        }
        return matches;
    }

    public static KeyStore loadExistingKeyStore(Path keystorePath, char[] password)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (InputStream in = Files.newInputStream(keystorePath)) {
            ks.load(in, password);
        }
        return ks;
    }

    private static KeyStore loadOrCreateKeyStore(Path keystorePath, char[] password)
            throws GeneralSecurityException, IOException {
        if (Files.exists(keystorePath)) {
            return loadExistingKeyStore(keystorePath, password);
        }
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, password);
        return ks;
    }

    private static void persistKeyStore(KeyStore ks, Path keystorePath, char[] password)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, password);
        Framing.writeFileAtomically(keystorePath, bos.toByteArray());
    }
}
