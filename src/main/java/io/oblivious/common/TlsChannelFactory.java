package io.oblivious.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Configures strict TLS 1.3 {@link SSLServerSocket} and {@link SSLSocket} channels
 * pinned to AEAD cipher suites and endpoint hostname verification.
 */
public final class TlsChannelFactory {

    private static final String[] TLS_PROTOCOLS = new String[] {"TLSv1.3"};
    private static final String[] TLS_CIPHER_SUITES = new String[] {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256"
    };
    private static final int SOCKET_TIMEOUT_MS = 15_000;

    private TlsChannelFactory() {
    }

    /**
     * Ensures a TLS PKCS12 keystore exists for a server and exports its X.509 DER certificate
     * to {@code exportedCertPath} so clients can pin/trust the server over TLS 1.3.
     */
    public static X509Certificate ensureServerTlsMaterial(
            Path keystorePath, char[] keystorePassword, String alias, String commonName, Path exportedCertPath)
            throws GeneralSecurityException, IOException {
        X509Certificate cert = KeystoreManager.loadCertificate(keystorePath, keystorePassword, alias);
        if (cert == null) {
            KeyPair tlsKp = CryptoPrimitives.generateEcKeyPair();
            KeystoreManager.saveKeyPair(keystorePath, keystorePassword, alias, tlsKp, commonName);
            cert = KeystoreManager.loadCertificate(keystorePath, keystorePassword, alias);
        }
        if (exportedCertPath != null && cert != null) {
            Framing.writeFileAtomically(exportedCertPath, cert.getEncoded());
        }
        return cert;
    }

    public static SSLServerSocket createServerSocket(int port, Path keystorePath, char[] keystorePassword)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeystoreManager.loadExistingKeyStore(keystorePath, keystorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, CryptoPrimitives.secureRandom());

        SSLServerSocketFactory factory = ctx.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
        serverSocket.setEnabledProtocols(TLS_PROTOCOLS);
        serverSocket.setEnabledCipherSuites(TLS_CIPHER_SUITES);
        serverSocket.setReuseAddress(true);
        return serverSocket;
    }

    public static SSLSocket connectClientSocket(String host, int port, Path trustedCertDerPath)
            throws GeneralSecurityException, IOException {
        X509Certificate cert;
        try (InputStream in = Files.newInputStream(trustedCertDerPath)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        return connectClientSocket(host, port, cert);
    }

    public static SSLSocket connectClientSocket(String host, int port, X509Certificate pinnedServerCert)
            throws GeneralSecurityException, IOException {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("pinned-server", pinnedServerCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, tmf.getTrustManagers(), CryptoPrimitives.secureRandom());

        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);
        socket.setEnabledProtocols(TLS_PROTOCOLS);
        socket.setEnabledCipherSuites(TLS_CIPHER_SUITES);

        SSLParameters params = socket.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(params);

        socket.startHandshake();
        return socket;
    }
}
