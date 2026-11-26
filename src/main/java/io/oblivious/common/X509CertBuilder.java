package io.oblivious.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * Pure-Java ASN.1 DER X.509v3 self-signed EC certificate builder.
 *
 * <p>Enables standards-compliant {@code PKCS12} {@code PrivateKeyEntry} storage and
 * programmatic TLS 1.3 certificate + SubjectAlternativeName ({@code DNS:localhost, IP:127.0.0.1})
 * generation with zero external dependencies or {@code keytool} subprocesses.
 */
public final class X509CertBuilder {

    /** OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) */
    private static final byte[] OID_ECDSA_WITH_SHA256 =
            new byte[] {0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};
    /** OID 2.5.4.3 (id-at-commonName) */
    private static final byte[] OID_COMMON_NAME = new byte[] {0x06, 0x03, 0x55, 0x04, 0x03};
    /** OID 2.5.29.17 (id-ce-subjectAltName) */
    private static final byte[] OID_SUBJECT_ALT_NAME = new byte[] {0x06, 0x03, 0x55, 0x1D, 0x11};

    private static final DateTimeFormatter GENERALIZED_TIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private X509CertBuilder() {
    }

    public static X509Certificate generateSelfSignedEcCert(KeyPair keyPair, String commonName, int validDays)
            throws GeneralSecurityException {
        byte[] serialBytes = CryptoPrimitives.randomBytes(16);
        serialBytes[0] &= 0x7F;
        if (serialBytes[0] == 0) {
            serialBytes[0] = 0x01;
        }
        BigInteger serial = new BigInteger(1, serialBytes);

        Instant now = Instant.now();
        Instant notBefore = now.minus(1, ChronoUnit.DAYS);
        Instant notAfter = now.plus(validDays, ChronoUnit.DAYS);

        byte[] versionExplicit = derTag(0xA0, new byte[] {0x02, 0x01, 0x02}); // v3 = 2
        byte[] serialDer = derTag(0x02, serial.toByteArray());
        byte[] sigAlgId = derTag(0x30, OID_ECDSA_WITH_SHA256); // RFC 5758: omit NULL params
        byte[] x500Name = buildCommonName(commonName);
        byte[] validity = derTag(0x30, concat(
                derGeneralizedTime(notBefore),
                derGeneralizedTime(notAfter)));
        byte[] subjectPublicKeyInfo = keyPair.getPublic().getEncoded();
        byte[] extensionsExplicit = derTag(0xA3, derTag(0x30, buildLocalhostSanExtension()));

        byte[] tbsCertificate = derTag(0x30, concat(
                versionExplicit,
                serialDer,
                sigAlgId,
                x500Name,
                validity,
                x500Name,
                subjectPublicKeyInfo,
                extensionsExplicit));

        byte[] signature = CryptoPrimitives.signEcdsa(keyPair.getPrivate(), tbsCertificate);
        byte[] bitStringBody = new byte[1 + signature.length];
        bitStringBody[0] = 0x00; // 0 unused bits
        System.arraycopy(signature, 0, bitStringBody, 1, signature.length);
        byte[] signatureBitString = derTag(0x03, bitStringBody);

        byte[] fullCertDer = derTag(0x30, concat(tbsCertificate, sigAlgId, signatureBitString));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(fullCertDer));
    }

    private static byte[] buildCommonName(String cn) {
        byte[] utf8Cn = derTag(0x0C, cn.getBytes(StandardCharsets.UTF_8));
        byte[] attrTypeAndValue = derTag(0x30, concat(OID_COMMON_NAME, utf8Cn));
        byte[] rdnSet = derTag(0x31, attrTypeAndValue);
        return derTag(0x30, rdnSet);
    }

    private static byte[] buildLocalhostSanExtension() {
        byte[] dnsLocalhost = derTag(0x82, "localhost".getBytes(StandardCharsets.US_ASCII));
        byte[] ipLoopback = derTag(0x87, new byte[] {127, 0, 0, 1});
        byte[] generalNames = derTag(0x30, concat(dnsLocalhost, ipLoopback));
        byte[] extnValue = derTag(0x04, generalNames);
        return derTag(0x30, concat(OID_SUBJECT_ALT_NAME, extnValue));
    }

    private static byte[] derGeneralizedTime(Instant instant) {
        String formatted = GENERALIZED_TIME_FMT.format(instant);
        return derTag(0x18, formatted.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derTag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 128) {
            out.write(len);
        } else {
            byte[] lenBytes = toUnsignedBigEndian(len);
            out.write(0x80 | lenBytes.length);
            out.writeBytes(lenBytes);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] toUnsignedBigEndian(int value) {
        if (value <= 0xFF) {
            return new byte[] {(byte) value};
        } else if (value <= 0xFFFF) {
            return new byte[] {(byte) (value >>> 8), (byte) value};
        } else if (value <= 0xFFFFFF) {
            return new byte[] {(byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
        } else {
            return new byte[] {
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
            };
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] arr : arrays) {
            total += arr.length;
        }
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos += arr.length;
        }
        return result;
    }
}
