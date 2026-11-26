package io.oblivious.common;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dependency-free RFC 7515 / RFC 7519 {@code ES256} (ECDSA P-256 + SHA-256 in IEEE P1363 format)
 * JSON Web Token issuer and stateless verifier.
 *
 * <p>Strictly enforces {@code "alg":"ES256"} in the JOSE header (preventing {@code alg:none} or
 * algorithm-confusion attacks), checks {@code exp} and {@code iat}, and extracts the anonymous
 * subject ({@code sub} = Base64 X.509 ECC Public Key).
 */
public final class JwtService {

    private static final String HEADER_JSON = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
    private static final String ENCODED_HEADER =
            Base64.getUrlEncoder().withoutPadding().encodeToString(HEADER_JSON.getBytes(StandardCharsets.UTF_8));
    private static final long MAX_CLOCK_SKEW_SECONDS = 30L;

    private static final Pattern STRING_CLAIM = Pattern.compile("\"([A-Za-z0-9_]+)\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern NUMERIC_CLAIM = Pattern.compile("\"([A-Za-z0-9_]+)\"\\s*:\\s*(-?\\d+)");

    public record VerifiedClaims(String subject, String tokenId, long issuedAtEpochSec, long expiresAtEpochSec) {
    }

    private JwtService() {
    }

    public static String issueToken(PrivateKey issuerPrivateKey, String subjectAnonId, long ttlSeconds)
            throws GeneralSecurityException {
        Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey");
        Objects.requireNonNull(subjectAnonId, "subjectAnonId");
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("ttlSeconds must be positive");
        }
        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;
        String jti = CryptoPrimitives.generateNonceBase64Url(16);

        String payloadJson = String.format(
                "{\"sub\":\"%s\",\"jti\":\"%s\",\"iat\":%d,\"exp\":%d}",
                escapeJson(subjectAnonId), escapeJson(jti), now, exp);
        String encodedPayload = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        String signingInput = ENCODED_HEADER + "." + encodedPayload;
        byte[] sigBytes = CryptoPrimitives.signEcdsaP1363(
                issuerPrivateKey, signingInput.getBytes(StandardCharsets.US_ASCII));
        String encodedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
        return signingInput + "." + encodedSig;
    }

    /**
     * Verifies a compact JWS/JWT against {@code issuerPublicKey} and current wall-clock time.
     *
     * @return verified claims if authentic and unexpired, or {@code null} otherwise
     */
    public static VerifiedClaims verifyToken(PublicKey issuerPublicKey, String compactJwt) {
        return verifyTokenAt(issuerPublicKey, compactJwt, Instant.now().getEpochSecond());
    }

    public static VerifiedClaims verifyTokenAt(PublicKey issuerPublicKey, String compactJwt, long nowEpochSec) {
        if (issuerPublicKey == null || compactJwt == null || compactJwt.isBlank()) {
            return null;
        }
        String[] parts = compactJwt.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            return null;
        }
        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String alg = extractStringClaim(headerJson, "alg");
            String typ = extractStringClaim(headerJson, "typ");
            if (!"ES256".equals(alg) || !"JWT".equals(typ)) {
                return null;
            }

            String signingInput = parts[0] + "." + parts[1];
            byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
            if (!CryptoPrimitives.verifyEcdsaP1363(
                    issuerPublicKey, signingInput.getBytes(StandardCharsets.US_ASCII), sigBytes)) {
                return null;
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String sub = extractStringClaim(payloadJson, "sub");
            String jti = extractStringClaim(payloadJson, "jti");
            Long iat = extractNumericClaim(payloadJson, "iat");
            Long exp = extractNumericClaim(payloadJson, "exp");
            if (sub == null || sub.isBlank() || jti == null || iat == null || exp == null) {
                return null;
            }
            if (nowEpochSec >= exp || iat > nowEpochSec + MAX_CLOCK_SKEW_SECONDS) {
                return null;
            }
            return new VerifiedClaims(sub, jti, iat, exp);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String extractStringClaim(String json, String key) {
        Matcher m = STRING_CLAIM.matcher(json);
        while (m.find()) {
            if (key.equals(m.group(1))) {
                return m.group(2);
            }
        }
        return null;
    }

    private static Long extractNumericClaim(String json, String key) {
        Matcher m = NUMERIC_CLAIM.matcher(json);
        while (m.find()) {
            if (key.equals(m.group(1))) {
                try {
                    return Long.parseLong(m.group(2));
                } catch (NumberFormatException e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
