package io.oblivious.common;

import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Prevents path-traversal, null-byte injection, and separator smuggling on
 * untrusted identifiers (file IDs, block hashes, local aliases).
 */
public final class PathSanitizer {

    private static final int MAX_IDENTIFIER_LEN = 200;
    private static final Pattern SAFE_ID_PATTERN = Pattern.compile("^[A-Za-z0-9._-]+$");

    private PathSanitizer() {
    }

    public static String sanitizeIdentifier(String value, String fieldName) {
        if (value == null) {
            throw new SecurityException("Missing " + fieldName);
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.length() > MAX_IDENTIFIER_LEN) {
            throw new SecurityException("Invalid length for " + fieldName);
        }
        if (".".equals(trimmed) || "..".equals(trimmed) || trimmed.contains("..")) {
            throw new SecurityException("Path traversal sequence rejected in " + fieldName);
        }
        if (!SAFE_ID_PATTERN.matcher(trimmed).matches()) {
            throw new SecurityException("Disallowed characters in " + fieldName);
        }
        return trimmed;
    }

    public static Path resolveSafeChild(Path baseDir, String untrustedName, String fieldName) {
        String safeName = sanitizeIdentifier(untrustedName, fieldName);
        Path normalizedBase = baseDir.toAbsolutePath().normalize();
        Path resolved = normalizedBase.resolve(safeName).normalize();
        if (!resolved.startsWith(normalizedBase) || resolved.equals(normalizedBase)) {
            throw new SecurityException("Resolved path escapes base directory for " + fieldName);
        }
        return resolved;
    }
}
