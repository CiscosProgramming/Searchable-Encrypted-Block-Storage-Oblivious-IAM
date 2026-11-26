package io.oblivious.oams;

import java.util.Locale;

/**
 * Fine-grained access permissions managed by OAMS and cryptographically bound
 * as AES-GCM Additional Authenticated Data (AAD) inside wrapped file keys.
 */
public enum Permission {
    READ,
    SEARCH;

    public static Permission parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("Missing permission");
        }
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "READ", "READ_ONLY" -> READ;
            case "SEARCH", "READ_SEARCH", "READ_AND_SEARCH" -> SEARCH;
            default -> throw new IllegalArgumentException("Unsupported permission: " + raw);
        };
    }

    public boolean allowsSearch() {
        return this == SEARCH;
    }
}
