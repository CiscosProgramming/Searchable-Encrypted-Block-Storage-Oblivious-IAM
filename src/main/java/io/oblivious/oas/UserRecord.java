package io.oblivious.oas;

import java.util.Arrays;
import java.util.Objects;

/**
 * Oblivious account record indexed solely by an anonymous P-256 public key ({@code anonId}).
 * No usernames, emails, or plaintext credentials are stored.
 */
public record UserRecord(
        String anonId,
        String passwordVerifier,
        byte[] salt,
        String hashedAttribute) {

    public UserRecord {
        Objects.requireNonNull(anonId, "anonId");
        Objects.requireNonNull(passwordVerifier, "passwordVerifier");
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(hashedAttribute, "hashedAttribute");
        salt = salt.clone();
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserRecord other)) {
            return false;
        }
        return anonId.equals(other.anonId)
                && passwordVerifier.equals(other.passwordVerifier)
                && Arrays.equals(salt, other.salt)
                && hashedAttribute.equals(other.hashedAttribute);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(anonId, passwordVerifier, hashedAttribute);
        return 31 * result + Arrays.hashCode(salt);
    }
}
