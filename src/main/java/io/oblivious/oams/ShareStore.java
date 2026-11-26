package io.oblivious.oams;

import io.oblivious.common.CryptoPrimitives;
import io.oblivious.common.Framing;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe, owner-enforced access control registry for OAMS.
 *
 * <p>Fixes the missing-owner-authorization vulnerability by binding each {@code fileId}
 * to its creator's {@code ownerAnonId} on first registration/share and verifying
 * {@code requesterAnonId == ownerAnonId} on every subsequent share or revocation.
 */
public final class ShareStore {

    private static final byte[] MAGIC = "OAMSDB01".getBytes(StandardCharsets.US_ASCII);

    public record AccessGrant(String targetAnonId, String wrappedKeyPayload, Permission permission) {
        public AccessGrant {
            Objects.requireNonNull(targetAnonId, "targetAnonId");
            Objects.requireNonNull(wrappedKeyPayload, "wrappedKeyPayload");
            Objects.requireNonNull(permission, "permission");
        }
    }

    private static final class FileAcl {
        final String ownerAnonId;
        final Map<String, AccessGrant> grantsByRecipient = new HashMap<>();

        FileAcl(String ownerAnonId) {
            this.ownerAnonId = ownerAnonId;
        }
    }

    private final Path dbFile;
    private final Map<String, FileAcl> registry = new HashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public ShareStore(Path dbFile) throws IOException {
        this.dbFile = dbFile;
        load();
    }

    /**
     * Grants or updates access on {@code fileId} for {@code targetAnonId}.
     * Fails with {@code false} if {@code fileId} is already owned by a different {@code ownerAnonId}.
     */
    public boolean upsertGrant(
            String requesterAnonId,
            String fileId,
            String targetAnonId,
            String wrappedKeyPayload,
            Permission permission) throws IOException {
        lock.writeLock().lock();
        try {
            FileAcl acl = registry.get(fileId);
            if (acl == null) {
                acl = new FileAcl(requesterAnonId);
                registry.put(fileId, acl);
            } else if (!CryptoPrimitives.constantTimeEquals(acl.ownerAnonId, requesterAnonId)) {
                return false;
            }
            acl.grantsByRecipient.put(
                    targetAnonId, new AccessGrant(targetAnonId, wrappedKeyPayload, permission));
            saveLocked();
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public AccessGrant getGrant(String guestAnonId, String fileId) {
        lock.readLock().lock();
        try {
            FileAcl acl = registry.get(fileId);
            if (acl == null) {
                return null;
            }
            return acl.grantsByRecipient.get(guestAnonId);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Revokes {@code targetAnonId}'s grant on {@code fileId} iff {@code requesterAnonId} is the owner.
     */
    public boolean revokeGrant(String requesterAnonId, String fileId, String targetAnonId)
            throws IOException {
        lock.writeLock().lock();
        try {
            FileAcl acl = registry.get(fileId);
            if (acl == null || !CryptoPrimitives.constantTimeEquals(acl.ownerAnonId, requesterAnonId)) {
                return false;
            }
            AccessGrant removed = acl.grantsByRecipient.remove(targetAnonId);
            if (removed == null) {
                return false;
            }
            saveLocked();
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public List<String> listSharedFileIdsForGuest(String guestAnonId) {
        lock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (Map.Entry<String, FileAcl> entry : registry.entrySet()) {
                if (entry.getValue().grantsByRecipient.containsKey(guestAnonId)) {
                    result.add(entry.getKey());
                }
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    private void saveLocked() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(MAGIC);
            out.writeInt(registry.size());
            for (Map.Entry<String, FileAcl> fileEntry : registry.entrySet()) {
                out.writeUTF(fileEntry.getKey());
                FileAcl acl = fileEntry.getValue();
                out.writeUTF(acl.ownerAnonId);
                out.writeInt(acl.grantsByRecipient.size());
                for (AccessGrant grant : acl.grantsByRecipient.values()) {
                    out.writeUTF(grant.targetAnonId());
                    out.writeUTF(grant.wrappedKeyPayload());
                    out.writeUTF(grant.permission().name());
                }
            }
        }
        Framing.writeFileAtomically(dbFile, bos.toByteArray());
    }

    private void load() throws IOException {
        if (!Files.exists(dbFile)) {
            return;
        }
        byte[] raw = Files.readAllBytes(dbFile);
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw))) {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            for (int i = 0; i < MAGIC.length; i++) {
                if (magic[i] != MAGIC[i]) {
                    throw new IOException("Invalid ShareStore file header");
                }
            }
            int fileCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            for (int i = 0; i < fileCount; i++) {
                String fileId = in.readUTF();
                String ownerId = in.readUTF();
                FileAcl acl = new FileAcl(ownerId);
                int grantCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
                for (int j = 0; j < grantCount; j++) {
                    String targetId = in.readUTF();
                    String wrappedKey = in.readUTF();
                    Permission perm = Permission.parse(in.readUTF());
                    acl.grantsByRecipient.put(targetId, new AccessGrant(targetId, wrappedKey, perm));
                }
                registry.put(fileId, acl);
            }
        }
    }
}
