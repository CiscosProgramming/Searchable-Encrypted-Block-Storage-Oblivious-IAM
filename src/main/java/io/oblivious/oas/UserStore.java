package io.oblivious.oas;

import io.oblivious.common.Framing;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe, crash-consistent store for {@link UserRecord} entries.
 * Uses deterministic binary encoding instead of {@code ObjectInputStream} to prevent
 * deserialization gadget vulnerabilities, and persists every mutation atomically.
 */
public final class UserStore {

    private static final byte[] MAGIC = "OASDB001".getBytes(StandardCharsets.US_ASCII);

    private final Path dbFile;
    private final ConcurrentHashMap<String, UserRecord> users = new ConcurrentHashMap<>();
    private final ReentrantReadWriteLock persistenceLock = new ReentrantReadWriteLock();

    public UserStore(Path dbFile) throws IOException {
        this.dbFile = dbFile;
        load();
    }

    public boolean exists(String anonId) {
        return users.containsKey(anonId);
    }

    public UserRecord get(String anonId) {
        return users.get(anonId);
    }

    public boolean putIfAbsent(UserRecord record) throws IOException {
        persistenceLock.writeLock().lock();
        try {
            if (users.putIfAbsent(record.anonId(), record) != null) {
                return false;
            }
            saveLocked();
            return true;
        } finally {
            persistenceLock.writeLock().unlock();
        }
    }

    public boolean replace(UserRecord updated) throws IOException {
        persistenceLock.writeLock().lock();
        try {
            if (!users.containsKey(updated.anonId())) {
                return false;
            }
            users.put(updated.anonId(), updated);
            saveLocked();
            return true;
        } finally {
            persistenceLock.writeLock().unlock();
        }
    }

    public boolean remove(String anonId) throws IOException {
        persistenceLock.writeLock().lock();
        try {
            if (users.remove(anonId) == null) {
                return false;
            }
            saveLocked();
            return true;
        } finally {
            persistenceLock.writeLock().unlock();
        }
    }

    private void saveLocked() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(MAGIC);
            out.writeInt(users.size());
            for (Map.Entry<String, UserRecord> entry : users.entrySet()) {
                UserRecord r = entry.getValue();
                out.writeUTF(r.anonId());
                out.writeUTF(r.passwordVerifier());
                Framing.writeBytes(out, r.salt());
                out.writeUTF(r.hashedAttribute());
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
                    throw new IOException("Invalid UserStore file header");
                }
            }
            int count = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            for (int i = 0; i < count; i++) {
                String anonId = in.readUTF();
                String verifier = in.readUTF();
                byte[] salt = Framing.readBoundedBytes(in, 64);
                String attr = in.readUTF();
                users.put(anonId, new UserRecord(anonId, verifier, salt, attr));
            }
        }
    }
}
