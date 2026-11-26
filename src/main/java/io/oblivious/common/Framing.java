package io.oblivious.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Bounded binary framing and crash-safe atomic file persistence helpers.
 */
public final class Framing {

    /** Maximum frame size accepted over the wire (16 MiB) to prevent OOM DoS. */
    public static final int MAX_FRAME_BYTES = 16 * 1024 * 1024;
    /** Maximum collection cardinality accepted in a single protocol message. */
    public static final int MAX_COLLECTION_ITEMS = 10_000;

    private Framing() {
    }

    public static void writeBytes(DataOutputStream out, byte[] payload) throws IOException {
        if (payload.length > MAX_FRAME_BYTES) {
            throw new IOException("Frame exceeds maximum allowed size: " + payload.length);
        }
        out.writeInt(payload.length);
        out.write(payload);
    }

    public static byte[] readBoundedBytes(DataInputStream in, int maxBytes) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > maxBytes) {
            throw new IOException("Invalid or oversized frame length: " + len);
        }
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    public static int readBoundedCount(DataInputStream in, int maxCount) throws IOException {
        int count = in.readInt();
        if (count < 0 || count > maxCount) {
            throw new IOException("Invalid or oversized item count: " + count);
        }
        return count;
    }

    /**
     * Writes bytes to a sibling temporary file and atomically renames onto target
     * so concurrent readers or crashes never observe torn writes.
     */
    public static void writeFileAtomically(Path target, byte[] content) throws IOException {
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tempFile = Files.createTempFile(parent, target.getFileName().toString() + ".", ".tmp");
        try {
            Files.write(tempFile, content);
            try {
                Files.move(tempFile, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}
