package io.oblivious.obss;

import io.oblivious.common.Framing;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;

/**
 * Authenticated, encrypted per-file manifest storing ordered block hashes and
 * normalized keywords without Java {@code ObjectInputStream} deserialization.
 *
 * <p>Binds {@code "OBSS-MANIFEST|" + fileId} as AEAD / EtM-HMAC AAD so the server
 * cannot substitute one file's manifest for another.
 */
public record EncryptedManifest(String fileId, List<String> blockIds, List<String> keywords) {

    private static final byte[] MAGIC = "OBSMAN01".getBytes(StandardCharsets.US_ASCII);

    public EncryptedManifest {
        blockIds = List.copyOf(blockIds);
        keywords = List.copyOf(keywords);
    }

    public byte[] seal(SecretKey fileRootKey, CipherMode mode)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(MAGIC);
            out.writeUTF(fileId);
            out.writeInt(blockIds.size());
            for (String b : blockIds) {
                out.writeUTF(b);
            }
            out.writeInt(keywords.size());
            for (String kw : keywords) {
                out.writeUTF(kw);
            }
        }
        return BlockCipherEngine.encrypt(
                bos.toByteArray(), fileRootKey, mode, manifestAad(fileId));
    }

    public static EncryptedManifest open(String expectedFileId, byte[] ciphertext, SecretKey fileRootKey)
            throws GeneralSecurityException, IOException {
        byte[] plain = BlockCipherEngine.decrypt(ciphertext, fileRootKey, manifestAad(expectedFileId));
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain))) {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            for (int i = 0; i < MAGIC.length; i++) {
                if (magic[i] != MAGIC[i]) {
                    throw new IOException("Invalid manifest header");
                }
            }
            String storedFileId = in.readUTF();
            if (!expectedFileId.equals(storedFileId)) {
                throw new SecurityException("Manifest fileId mismatch");
            }
            int blockCount = Framing.readBoundedCount(in, 1_000_000);
            List<String> blocks = new ArrayList<>(blockCount);
            for (int i = 0; i < blockCount; i++) {
                blocks.add(in.readUTF());
            }
            int kwCount = Framing.readBoundedCount(in, Framing.MAX_COLLECTION_ITEMS);
            List<String> kws = new ArrayList<>(kwCount);
            for (int i = 0; i < kwCount; i++) {
                kws.add(in.readUTF());
            }
            return new EncryptedManifest(storedFileId, blocks, kws);
        }
    }

    private static byte[] manifestAad(String fileId) {
        return ("OBSS-MANIFEST|" + fileId).getBytes(StandardCharsets.UTF_8);
    }
}
