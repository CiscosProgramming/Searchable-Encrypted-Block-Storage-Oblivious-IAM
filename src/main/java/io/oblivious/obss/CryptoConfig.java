package io.oblivious.obss;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Dynamically loads client cryptographic settings from {@code config/cryptoconfig.properties}
 * so cipher suites can be switched at runtime without recompiling source code.
 */
public record CryptoConfig(CipherMode cipherMode, int keySizeBits, int blockSizeBytes) {

    public static final int DEFAULT_BLOCK_SIZE = 4096;

    public CryptoConfig {
        if (keySizeBits != 256) {
            throw new IllegalArgumentException("Only 256-bit keys are permitted (got " + keySizeBits + ")");
        }
        if (blockSizeBytes < 256 || blockSizeBytes > 4 * 1024 * 1024) {
            throw new IllegalArgumentException("Invalid block size: " + blockSizeBytes);
        }
    }

    public static CryptoConfig defaults() {
        return new CryptoConfig(CipherMode.AES_256_GCM, 256, DEFAULT_BLOCK_SIZE);
    }

    public static CryptoConfig load(Path configPath) throws IOException {
        if (configPath == null || !Files.exists(configPath)) {
            return defaults();
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(configPath)) {
            props.load(in);
        }
        CipherMode mode = CipherMode.parse(props.getProperty("cipher.mode", "AES_256_GCM"));
        int keyBits = Integer.parseInt(props.getProperty("key.size.bits", "256").trim());
        int blockBytes = Integer.parseInt(
                props.getProperty("block.size.bytes", String.valueOf(DEFAULT_BLOCK_SIZE)).trim());
        return new CryptoConfig(mode, keyBits, blockBytes);
    }
}
