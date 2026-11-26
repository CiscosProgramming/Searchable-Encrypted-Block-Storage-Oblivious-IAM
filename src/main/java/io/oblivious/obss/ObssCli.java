package io.oblivious.obss;

import io.oblivious.common.PathSanitizer;
import io.oblivious.oas.OasClient;
import io.oblivious.oas.OasServer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

/**
 * Unified interactive and non-interactive CLI for the Oblivious Block Storage Client.
 *
 * <p>Non-interactive usage (compatible with automated grading/benchmark scripts):
 * <pre>
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret PUT path/to/file.pdf "kw1,kw2"
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret LIST
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret SEARCH "kw1,kw2"
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret GET FILE file.pdf ./out
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret GET KEYWORDS "kw1,kw2" ./out
 *   java ... io.oblivious.obss.ObssCli --id alice --pwd secret GET CHECKINTEGRITY file.pdf
 * </pre>
 */
public final class ObssCli {

    private ObssCli() {
    }

    public static void main(String[] args) throws Exception {
        Path sharedDir = Path.of("runtime/shared");
        Path clientDir = Path.of("runtime/client");
        Path configPath = Path.of("config/cryptoconfig.properties");

        OasClient oasClient = new OasClient(
                "localhost", OasServer.DEFAULT_PORT, sharedDir.resolve("oas-tls.crt"), clientDir);
        ObssClient obssClient = new ObssClient(
                "localhost", ObssServer.DEFAULT_PORT, sharedDir.resolve("obss-tls.crt"), configPath);

        if (args.length > 0) {
            runNonInteractive(args, oasClient, obssClient);
        } else {
            runInteractive(oasClient, obssClient);
        }
    }

    private static void runNonInteractive(String[] args, OasClient oasClient, ObssClient obssClient)
            throws Exception {
        String alias = null;
        char[] password = null;
        List<String> cmdArgs = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-id", "--id" -> {
                    if (i + 1 < args.length) {
                        alias = args[++i];
                    }
                }
                case "-pwd", "--pwd" -> {
                    if (i + 1 < args.length) {
                        password = args[++i].toCharArray();
                    }
                }
                default -> cmdArgs.add(args[i]);
            }
        }

        if (alias == null || password == null || cmdArgs.isEmpty()) {
            System.err.println("Usage: ObssCli --id <alias> --pwd <password> <PUT|GET|LIST|SEARCH> [args...]");
            System.exit(1);
            return;
        }

        Path ksPath = oasClient.keystorePath(PathSanitizer.sanitizeIdentifier(alias, "alias"));
        try {
            String cmd = cmdArgs.get(0).toUpperCase(Locale.ROOT);
            switch (cmd) {
                case "PUT" -> {
                    Path file = Path.of(cmdArgs.get(1));
                    List<String> kws = cmdArgs.size() > 2 ? splitCsv(cmdArgs.get(2)) : List.of();
                    ObssClient.UploadResult res = obssClient.putFile(file, kws, ksPath, password);
                    System.out.printf("OK: stored %s (%d blocks, %s)%n",
                            res.fileId(), res.blockCount(), res.cipherMode());
                }
                case "LIST" -> {
                    for (String f : obssClient.listOwnerFiles(ksPath, password)) {
                        System.out.println(" - " + f);
                    }
                }
                case "SEARCH" -> {
                    List<String> kws = splitCsv(cmdArgs.get(1));
                    List<String> hits = obssClient.searchOwnerFiles(kws, ksPath, password);
                    hits.forEach(f -> System.out.println(" - " + f));
                }
                case "GET" -> {
                    String sub = cmdArgs.get(1).toUpperCase(Locale.ROOT);
                    switch (sub) {
                        case "FILE" -> {
                            String filename = cmdArgs.get(2);
                            Path outDir = Path.of(cmdArgs.get(3));
                            Path dest = outDir.resolve(filename);
                            obssClient.getOwnerFile(filename, dest, ksPath, password);
                            System.out.println("OK: reconstructed " + dest);
                        }
                        case "KEYWORDS" -> {
                            List<String> kws = splitCsv(cmdArgs.get(2));
                            Path outDir = Path.of(cmdArgs.get(3));
                            List<String> hits = obssClient.searchOwnerFiles(kws, ksPath, password);
                            for (String f : hits) {
                                obssClient.getOwnerFile(f, outDir.resolve(f), ksPath, password);
                                System.out.println("OK: downloaded " + f);
                            }
                        }
                        case "CHECKINTEGRITY" -> {
                            String filename = cmdArgs.get(2);
                            boolean valid = obssClient.verifyFileIntegrity(filename, ksPath, password);
                            System.out.println(valid ? "INTEGRITY_OK" : "INTEGRITY_FAILED");
                            if (!valid) {
                                System.exit(2);
                            }
                        }
                        default -> throw new IllegalArgumentException("Unknown GET subcommand: " + sub);
                    }
                }
                default -> throw new IllegalArgumentException("Unknown command: " + cmd);
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void runInteractive(OasClient oasClient, ObssClient obssClient) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("=== Oblivious Block Storage Client (TLS 1.3) ===");
            System.out.print("Local alias: ");
            String alias = PathSanitizer.sanitizeIdentifier(scanner.nextLine().trim(), "alias");
            System.out.print("Password: ");
            char[] password = scanner.nextLine().toCharArray();
            Path ksPath = oasClient.keystorePath(alias);

            System.out.print("Mode (1 = Owner, 2 = Shared User): ");
            boolean ownerMode = !"2".equals(scanner.nextLine().trim());

            try {
                while (true) {
                    if (ownerMode) {
                        System.out.println("\n1. PUT  2. GET  3. SEARCH  4. LIST  5. CHECKINTEGRITY  0. EXIT");
                        System.out.print("> ");
                        switch (scanner.nextLine().trim()) {
                            case "1" -> {
                                System.out.print("Local file path: ");
                                Path file = Path.of(scanner.nextLine().trim());
                                System.out.print("Keywords (comma-separated): ");
                                List<String> kws = splitCsv(scanner.nextLine());
                                ObssClient.UploadResult r = obssClient.putFile(file, kws, ksPath, password);
                                System.out.printf("OK (%d blocks, %s)%n", r.blockCount(), r.cipherMode());
                            }
                            case "2" -> {
                                System.out.print("File ID: ");
                                String f = scanner.nextLine().trim();
                                Path out = Path.of("retrieved_" + f);
                                obssClient.getOwnerFile(f, out, ksPath, password);
                                System.out.println("OK -> " + out);
                            }
                            case "3" -> {
                                System.out.print("Keywords (comma-separated): ");
                                List<String> hits = obssClient.searchOwnerFiles(
                                        splitCsv(scanner.nextLine()), ksPath, password);
                                System.out.println(hits.isEmpty() ? "NOK" : hits);
                            }
                            case "4" -> System.out.println(obssClient.listOwnerFiles(ksPath, password));
                            case "5" -> {
                                System.out.print("File ID: ");
                                String f = scanner.nextLine().trim();
                                System.out.println(
                                        obssClient.verifyFileIntegrity(f, ksPath, password) ? "OK" : "NOK");
                            }
                            case "0" -> {
                                return;
                            }
                            default -> System.out.println("NOK");
                        }
                    } else {
                        System.out.println("\n1. SEARCH Shared  2. GET Shared  0. EXIT");
                        System.out.print("> ");
                        switch (scanner.nextLine().trim()) {
                            case "1" -> {
                                System.out.print("Keywords (comma-separated): ");
                                List<String> hits = obssClient.searchSharedFiles(
                                        splitCsv(scanner.nextLine()), ksPath, password);
                                System.out.println(hits.isEmpty() ? "NOK" : hits);
                            }
                            case "2" -> {
                                System.out.print("File ID: ");
                                String f = scanner.nextLine().trim();
                                Path out = Path.of("retrieved_" + f);
                                obssClient.getSharedFile(f, out, ksPath, password);
                                System.out.println("OK -> " + out);
                            }
                            case "0" -> {
                                return;
                            }
                            default -> System.out.println("NOK");
                        }
                    }
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static List<String> splitCsv(String line) {
        if (line == null || line.isBlank()) {
            return List.of();
        }
        return Arrays.stream(line.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
