package io.pcapanalyzer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Several TLS key logs as one file for tshark, such as the client to NetScaler leg and the NetScaler to gateway leg. */
final class KeyLogs {
    static final long MAX_BYTES = 64L << 20;

    private KeyLogs() {}

    /** True when the start of the file looks like an NSS key log. */
    static boolean looksLikeKeyLog(Path file) throws IOException {
        byte[] head = new byte[4096];
        int n;
        try (var in = Files.newInputStream(file)) { n = in.readNBytes(head, 0, head.length); }
        String text = new String(head, 0, Math.max(n, 0), StandardCharsets.ISO_8859_1);
        return text.contains("CLIENT_RANDOM ") || text.contains("_TRAFFIC_SECRET") || text.contains("RSA ");
    }

    /** Writes every distinct line of the key logs to out, in order, and returns how many key lines it holds. */
    static int join(List<Path> logs, Path out) throws IOException {
        Set<String> seen = new HashSet<>();
        int keys = 0;
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.ISO_8859_1)) {
            for (Path log : logs) {
                try (BufferedReader r = Files.newBufferedReader(log, StandardCharsets.ISO_8859_1)) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        line = line.strip();
                        if (line.isEmpty() || !seen.add(line)) continue;
                        w.write(line);
                        w.write('\n');
                        if (!line.startsWith("#")) keys++;
                    }
                }
            }
        }
        return keys;
    }
}
