package io.pcapanalyzer;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Analyzes one capture and saves the result where the web pages and the command line find it. */
public final class Runner {
    private Runner() {}

    /** Runs tshark over the capture and saves the result, headers and meta next to it. */
    public static void analyze(String id, Path dir, Path cap, Path keylog, Path rsa, List<String> decode, String filter, String name, String client) throws TShark.TsharkException, IOException {
        TShark ts = new TShark(Settings.tshark());
        ts.version();
        Analysis.SLOW_S = Records.slowS();
        Map<String, Object> result = Analysis.run(ts, cap, keylog, rsa, decode, filter, Settings.timeoutSeconds());
        removeOwn(dir, rsa);
        @SuppressWarnings("unchecked") Map<String, Object> summary = (Map<String, Object>) result.get("summary");
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("id", id); meta.put("filename", name); meta.put("size", Files.size(cap)); meta.put("created", System.currentTimeMillis() / 1000.0);
        meta.put("packets", summary.get("packets")); meta.put("capture_start", summary.get("start")); meta.put("capture_end", summary.get("end"));
        meta.put("connections", summary.get("connections")); meta.put("transactions", summary.get("requests")); meta.put("filter", filter);
        Object det = result.remove("_details");
        Vault.writeText(dir.resolve("details.json"), Json.write(det == null ? new LinkedHashMap<>() : det));
        Vault.writeText(dir.resolve("result.json"), Json.write(result));
        Vault.writeText(dir.resolve("meta.json"), Json.write(meta));
        removeOwn(dir, keylog); // keys are removed after the analysis, but only the copies kept in the analysis folder
        if (!Settings.keepCapture()) Files.deleteIfExists(cap);
        Records.audit(client.isEmpty() ? "upload" : "upload", client, id + " " + name);
    }

    /** Deletes a file only when it lives inside the analysis folder, so a file the user named on the command line is never touched. */
    private static void removeOwn(Path dir, Path file) throws IOException {
        if (file != null && file.toAbsolutePath().normalize().startsWith(dir.toAbsolutePath().normalize())) Files.deleteIfExists(file);
    }
}
