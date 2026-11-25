package io.pcapanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Views that read the kept capture again: Follow stream, Flow graph and Export objects. */
public final class Views {
    static final int FLOW_ROWS = 1000, FOLLOW_BYTES = 2 << 20;
    static final long OBJECTS_BYTES = 200L << 20;
    static final List<String> OBJECT_PROTOCOLS = List.of("http", "imf", "smb", "tftp", "ftp-data", "dicom");
    private static final Pattern SAFE_NAME = Pattern.compile("[^A-Za-z0-9._-]+");

    private Views() {}

    /** Each side in turn, as Wireshark's Follow TCP Stream shows it. Secrets are masked. The result is chunks of {side, text, cut}. */
    public static Map<String, Object> follow(TShark ts, Path capture, int stream, String mode) throws TShark.TsharkException {
        boolean hex = mode.equals("hex");
        List<Map<String, Object>> chunks = new ArrayList<>();
        String node0 = null;
        long size = 0;
        for (String line : ts.followLines(capture, stream, hex ? "hex" : "raw", 180)) {
            if (line.startsWith("===") || line.startsWith("Follow:") || line.startsWith("Filter:") || line.startsWith("Node 1:")) continue;
            if (line.startsWith("Node 0:")) { node0 = line.substring(7).strip(); continue; }
            int side = line.startsWith("\t") ? 1 : 0;
            String text;
            if (hex) text = line.strip();
            else {
                try { text = new String(java.util.HexFormat.of().parseHex(line.strip()), StandardCharsets.UTF_8); } catch (IllegalArgumentException e) { continue; }
            }
            if (text.isEmpty()) continue;
            if (size + text.length() > FOLLOW_BYTES) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("side", side); c.put("text", "…"); c.put("cut", true);
                chunks.add(c);
                break;
            }
            size += text.length();
            Map<String, Object> lastChunk = chunks.isEmpty() ? null : chunks.get(chunks.size() - 1);
            if (lastChunk != null && ((Number) lastChunk.get("side")).intValue() == side && !Boolean.TRUE.equals(lastChunk.get("cut"))) lastChunk.put("text", lastChunk.get("text") + (hex ? "\n" : "") + text);
            else {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("side", side); c.put("text", text);
                chunks.add(c);
            }
        }
        if (!hex) for (Map<String, Object> c : chunks) c.put("text", Privacy.maskStream((String) c.get("text")));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("client", node0); out.put("chunks", chunks); out.put("mode", mode);
        return out;
    }

    /** Packets between hosts on a time axis, as in Wireshark's Flow Graph. */
    public static Map<String, Object> flow(TShark ts, Path capture, String display, Integer stream) throws TShark.TsharkException {
        String expr = stream != null ? "tcp.stream == " + stream : (display == null || display.isBlank() ? null : display);
        List<String> fields = List.of("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "_ws.col.protocol", "_ws.col.info");
        List<String[]> raw = ts.query(capture, expr, fields, FLOW_ROWS, 180);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String[] p : raw) {
            if (p.length < 8 || p[1].isEmpty()) continue;
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("frame", Integer.parseInt(p[0])); r.put("t", Double.parseDouble(p[1]));
            r.put("src", !p[2].isEmpty() ? p[2] : !p[4].isEmpty() ? p[4] : "?"); r.put("dst", !p[3].isEmpty() ? p[3] : !p[5].isEmpty() ? p[5] : "?");
            r.put("protocol", p[6]); String info = Privacy.maskUri(p[7]); r.put("info", info.length() > 200 ? info.substring(0, 200) : info);
            rows.add(r);
        }
        List<String> hosts = new ArrayList<>();
        for (Map<String, Object> r : rows) for (String h : new String[] {(String) r.get("src"), (String) r.get("dst")}) if (!hosts.contains(h)) hosts.add(h);
        double t0 = rows.isEmpty() ? 0 : (Double) rows.get(0).get("t");
        for (Map<String, Object> r : rows) r.put("t", (Double) r.get("t") - t0);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("hosts", hosts); out.put("rows", rows); out.put("cut", rows.size() >= FLOW_ROWS); out.put("filter", expr);
        return out;
    }

    /** Finds the files in the capture and keeps them next to the analysis until it is deleted. Returns {protocol, name, file, size, kept}. */
    public static List<Map<String, Object>> objects(TShark ts, Path capture, Path folder) throws TShark.TsharkException, IOException {
        if (Files.isDirectory(folder)) try (var walk = Files.walk(folder)) { walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        Files.createDirectories(folder);
        List<Map<String, Object>> found = new ArrayList<>();
        long total = 0;
        for (String proto : OBJECT_PROTOCOLS) {
            Path stage = Files.createTempDirectory(folder.getParent(), "obj-stage-");
            try {
                if (!ts.exportObjects(capture, proto, stage, 300)) continue;
                List<Path> files = new ArrayList<>();
                try (var ds = Files.newDirectoryStream(stage)) { for (Path f : ds) if (Files.isRegularFile(f)) files.add(f); }
                Collections.sort(files);
                for (Path f : files) {
                    long size = Files.size(f);
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("protocol", proto); m.put("name", f.getFileName().toString()); m.put("size", size);
                    if (total + size > OBJECTS_BYTES) { m.put("kept", false); found.add(m); continue; }
                    String stored = String.format("%04d-%s", found.size(), cut(SAFE_NAME.matcher(f.getFileName().toString()).replaceAll("_"), 120));
                    Files.move(f, folder.resolve(stored));
                    total += size;
                    m.put("file", stored); m.put("kept", true);
                    found.add(m);
                }
            } finally {
                try (var walk = Files.walk(stage)) { walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
            }
        }
        return found;
    }

    private static String cut(String s, int n) { return s.length() > n ? s.substring(0, n) : s; }

    /** Which page each request came from, by its Referer header. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> sequences(Map<String, Object> result, Map<String, Object> details) {
        Pattern referer = Pattern.compile("(?im)^referer:\\s*(\\S+)");
        Map<String, Map<String, Integer>> found = new LinkedHashMap<>();
        for (Map<String, Object> t : (List<Map<String, Object>>) result.get("transactions")) {
            Map<String, Object> d = (Map<String, Object>) details.get(String.valueOf(((Number) t.get("id")).intValue()));
            String headers = d == null ? "" : String.valueOf(d.getOrDefault("req_headers", ""));
            Matcher m = referer.matcher(headers);
            String target = (t.get("host") == null ? "" : t.get("host")) + String.valueOf(t.get("uri") == null ? "" : t.get("uri"));
            found.computeIfAbsent(m.find() ? m.group(1) : "", k -> new HashMap<>()).merge(target, 1, Integer::sum);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        found.entrySet().stream().sorted((a, b) -> b.getValue().values().stream().mapToInt(i -> i).sum() - a.getValue().values().stream().mapToInt(i -> i).sum()).limit(500).forEach(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("referer", e.getKey().isEmpty() ? null : e.getKey());
            List<Map<String, Object>> targets = new ArrayList<>();
            e.getValue().entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(50).forEach(t -> { Map<String, Object> x = new LinkedHashMap<>(); x.put("url", t.getKey()); x.put("requests", t.getValue()); targets.add(x); });
            m.put("targets", targets);
            out.add(m);
        });
        return out;
    }
}
