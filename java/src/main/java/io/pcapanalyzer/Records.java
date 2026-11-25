package io.pcapanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Small records kept beside the analyses: limits, baseline, activity log and API tokens. */
public final class Records {
    public static final String TOKEN_PREFIX = "pat_";
    private static final int AUDIT_KEEP = 10_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Object LOCK = new Object();

    private Records() {}

    @SuppressWarnings("unchecked")
    private static Object read(String name) {
        try {
            return Json.parse(Files.readString(Settings.workdir().resolve(name), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static void write(String name, Object data) throws IOException {
        Files.createDirectories(Settings.workdir());
        Path tmp = Settings.workdir().resolve(name + "." + Long.toHexString(RANDOM.nextLong()) + ".tmp");
        Files.writeString(tmp, Json.write(data), StandardCharsets.UTF_8);
        Files.move(tmp, Settings.workdir().resolve(name), StandardCopyOption.ATOMIC_MOVE);
    }

    // ---- limits

    @SuppressWarnings("unchecked")
    public static Map<String, Object> thresholds() {
        Object o = read("thresholds.json");
        Map<String, Object> m = o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("slow_s", m.get("slow_s") instanceof Number n ? n.doubleValue() : Analysis.DEFAULT_SLOW_S);
        out.put("targets", m.get("targets") instanceof List ? m.get("targets") : new ArrayList<>());
        return out;
    }

    public static double slowS() { return ((Number) thresholds().get("slow_s")).doubleValue(); }

    public static void saveThresholds(double slow, List<Map<String, Object>> targets) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("slow_s", slow); m.put("targets", targets);
        write("thresholds.json", m);
    }

    /** One "URL-pattern seconds" per line. Lines that cannot be read go to {@code bad}. */
    public static List<Map<String, Object>> parseTargets(String text, List<String> bad) {
        List<Map<String, Object>> out = new ArrayList<>();
        Pattern line = Pattern.compile("\\s*(\\S+)\\s+([0-9]*\\.?[0-9]+)\\s*");
        for (String l : text.split("\\R")) {
            if (l.isBlank()) continue;
            Matcher m = line.matcher(l);
            if (!m.matches() || m.group(1).length() > 200) { bad.add(l); continue; }
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("pattern", m.group(1)); t.put("seconds", Double.parseDouble(m.group(2)));
            out.add(t);
        }
        return out;
    }

    /** fnmatch-style match: * any run, ? one character. */
    public static boolean matches(String url, String pattern) {
        StringBuilder re = new StringBuilder();
        for (char c : pattern.toCharArray()) re.append(c == '*' ? ".*" : c == '?' ? "." : Pattern.quote(String.valueOf(c)));
        return url != null && url.matches(re.toString());
    }

    // ---- baseline

    public static String baseline() {
        try {
            String v = Files.readString(Settings.workdir().resolve("baseline.txt"), StandardCharsets.UTF_8).strip();
            return v.matches("[0-9a-f]{16}") ? v : null;
        } catch (IOException e) {
            return null;
        }
    }

    public static void setBaseline(String id) throws IOException {
        Files.createDirectories(Settings.workdir());
        Files.writeString(Settings.workdir().resolve("baseline.txt"), id, StandardCharsets.UTF_8);
    }

    // ---- activity log

    public static void audit(String event, String client, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("time", System.currentTimeMillis() / 1000.0); m.put("event", event); m.put("client", client);
        m.put("detail", detail == null ? "" : detail.length() > 300 ? detail.substring(0, 300) : detail);
        synchronized (LOCK) {
            try {
                Files.createDirectories(Settings.workdir());
                Files.writeString(Settings.workdir().resolve("audit.log"), Json.write(m) + "\n", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                trimAudit();
            } catch (IOException ignored) { }
        }
    }

    private static void trimAudit() throws IOException {
        Path p = Settings.workdir().resolve("audit.log");
        if (Files.size(p) < 4_000_000) return;
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
        if (lines.size() > AUDIT_KEEP) Files.write(p, lines.subList(lines.size() - AUDIT_KEEP, lines.size()), StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> readAudit(String event, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            List<String> lines;
            synchronized (LOCK) { lines = Files.readAllLines(Settings.workdir().resolve("audit.log"), StandardCharsets.UTF_8); }
            for (int i = lines.size() - 1; i >= 0 && out.size() < limit; i--) {
                try {
                    Map<String, Object> r = (Map<String, Object>) Json.parse(lines.get(i));
                    if (event == null || event.equals(r.get("event"))) out.add(r);
                } catch (RuntimeException ignored) { }
            }
        } catch (IOException ignored) { }
        return out;
    }

    // ---- API tokens

    private static String sha(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> tokens() {
        Object o = read("tokens.json");
        return o instanceof List ? (List<Map<String, Object>>) o : new ArrayList<>();
    }

    /** Creates a token and returns it. Only its hash is kept. */
    public static String createToken(String name) throws IOException {
        byte[] raw = new byte[24];
        RANDOM.nextBytes(raw);
        String token = TOKEN_PREFIX + HexFormat.of().formatHex(raw);
        byte[] idb = new byte[4];
        RANDOM.nextBytes(idb);
        synchronized (LOCK) {
            List<Map<String, Object>> all = tokens();
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("id", HexFormat.of().formatHex(idb)); t.put("name", name); t.put("created", System.currentTimeMillis() / 1000.0); t.put("hash", sha(token));
            all.add(t);
            write("tokens.json", all);
        }
        return token;
    }

    public static void revokeToken(String id) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> all = tokens();
            all.removeIf(t -> id.equals(t.get("id")));
            write("tokens.json", all);
        }
    }

    public static boolean validToken(String token) {
        if (token == null || !token.startsWith(TOKEN_PREFIX) || token.length() > 100) return false;
        byte[] h = sha(token).getBytes(StandardCharsets.UTF_8);
        boolean ok = false;
        for (Map<String, Object> t : tokens()) ok |= MessageDigest.isEqual(h, String.valueOf(t.get("hash")).getBytes(StandardCharsets.UTF_8));
        return ok;
    }

    // ---- saved Inspect filters

    public static final List<String> FILTER_FIELDS = List.of("src", "src_port", "dst", "port", "kind", "url", "min_size", "size_of");

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> filters() {
        Object o = read("filters.json");
        return o instanceof List ? (List<Map<String, Object>>) o : new ArrayList<>();
    }

    public static void addFilter(String name, Map<String, String> values) throws IOException {
        byte[] idb = new byte[4];
        RANDOM.nextBytes(idb);
        synchronized (LOCK) {
            List<Map<String, Object>> all = filters();
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", HexFormat.of().formatHex(idb)); f.put("name", name);
            for (String k : FILTER_FIELDS) f.put(k, values.getOrDefault(k, ""));
            all.add(f);
            write("filters.json", all);
        }
    }

    public static void removeFilter(String id) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> all = filters();
            all.removeIf(f -> id.equals(f.get("id")));
            write("filters.json", all);
        }
    }
}
