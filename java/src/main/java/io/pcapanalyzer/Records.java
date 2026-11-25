package io.pcapanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Small records kept beside the analyses: limits, baseline, activity log and API tokens. */
public final class Records {
    public static final String TOKEN_PREFIX = "pat_";
    private static final int AUDIT_KEEP = 10_000;
    private static final Object LOCK = new Object();

    private Records() {}

    private static Object read(String name) { return Vault.readJson(Settings.workdir().resolve(name)); }

    private static void write(String name, Object data) throws IOException {
        Files.createDirectories(Settings.workdir());
        Vault.writeText(Settings.workdir().resolve(name), Json.write(data));
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
            Path p = Settings.workdir().resolve("baseline.txt");
            if (!Files.exists(p)) return null;
            String v = Vault.readText(p).strip();
            return v.matches("[0-9a-f]{16}") ? v : null;
        } catch (IOException e) {
            return null;
        }
    }

    public static void setBaseline(String id) throws IOException {
        Files.createDirectories(Settings.workdir());
        Vault.writeText(Settings.workdir().resolve("baseline.txt"), id);
    }

    // ---- activity log

    /** The activity log. Its name says nothing about it, and every line is encrypted. */
    static Path auditFile() { return Settings.workdir().resolve(".idx0"); }

    /** Encrypts the lines written before the vault existed: those of an old audit.log and the plain ones of the hidden log. Called when the vault is set up. */
    static void hideAudit() throws IOException {
        synchronized (LOCK) {
            List<String> lines = new ArrayList<>();
            Path old = Settings.workdir().resolve("audit.log");
            if (Files.exists(old)) lines.addAll(Files.readAllLines(old, StandardCharsets.UTF_8));
            if (Files.exists(auditFile())) lines.addAll(Files.readAllLines(auditFile(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (String l : lines) {
                if (l.isBlank()) continue;
                sb.append(l.startsWith("{") ? Base64.getEncoder().encodeToString(Vault.sealBytes(l.getBytes(StandardCharsets.UTF_8))) : l).append('\n');
            }
            Path tmp = Settings.workdir().resolve(".idx0.tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
            Vault.private600(tmp);
            Files.move(tmp, auditFile(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            Files.deleteIfExists(old);
        }
    }

    public static void audit(String event, String client, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("time", System.currentTimeMillis() / 1000.0); m.put("event", event); m.put("client", client);
        Users.Current who = Users.current();
        m.put("user", who == null ? "" : who.name());
        m.put("detail", detail == null ? "" : detail.length() > 300 ? detail.substring(0, 300) : detail);
        synchronized (LOCK) {
            try {
                Files.createDirectories(Settings.workdir());
                // each line is its own encrypted record, so lines can be appended without the vault being open
                String line = Vault.isSetUp() ? Base64.getEncoder().encodeToString(Vault.sealBytes(Json.write(m).getBytes(StandardCharsets.UTF_8))) : Json.write(m);
                Files.writeString(auditFile(), line + "\n", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                Vault.private600(auditFile());
                trimAudit();
            } catch (IOException ignored) { }
        }
    }

    private static void trimAudit() throws IOException {
        Path p = auditFile();
        if (Files.size(p) < 8_000_000) return;
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
        if (lines.size() > AUDIT_KEEP) Files.write(p, lines.subList(lines.size() - AUDIT_KEEP, lines.size()), StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> readAudit(String event, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            List<String> lines;
            synchronized (LOCK) { lines = Files.exists(auditFile()) ? Files.readAllLines(auditFile(), StandardCharsets.UTF_8) : List.of(); }
            for (int i = lines.size() - 1; i >= 0 && out.size() < limit; i--) {
                try {
                    String l = lines.get(i);
                    if (!l.startsWith("{")) l = new String(Vault.openBytes(Base64.getDecoder().decode(l), auditFile()), StandardCharsets.UTF_8);
                    else if (Vault.isSetUp()) { Vault.alert(auditFile(), "A plain line was added to the activity log by hand."); continue; }
                    Map<String, Object> r = (Map<String, Object>) Json.parse(l);
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

    /** A list file such as tokens.json or filters.json. */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(String file) {
        Object o = read(file);
        return o instanceof List ? (List<Map<String, Object>>) o : new ArrayList<>();
    }

    private static void removeById(String file, String id) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> all = list(file);
            all.removeIf(t -> id.equals(t.get("id")));
            write(file, all);
        }
    }

    public static List<Map<String, Object>> tokens() { return list("tokens.json"); }

    /** Creates a token and returns it. Only its hash is kept. */
    public static String createToken(String name) throws IOException {
        String token = TOKEN_PREFIX + Settings.randomHex(24);
        synchronized (LOCK) {
            List<Map<String, Object>> all = tokens();
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("id", Settings.randomHex(4)); t.put("name", name); t.put("created", System.currentTimeMillis() / 1000.0); t.put("hash", sha(token));
            all.add(t);
            write("tokens.json", all);
        }
        return token;
    }

    public static void revokeToken(String id) throws IOException { removeById("tokens.json", id); }

    public static boolean validToken(String token) {
        if (token == null || !token.startsWith(TOKEN_PREFIX) || token.length() > 100) return false;
        byte[] h = sha(token).getBytes(StandardCharsets.UTF_8);
        boolean ok = false;
        for (Map<String, Object> t : tokens()) ok |= MessageDigest.isEqual(h, String.valueOf(t.get("hash")).getBytes(StandardCharsets.UTF_8));
        return ok;
    }

    // ---- saved Inspect filters

    public static final List<String> FILTER_FIELDS = List.of("src", "src_port", "dst", "port", "kind", "url", "min_size", "size_of");

    public static List<Map<String, Object>> filters() { return list("filters.json"); }

    public static void addFilter(String name, Map<String, String> values) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> all = filters();
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", Settings.randomHex(4)); f.put("name", name);
            for (String k : FILTER_FIELDS) f.put(k, values.getOrDefault(k, ""));
            all.add(f);
            write("filters.json", all);
        }
    }

    public static void removeFilter(String id) throws IOException { removeById("filters.json", id);
    }
}
