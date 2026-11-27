package io.pcapanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * The AI tool the app uses for analysis in the background, and its configuration. The admin picks one tool from TOOLS and edits that
 * tool's JSON. For opencode the model is chosen from the connected providers' models (what `opencode models` lists) and written to
 * the "model" key. The settings are kept encrypted in the data folder, since the configuration may hold keys.
 */
final class Ai {
    static final Map<String, String> TOOLS = Map.of("opencode", "opencode");
    private static final Pattern MODEL = Pattern.compile("[\\w.\\-]+/\\S+");
    private static final Pattern ANSI = Pattern.compile("\u001b\\[[0-9;]*[A-Za-z]");
    private static final int TIMEOUT_S = 20;
    /** Bu uzunluga kadar soru sayfada acik yazilir; daha uzunu bir pencerede gosterilir. */
    static final int SHORT_PROMPT = 1500;

    private Ai() {}

    private static Path file() { return Settings.workdir().resolve("ai.json"); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> load() {
        Map<String, Object> out = new LinkedHashMap<>();
        Object saved = Vault.readJson(file());
        Map<String, Object> m = saved instanceof Map<?, ?> x ? (Map<String, Object>) x : Map.of();
        out.put("tool", m.get("tool") instanceof String t && TOOLS.containsKey(t) ? t : "opencode");
        out.put("config", m.get("config") instanceof Map<?, ?> c ? c : new LinkedHashMap<>(Map.of("$schema", "https://opencode.ai/config.json")));
        // Kullanicilara acilan modeller; hic kaydedilmemisse null, yani listelenen tum modeller
        List<String> allowed = null;
        if (m.get("allowed") instanceof List<?> l) { allowed = new ArrayList<>(); for (Object o : l) if (o instanceof String s && MODEL.matcher(s).matches()) allowed.add(s); }
        out.put("allowed", allowed);
        return out;
    }

    static String configText() { return Json.write(load().get("config")); }

    /** Problem with new settings as an English UI text, or null. */
    static String problem(String tool, String text) {
        if (!TOOLS.containsKey(tool)) return "Choose one of the listed AI tools.";
        Object v;
        try { v = Json.parse(text == null || text.isBlank() ? "{}" : text); } catch (RuntimeException e) { return "The configuration is not valid JSON."; }
        if (!(v instanceof Map<?, ?> m)) return "The configuration must be a JSON object, such as {\"model\": \"provider/model\"}.";
        if (m.containsKey("model") && !(m.get("model") instanceof String s && MODEL.matcher(s).matches())) return "The model must look like provider/model.";
        return null;
    }

    @SuppressWarnings("unchecked")
    static void save(String tool, String text, String model) throws IOException { save(tool, text, model, allowed()); }

    /** allowed: the models users may pick for an analysis; null offers every listed model. */
    @SuppressWarnings("unchecked")
    static void save(String tool, String text, String model, List<String> allowed) throws IOException {
        Map<String, Object> config = new LinkedHashMap<>((Map<String, Object>) Json.parse(text == null || text.isBlank() ? "{}" : text));
        if (model != null && !model.isBlank()) config.put("model", model);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tool", tool);
        out.put("config", config);
        if (allowed != null) {
            List<String> clean = new ArrayList<>();
            for (String a : allowed) if (a != null && MODEL.matcher(a.strip()).matches() && !clean.contains(a.strip())) clean.add(a.strip());
            out.put("allowed", clean);
        }
        Vault.writeText(file(), Json.write(out));
    }

    /** The opencode program: PCAP_ANALYZER_OPENCODE, else PATH, else ~/.local/bin. Null when missing. */
    static String binary() {
        List<String> candidates = new ArrayList<>();
        String env = System.getenv("PCAP_ANALYZER_OPENCODE");
        if (env != null && !env.isBlank()) candidates.add(env);
        String path = System.getenv("PATH");
        if (path != null) for (String d : path.split(java.io.File.pathSeparator)) if (!d.isEmpty()) candidates.add(d + "/opencode");
        candidates.add(System.getProperty("user.home") + "/.local/bin/opencode");
        for (String c : candidates) if (Files.isRegularFile(Path.of(c)) && Files.isExecutable(Path.of(c))) return c;
        return null;
    }

    private static String run(String... args) { return run(TIMEOUT_S, args); }

    private static String run(int timeoutS, String... args) { return runFor(null, timeoutS, args); }

    /** Runs opencode; a run with an id can be stopped with stop(id). */
    private static String runFor(String id, int timeoutS, String... args) {
        String exe = binary();
        if (exe == null) return "";
        List<String> cmd = new ArrayList<>(List.of(exe));
        cmd.addAll(List.of(args));
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(false);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            // opencode waits for the end of its input when that is an open pipe, so it gets none
            pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
            pb.environment().put("OPENCODE_CONFIG_CONTENT", Json.write(load().get("config")));
            Path dir = Settings.workdir();
            if (Files.isDirectory(dir)) pb.directory(dir.toFile());
            Process p = pb.start();
            if (id != null) PROCS.put(id, p);
            // the output is read on its own thread, so the time limit holds even when the program stays silent
            java.util.concurrent.CompletableFuture<byte[]> reader = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try { return p.getInputStream().readAllBytes(); } catch (IOException e) { return new byte[0]; }
            });
            if (!p.waitFor(timeoutS, TimeUnit.SECONDS)) { p.destroyForcibly(); return ""; }
            byte[] out = reader.get(5, TimeUnit.SECONDS);
            return ANSI.matcher(new String(out, StandardCharsets.UTF_8)).replaceAll("");
        } catch (IOException | java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            return "";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        } finally {
            if (id != null) PROCS.remove(id);
        }
    }

    static String version() { String v = run("--version").strip(); return v.isEmpty() ? null : v; }

    /** provider/model names opencode can use now, grouped by provider in first-seen order. */
    static Map<String, List<String>> models() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String line : run("models").split("\n")) {
            String n = line.strip();
            if (MODEL.matcher(n).matches()) out.computeIfAbsent(n.substring(0, n.indexOf('/')), k -> new ArrayList<>()).add(n);
        }
        return out;
    }

    // ---- the AI opinion on a capture: asked in the background, saved next to the analysis

    private static final Map<String, String> RUNNING = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Map<String, Process> PROCS = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Set<String> STOPPED = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Stops the analysis that is running for this capture. True when there was one. */
    static boolean stop(String id) {
        if (!RUNNING.containsKey(id)) return false;
        STOPPED.add(id);
        Process p = PROCS.get(id);
        if (p != null) p.destroyForcibly();
        return true;
    }

    private static final Map<String, String> FAILED = new java.util.concurrent.ConcurrentHashMap<>();

    private static Path opinionFile(String id) { return Settings.workdir().resolve(id).resolve("ai-opinion.json"); }

    static boolean running(String id) { return RUNNING.containsKey(id); }
    static String failure(String id) { return FAILED.get(id); }

    /** The saved opinion: model, created (epoch seconds), text and the prompt that was sent; null when none. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> opinion(String id) {
        return Vault.readJson(opinionFile(id)) instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    /** The models the admin offers to users; null when the admin has not chosen, which offers every listed model. */
    @SuppressWarnings("unchecked")
    static List<String> allowed() { return (List<String>) load().get("allowed"); }

    /** Whether a model may be used for an analysis: the default always, others when the admin offers them. */
    static boolean offered(String name, List<String> allowed, Map<String, List<String>> listed) {
        if (name.equals(model())) return true;
        if (allowed != null) return allowed.contains(name);
        return listed.values().stream().anyMatch(l -> l.contains(name));
    }

    /** The listed models users may pick, by provider, without the default. */
    static Map<String, List<String>> offeredModels() {
        List<String> allowed = allowed();
        String def = model();
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> g : models().entrySet())
            for (String n : g.getValue()) if (!n.equals(def) && (allowed == null || allowed.contains(n))) out.computeIfAbsent(g.getKey(), k -> new ArrayList<>()).add(n);
        return out;
    }

    static String model() { return ((Map<?, ?>) load().get("config")).get("model") instanceof String s ? s : ""; }

    /** What the model is told: the facts of the analysis and, per service, two groups of requests to compare. Never packet contents. */
    static String prompt(Map<String, Object> result, String lang) { return prompt(result, lang, true); }

    /** privacy: IP addresses, card numbers, national ID numbers, e-mail addresses and IBANs are replaced by labels before anything is sent. */
    static String prompt(Map<String, Object> result, String lang, boolean privacy) {
        Map<String, Object> facts = new LinkedHashMap<>();
        for (String k : new String[] {"summary", "http", "tcp", "kinds", "capture_points", "budget", "quality"}) if (result.get(k) != null) facts.put(k, result.get(k));
        List<Object> issues = new ArrayList<>();
        if (result.get("issues") instanceof List<?> l)
            for (Object o : l) if (o instanceof Map<?, ?> m) { Map<String, Object> i = new LinkedHashMap<>(); for (String k : new String[] {"id", "title", "severity", "count", "summary"}) if (m.get(k) != null) i.put(k, m.get(k)); issues.add(i); }
        facts.put("issues", issues);
        String json = Json.write(facts), bands = Json.write(Bands.of(result));
        if (json.length() > 8000) json = json.substring(0, 8000) + "...";
        if (bands.length() > 24000) bands = bands.substring(0, 24000) + "...";
        String language = switch (lang) { case "tr" -> "Turkish"; case "de" -> "German"; case "es" -> "Spanish"; default -> "English"; };
        String text = "You are a network and web performance expert. Below is the automatic analysis of one packet capture as JSON, then, for each service (method and URL template), "
            + "two groups of its requests cut from the sorted response times: typical_slow is the group around the percentile where the mean of p50 and p90 falls (that percentile +-2), "
            + "fast is p12.5 to p15. Times are in seconds; phases are parts of the response time. The slowest few requests are left out on purpose. "
            + "For each service compare the two groups: which phase explains the gap (see phase_differences), whether the clients, sizes, connections or times differ, and what that means. "
            + "Then list the likely problems and the fixes to try, most important first. Say when the data is too thin to tell. Be concrete and short, use short sections. "
            + "Write in " + language + ". Do not use tools or read files.\n\nANALYSIS:\n" + json + "\n\nSERVICES:\n" + bands;
        return privacy ? redact(text) : text;
    }

    private static final java.util.regex.Pattern IPV4 = java.util.regex.Pattern.compile("(?<![\\d.])((?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3})(?::\\d{1,5})?(?![\\d.]*\\d)");
    private static final java.util.regex.Pattern IPV6 = java.util.regex.Pattern.compile("(?<![\\w:])(?:(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?|::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})(?![\\w:])");
    private static final java.util.regex.Pattern EMAIL = java.util.regex.Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
    private static final java.util.regex.Pattern IBAN = java.util.regex.Pattern.compile("(?<![A-Za-z0-9])[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])");
    private static final java.util.regex.Pattern CARD = java.util.regex.Pattern.compile("(?<![\\d.])\\d(?:[ -]?\\d){12,18}(?![\\d.]*\\d)");
    private static final java.util.regex.Pattern SSN = java.util.regex.Pattern.compile("(?<![\\d-])\\d{3}-\\d{2}-\\d{4}(?![\\d-])");
    private static final java.util.regex.Pattern NATIONAL_ID = java.util.regex.Pattern.compile("(?<![\\d.])[1-9]\\d{10}(?![\\d.]*\\d)");

    /** Replaces what identifies a person or an account. One address always gets the same label, so the model can still tell clients apart. */
    static String redact(String text) {
        Map<String, String> labels = new HashMap<>();
        String s = IPV4.matcher(text).replaceAll(m -> java.util.regex.Matcher.quoteReplacement(labels.computeIfAbsent(m.group(1), k -> "ip-" + (labels.size() + 1))));
        s = IPV6.matcher(s).replaceAll(m -> java.util.regex.Matcher.quoteReplacement(labels.computeIfAbsent(m.group(), k -> "ip-" + (labels.size() + 1))));
        s = EMAIL.matcher(s).replaceAll("[email]");
        s = IBAN.matcher(s).replaceAll("[iban]");
        s = SSN.matcher(s).replaceAll("[ssn]");
        s = CARD.matcher(s).replaceAll(m -> luhn(m.group().replaceAll("\\D", "")) ? "[card]" : java.util.regex.Matcher.quoteReplacement(m.group()));
        s = NATIONAL_ID.matcher(s).replaceAll(m -> turkishId(m.group()) ? "[national-id]" : m.group());
        return s;
    }

    private static boolean luhn(String d) {
        if (d.length() < 13 || d.length() > 19) return false;
        int sum = 0;
        boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) { int n = d.charAt(i) - '0'; if (dbl && (n *= 2) > 9) n -= 9; sum += n; dbl = !dbl; }
        return sum % 10 == 0;
    }

    /** The checksum of a Turkish national ID number, so other 11-digit numbers are left alone. */
    private static boolean turkishId(String d) {
        int[] v = d.chars().map(c -> c - '0').toArray();
        int odd = v[0] + v[2] + v[4] + v[6] + v[8], even = v[1] + v[3] + v[5] + v[7];
        int d10 = ((odd * 7 - even) % 10 + 10) % 10;
        return d10 == v[9] && (odd + even + v[9]) % 10 == v[10];
    }

    /** Starts asking the chosen model in the background. Returns an English UI text when it cannot start, else null. */
    static String start(String id, String prompt, String chosen) { return launch(id, prompt, chosen, null); }

    /** A follow-up question in the same conversation: the first question and answer and the earlier follow-ups go along as text. */
    @SuppressWarnings("unchecked")
    static String followUp(String id, String question, String chosen, boolean privacy) {
        Map<String, Object> op = opinion(id);
        if (op == null || !(op.get("prompt") instanceof String base) || base.isEmpty()) return "Ask the AI for the analysis first.";
        String q = question == null ? "" : question.strip();
        if (q.isEmpty()) return "Write your question.";
        if (q.length() > 2000) q = q.substring(0, 2000);
        if (privacy) q = redact(q);
        StringBuilder sb = new StringBuilder(base).append("\n\nYOUR ANSWER SO FAR:\n").append(op.get("text"));
        if (op.get("followups") instanceof List<?> l)
            for (Object o : l) if (o instanceof Map<?, ?> m) sb.append("\n\nFOLLOW-UP QUESTION:\n").append(m.get("question")).append("\n\nYOUR ANSWER:\n").append(m.get("answer"));
        sb.append("\n\nNEW FOLLOW-UP QUESTION:\n").append(q)
          .append("\n\nAnswer the new question using the analysis above, in the language of the question. Be concrete and short. Do not use tools or read files.");
        return launch(id, sb.toString(), chosen, q);
    }

    @SuppressWarnings("unchecked")
    private static String launch(String id, String prompt, String chosen, String question) {
        String model = chosen != null && MODEL.matcher(chosen.strip()).matches() ? chosen.strip() : model();
        if (binary() == null) return "opencode is not installed on this host. Install it with: npm install -g opencode-ai";
        // Formdan gelen model yoneticinin actiklarindan degilse soru gonderilmez
        if (!model.isEmpty() && !offered(model, allowed(), models())) return "This model is not offered. Choose one of the listed models.";
        if (model.isEmpty()) return "Choose a model in Settings, AI first.";
        if (RUNNING.putIfAbsent(id, model) != null) return null;
        FAILED.remove(id);
        STOPPED.remove(id);
        Thread t = new Thread(() -> {
            try {
                String text = runFor(id, 300, "run", "-m", model, prompt).replaceFirst("^\\s*> [^\\n]*\\n", "").strip();
                if (STOPPED.remove(id)) { FAILED.put(id, "The analysis was stopped."); return; }
                if (text.isEmpty()) { FAILED.put(id, "The model gave no answer."); return; }
                Map<String, Object> out;
                if (question == null) {
                    out = new LinkedHashMap<>();
                    out.put("model", model);
                    out.put("created", System.currentTimeMillis() / 1000.0);
                    out.put("text", text);
                    // Modele gonderilen soru da saklanir ki cevapla birlikte gosterilebilsin
                    out.put("prompt", prompt);
                } else {
                    Map<String, Object> op = opinion(id);
                    if (op == null) { FAILED.put(id, "The model gave no answer."); return; }
                    out = new LinkedHashMap<>(op);
                    List<Object> fu = new ArrayList<>(out.get("followups") instanceof List<?> l ? l : List.of());
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("question", question); f.put("answer", text); f.put("model", model);
                    f.put("created", System.currentTimeMillis() / 1000.0); f.put("prompt", prompt);
                    fu.add(f);
                    out.put("followups", fu);
                }
                Vault.writeText(opinionFile(id), Json.write(out));
            } catch (IOException | RuntimeException e) {
                FAILED.put(id, STOPPED.remove(id) ? "The analysis was stopped." : "The model gave no answer.");
            } finally {
                RUNNING.remove(id);
            }
        }, "ai-opinion");
        t.setDaemon(true);
        t.start();
        return null;
    }
}
