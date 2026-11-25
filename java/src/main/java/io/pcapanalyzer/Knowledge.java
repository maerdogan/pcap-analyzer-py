package io.pcapanalyzer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Interface text and plain explanations from knowledge.json, exported from the Python knowledge base. */
public final class Knowledge {
    public static final List<String> LANGUAGES = List.of("tr", "en", "de", "es");
    public static final Map<String, String> LANGUAGE_NAMES = Map.of("tr", "Türkçe", "en", "English", "de", "Deutsch", "es", "Español");
    public static final String DEFAULT = "tr";

    @SuppressWarnings("unchecked")
    private static final Map<String, Object> ROOT = load();

    private Knowledge() {}

    @SuppressWarnings("unchecked")
    private static Map<String, Object> load() {
        try (InputStream in = Knowledge.class.getResourceAsStream("/knowledge.json")) {
            return (Map<String, Object>) Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            return new HashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(String key) {
        Object o = ROOT.get(key);
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }

    /** Interface text in a language. The English text is the key, and missing entries stay English. */
    public static String ui(String text, String lang) {
        Object e = map("ui").get(text);
        if (e instanceof Map<?, ?> m && m.get(lang) instanceof String s) return s;
        return text;
    }

    @SuppressWarnings("unchecked")
    public static String phaseLabel(String phase, String lang) { return field(map("phases").get(phase), "label", lang); }

    @SuppressWarnings("unchecked")
    public static String phaseAbout(String phase, String lang) { return field(map("phases").get(phase), "about", lang); }

    @SuppressWarnings("unchecked")
    private static String field(Object entry, String name, String lang) {
        if (entry instanceof Map<?, ?> m && m.get(name) instanceof Map<?, ?> l && l.get(lang) instanceof String s) return s;
        return "";
    }

    public static String topicLabel(String topic, String lang) {
        Object t = map("topics").get(topic);
        if (t instanceof Map<?, ?> m && m.get("label") instanceof Map<?, ?> l && l.get(lang) instanceof String s) return s;
        return topic;
    }

    /** The text of a warning about the capture itself. */
    public static String warning(String key, String lang) {
        Object e = map("warnings").get(key);
        return e instanceof Map<?, ?> m && m.get(lang) instanceof String s ? s : key;
    }

    /** A column title in a language, or the column name when the knowledge base has none. */
    public static String column(String name, String lang) {
        Object e = map("columns").get(name);
        return e instanceof Map<?, ?> m && m.get(lang) instanceof String s ? s : name;
    }

    /** Title and reason of an issue, from the knowledge base. */
    public static String[] issue(String key, String lang) {
        Object e = map("issues").get(key);
        if (e instanceof Map<?, ?> m) {
            return new String[] {field(m, "title", lang), field(m, "why", lang), String.valueOf(m.get("topic"))};
        }
        return new String[] {key, "", key};
    }

    public static String quality(String key, long n, String lang) {
        Object e = map("quality").get(key);
        if (e instanceof Map<?, ?> m && m.get(lang) instanceof String s) return s.replace("{n}", Long.toString(n));
        return key;
    }

    /** One or two sentences for a result row: the first matching variant, then every matching suffix. */
    @SuppressWarnings("unchecked")
    public static String summary(String topic, Map<String, Object> facts, String lang) {
        Object t = map("topics").get(topic);
        List<Object> variants = t instanceof Map<?, ?> m && m.get("summary") instanceof List<?> l ? (List<Object>) l : List.of();
        StringBuilder out = new StringBuilder();
        for (Object v : variants) {
            if (holds((Map<String, Object>) v, facts)) { out.append(fill((Map<String, Object>) v, facts, lang)); break; }
        }
        Object common = map("common").get("suffix");
        if (common instanceof List<?> l) for (Object v : l) if (holds((Map<String, Object>) v, facts)) out.append(fill((Map<String, Object>) v, facts, lang));
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    private static boolean holds(Map<String, Object> entry, Map<String, Object> facts) {
        Object when = entry.get("when");
        if (!(when instanceof List<?> rules)) return true;
        for (Object r : rules) {
            List<Object> rule = (List<Object>) r;
            Object have = facts.get((String) rule.get(0));
            if (have == null || !test((String) rule.get(1), have, rule.get(2))) return false;
        }
        return true;
    }

    private static boolean test(String op, Object have, Object want) {
        switch (op) {
            case "in": return want instanceof List<?> l && l.stream().anyMatch(x -> same(have, x));
            case "not in": return !(want instanceof List<?> l && l.stream().anyMatch(x -> same(have, x)));
            case "has": return String.valueOf(have).toLowerCase().contains(String.valueOf(want).toLowerCase());
            case "==": return same(have, want);
            case "!=": return !same(have, want);
            default:
                if (!(have instanceof Number) || !(want instanceof Number)) return false;
                double a = ((Number) have).doubleValue(), b = ((Number) want).doubleValue();
                return switch (op) { case ">=" -> a >= b; case "<=" -> a <= b; case ">" -> a > b; case "<" -> a < b; default -> false; };
        }
    }

    private static boolean same(Object a, Object b) {
        if (a instanceof Number x && b instanceof Number y) return x.doubleValue() == y.doubleValue();
        return Objects.equals(a, b);
    }

    @SuppressWarnings("unchecked")
    private static String fill(Map<String, Object> entry, Map<String, Object> facts, String lang) {
        String template = entry.get(lang) instanceof String s ? s : String.valueOf(entry.get("en"));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < template.length(); i++) {
            char c = template.charAt(i);
            int end = c == '{' ? template.indexOf('}', i) : -1;
            if (end < 0) { sb.append(c); continue; }
            String field = template.substring(i + 1, end);
            String name = field, spec = "";
            int colon = field.indexOf(':');
            if (colon >= 0) { name = field.substring(0, colon); spec = field.substring(colon + 1); }
            Object v = facts.get(name);
            if (spec.equals("term")) {
                Object terms = map("terms").get(String.valueOf(v));
                if (terms == null) terms = map("terms").get("other");
                sb.append(terms instanceof Map<?, ?> m && m.get(lang) instanceof String s ? s : "–");
            } else if (v == null) sb.append("–");
            else if (spec.equals("time") && v instanceof Number n) sb.append(Fmt.duration(n.doubleValue()));
            else sb.append(v);
            i = end;
        }
        return sb.toString();
    }

    /** The topic an issue belongs to. */
    public static String issueTopic(String key) {
        Object e = map("issues").get(key);
        return e instanceof Map<?, ?> m && m.get("topic") instanceof String s ? s : null;
    }

    @SuppressWarnings("unchecked")
    private static List<String> matching(Object entries, Map<String, Object> facts, String lang) {
        List<String> out = new ArrayList<>();
        if (entries instanceof List<?> l) for (Object e : l) if (holds((Map<String, Object>) e, facts)) out.add(fill((Map<String, Object>) e, facts, lang));
        return out;
    }

    private static String text(Object entry, String lang) {
        return entry instanceof Map<?, ?> m ? (m.get(lang) instanceof String s ? s : String.valueOf(m.get("en"))) : "";
    }

    /** The full explanation of a topic, or null when it has none. Lines with conditions appear only when this capture meets them. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> guide(String topic, Map<String, Object> facts, String lang) {
        if (!(map("topics").get(topic) instanceof Map<?, ?> raw) || !raw.containsKey("meaning")) return null;
        Map<String, Object> entry = (Map<String, Object>) raw;
        Map<String, Object> f = new HashMap<>(facts == null ? Map.of() : facts);
        Object code = f.get("rst_code");
        Object note = code instanceof Number n ? map("netscaler_resets").get(String.valueOf(n.longValue())) : null;
        if (note != null) f.put("rst_note", text(note, lang));
        List<Object> evidence = new ArrayList<>();
        if (entry.get("evidence") instanceof List<?> l) evidence.addAll(l);
        if (map("common").get("evidence") instanceof List<?> l) evidence.addAll(l);
        Map<String, Object> g = new LinkedHashMap<>();
        g.put("meaning", text(entry.get("meaning"), lang));
        g.put("misread", entry.containsKey("misread") ? text(entry.get("misread"), lang) : null);
        g.put("evidence", matching(evidence, f, lang));
        g.put("checks", matching(entry.get("checks"), f, lang));
        Map<String, String> headings = new HashMap<>();
        map("headings").forEach((k, v) -> headings.put(k, text(v, lang)));
        g.put("headings", headings);
        List<Map<String, String>> sources = new ArrayList<>();
        if (entry.get("sources") instanceof List<?> l) for (Object o : l) {
            List<Object> pair = (List<Object>) o;
            Object src = map("sources").get(String.valueOf(pair.get(0)));
            if (src instanceof Map<?, ?> m) sources.add(Map.of("title", String.valueOf(m.get("title")), "url", String.valueOf(m.get("url")), "where", String.valueOf(pair.get(1))));
        }
        g.put("sources", sources);
        return g;
    }
}
