package io.pcapanalyzer;

import java.util.Set;
import java.util.regex.Pattern;

/** Mask secrets before anything is saved, so results and exports never hold them. */
public final class Privacy {
    public static final String MASK = "***";
    public static final Set<String> SENSITIVE_HEADERS = Set.of("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token", "x-amz-security-token");
    private static final String WORDS = "pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|session(?:id)?|auth";
    private static final Pattern QUERY = Pattern.compile("(?i)([?&;](?:\\w*(?:" + WORDS + ")\\w*)=)[^&;#\\s]*");
    private static final Pattern FORM = Pattern.compile("(?i)((?:^|[&;\\s])\\w*(?:" + WORDS + ")\\w*=)[^&;\\s]*");
    private static final Pattern JSON = Pattern.compile("(?i)(\"\\w*(?:" + WORDS + ")\\w*\"\\s*:\\s*)\"(?:[^\"\\\\]|\\\\.)*\"");
    private static final Pattern SECRET_LINE = Pattern.compile("(?im)^((?:" + String.join("|", SENSITIVE_HEADERS.stream().map(Pattern::quote).toList()) + ")\\s*:\\s*).*$");

    private Privacy() {}

    public static String maskUri(String uri) { return uri == null ? null : QUERY.matcher(uri).replaceAll("$1" + MASK); }

    public static String maskHeader(String name, String value) { return SENSITIVE_HEADERS.contains(name.strip().toLowerCase()) ? MASK : value; }

    public static String maskBody(String text) {
        if (text == null || text.isEmpty()) return text;
        String s = FORM.matcher(text).replaceAll("$1" + MASK);
        return JSON.matcher(s).replaceAll("$1\"" + MASK + "\"");
    }

    /** Header lines that carry secrets, and secrets in bodies, as followed text shows them. */
    public static String maskStream(String text) {
        return maskBody(SECRET_LINE.matcher(text).replaceAll(m -> java.util.regex.Matcher.quoteReplacement(m.group(1) + MASK)));
    }

    /** tshark lists header lines with a literal CRLF at the end. Each becomes "name: value" with secrets masked. */
    public static String maskedHeaders(String[] lines) {
        StringBuilder sb = new StringBuilder();
        for (String raw : lines) {
            String line = raw.endsWith("\\r\\n") ? raw.substring(0, raw.length() - 4) : raw;
            line = line.strip();
            int colon = line.indexOf(':');
            String name = colon < 0 ? line : line.substring(0, colon), value = colon < 0 ? "" : line.substring(colon + 1).strip();
            sb.append(sb.length() > 0 ? "\n" : "").append(name).append(": ").append(maskHeader(name, value));
        }
        return sb.toString();
    }

    /** The start of a body as text. tshark gives hex, and binary data is left out rather than shown as noise. */
    public static String preview(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        String hex = raw.replace(":", "");
        if (hex.length() > 4000) hex = hex.substring(0, 4000);
        if (hex.length() % 2 == 1) hex = hex.substring(0, hex.length() - 1);
        byte[] data;
        try { data = java.util.HexFormat.of().parseHex(hex); } catch (IllegalArgumentException e) { return null; }
        String text = new String(data, java.nio.charset.StandardCharsets.UTF_8);
        long bad = text.chars().filter(c -> c == 0xFFFD || (c < 32 && "\r\n\t".indexOf(c) < 0)).count();
        return bad > text.length() * 0.05 ? null : maskBody(text);
    }
}
