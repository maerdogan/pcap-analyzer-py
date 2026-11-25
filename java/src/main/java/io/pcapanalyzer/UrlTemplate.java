package io.pcapanalyzer;

import java.util.regex.Pattern;

/** Group URLs by shape: /users/123/orders becomes /users/{id}/orders. */
public final class UrlTemplate {
    private static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern HEX = Pattern.compile("^[0-9a-f]{16,}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern MIXED = Pattern.compile("^(?=.*\\d)(?=.*[a-zA-Z])[A-Za-z0-9_-]{12,}$");
    private static final Pattern DIGITS = Pattern.compile("^\\d+$");

    private UrlTemplate() {}

    private static boolean variable(String seg) {
        return DIGITS.matcher(seg).matches() || UUID.matcher(seg).matches() || HEX.matcher(seg).matches() || MIXED.matcher(seg).matches();
    }

    public static String of(String uri) {
        if (uri == null || uri.isEmpty()) return uri;
        if (uri.contains("://")) {
            String rest = uri.substring(uri.indexOf("://") + 3);
            int slash = rest.indexOf('/');
            uri = "/" + (slash < 0 ? "" : rest.substring(slash + 1));
        }
        int cut = uri.length();
        for (char c : new char[] {'?', '#'}) {
            int i = uri.indexOf(c);
            if (i >= 0) cut = Math.min(cut, i);
        }
        String path = uri.substring(0, cut);
        String[] parts = path.split("/", -1);
        for (int i = 0; i < parts.length; i++) if (variable(parts[i])) parts[i] = "{id}";
        String out = String.join("/", parts);
        return out.isEmpty() ? "/" : out;
    }
}
