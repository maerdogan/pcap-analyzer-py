package io.pcapanalyzer;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

/**
 * Sign-in against a directory. The admin sets the server, a service account that may search, the base DN and the filter that finds a user
 * by name. A user defined as "LDAP" in the app keeps no password here: the app finds the user's DN with the service account, then binds
 * as that DN with the password given. The group and role still come from the app. The settings, bind password included, are kept encrypted.
 */
final class Ldap {
    static final String[] FIELDS = {"url", "bind_dn", "bind_password", "base_dn", "user_filter"};
    private static final int TIMEOUT_MS = 5000;

    private Ldap() {}

    private static Path file() { return Settings.workdir().resolve("ldap.json"); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> settings() {
        if (Vault.readJson(file()) instanceof Map<?, ?> m) return new LinkedHashMap<>((Map<String, Object>) m);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("url", ""); d.put("bind_dn", ""); d.put("bind_password", ""); d.put("base_dn", ""); d.put("user_filter", "(uid={0})");
        return d;
    }

    static boolean configured() {
        Map<String, Object> s = settings();
        return !String.valueOf(s.get("url")).isBlank() && !String.valueOf(s.get("base_dn")).isBlank();
    }

    /** Problem with the settings as an English UI text, or null. An empty bind password keeps the saved one. */
    static String problem(Map<String, String> s) {
        String url = s.getOrDefault("url", "");
        // the port is optional: ldaps:// defaults to 636 and ldap:// to 389, but a directory may listen anywhere
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("ldaps?://(?:[A-Za-z0-9.\\-]+|\\[[0-9A-Fa-f:.]+\\])(?::(\\d{1,5}))?/?").matcher(url);
        if (!url.isEmpty() && (!m.matches() || (m.group(1) != null && (Integer.parseInt(m.group(1)) < 1 || Integer.parseInt(m.group(1)) > 65535)))) return "The LDAP address must look like ldaps://dc.example.com or ldap://dc.example.com, with a port after a colon if it is not the usual one (1 to 65535).";
        if (!s.getOrDefault("user_filter", "").contains("{0}")) return "The user filter must contain {0}, where the user name goes, such as (sAMAccountName={0}).";
        return null;
    }

    static void save(Map<String, String> s) throws IOException {
        Map<String, Object> old = settings(), out = new LinkedHashMap<>();
        for (String f : FIELDS) out.put(f, Users.clean(s.get(f), 400));
        if (String.valueOf(out.get("bind_password")).isEmpty()) out.put("bind_password", old.getOrDefault("bind_password", ""));
        Vault.writeText(file(), Json.write(out));
    }

    /** RFC 4515: characters that would change a filter are escaped, so a user name cannot widen the search. */
    static String escape(String v) {
        StringBuilder sb = new StringBuilder();
        for (char ch : v.toCharArray()) {
            switch (ch) {
                case '\\' -> sb.append("\\5c"); case '*' -> sb.append("\\2a"); case '(' -> sb.append("\\28"); case ')' -> sb.append("\\29"); case '\0' -> sb.append("\\00");
                default -> sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static Hashtable<String, String> env(String url, String dn, String password) {
        Hashtable<String, String> e = new Hashtable<>();
        e.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        e.put(Context.PROVIDER_URL, url);
        e.put(Context.SECURITY_AUTHENTICATION, "simple");
        e.put(Context.SECURITY_PRINCIPAL, dn);
        e.put(Context.SECURITY_CREDENTIALS, password);
        e.put(Context.REFERRAL, "ignore");
        e.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(TIMEOUT_MS));
        e.put("com.sun.jndi.ldap.read.timeout", String.valueOf(TIMEOUT_MS));
        return e;
    }

    /** The DN of a user, found with the service account; null when there is none or more than one. */
    static String find(Map<String, Object> s, String name) throws NamingException {
        InitialDirContext ctx = new InitialDirContext(env(String.valueOf(s.get("url")), String.valueOf(s.get("bind_dn")), String.valueOf(s.get("bind_password"))));
        try {
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            sc.setReturningAttributes(new String[0]);
            sc.setCountLimit(2);
            String filter = String.valueOf(s.get("user_filter")).replace("{0}", escape(name));
            NamingEnumeration<SearchResult> r = ctx.search(String.valueOf(s.get("base_dn")), filter, sc);
            String dn = null;
            int n = 0;
            while (r.hasMore()) { dn = r.next().getNameInNamespace(); n++; }
            return n == 1 ? dn : null;
        } finally { ctx.close(); }
    }

    /** True when the directory accepts this name and password. An empty password is refused, since many servers treat it as an anonymous bind. */
    static boolean authenticate(String name, String password) {
        if (password == null || password.isEmpty() || !configured()) return false;
        Map<String, Object> s = settings();
        try {
            String dn = find(s, name);
            if (dn == null) return false;
            new InitialDirContext(env(String.valueOf(s.get("url")), dn, password)).close();
            return true;
        } catch (NamingException e) {
            return false;
        }
    }

    /** Checks the settings with the service account, and finds a user when a name is given. Returns a line for the admin. */
    static String test(String name) {
        if (!configured()) return "LDAP is not set up.";
        Map<String, Object> s = settings();
        try {
            if (name == null || name.isBlank()) { new InitialDirContext(env(String.valueOf(s.get("url")), String.valueOf(s.get("bind_dn")), String.valueOf(s.get("bind_password")))).close(); return "OK: the service account signed in."; }
            String dn = find(s, name.strip());
            return dn == null ? "The service account signed in, but no single user matches " + name.strip() + "." : "OK: " + name.strip() + " is " + dn;
        } catch (NamingException e) {
            return "Failed: " + Optional.ofNullable(e.getExplanation()).orElse(e.getClass().getSimpleName());
        }
    }
}
