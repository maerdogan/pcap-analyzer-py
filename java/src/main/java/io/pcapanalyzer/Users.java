package io.pcapanalyzer;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

/** Users and their roles besides the setup admin. They are kept in users.json in the work folder, each password as a salted PBKDF2 hash.
 *  viewer: opens and exports captures. analyst: also uploads, deletes, writes notes and saves filters. admin: also manages users, preferences, tokens and the audit log.
 *  Each user is in one group and sees only the captures uploaded in that group; admins see all.
 *  The setup admin (PCAP_ANALYZER_ADMIN_USER) is not in the file and cannot be changed or deleted here. */
public final class Users {
    public enum Role {
        VIEWER, ANALYST, ADMIN;
        public boolean atLeast(Role r) { return compareTo(r) >= 0; }
        public String key() { return name().toLowerCase(Locale.ROOT); }
        static Role of(String s) { try { return valueOf(String.valueOf(s).toUpperCase(Locale.ROOT)); } catch (IllegalArgumentException e) { return null; } }
    }

    /** The signed-in user of this request. group is null for those who see every group: admins and API tokens. */
    public record Current(String name, Role role, boolean setupAdmin, String group, boolean mustChange) {
        /** Admins see every capture; everyone else only the captures uploaded in their own group. */
        public boolean sees(String captureGroup) { return role == Role.ADMIN || group == null || group.equals(captureGroup); }
    }

    static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{1,39}");
    private static final ThreadLocal<Current> CURRENT = new ThreadLocal<>();
    private static final Object LOCK = new Object();

    private Users() {}

    public static Current current() { return CURRENT.get(); }
    static void set(Current c) { if (c == null) CURRENT.remove(); else CURRENT.set(c); }

    public static Role role() { Current c = CURRENT.get(); return c == null ? Role.VIEWER : c.role(); }
    public static boolean can(Role needed) { return role().atLeast(needed); }

    private static Path file() { return Settings.workdir().resolve("users.json"); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> content() {
        return Vault.readJson(file()) instanceof Map<?, ?> m ? new LinkedHashMap<>((Map<String, Object>) m) : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> section(String key) {
        Object l = content().get(key);
        return l instanceof List<?> ? new ArrayList<>((List<Map<String, Object>>) l) : new ArrayList<>();
    }

    private static List<Map<String, Object>> load() { return section("users"); }
    private static List<Map<String, Object>> loadGroups() { return section("groups"); }

    /** Writes one section of users.json, keeping the other. */
    private static void write(String key, List<Map<String, Object>> rows) throws IOException {
        Map<String, Object> all = content();
        all.put(key, rows);
        all.putIfAbsent("users", new ArrayList<>()); all.putIfAbsent("groups", new ArrayList<>());
        Vault.writeText(file(), Json.write(all));
    }

    private static void save(List<Map<String, Object>> users) throws IOException { write("users", users); }

    /** Name, role and creation time of every user, without the hashes, sorted by name. */
    public static List<Map<String, Object>> list() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> u : load()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", u.get("name")); m.put("source", u.getOrDefault("source", "local")); m.put("must_change", Boolean.TRUE.equals(u.get("must_change"))); m.put("full_name", u.getOrDefault("full_name", "")); m.put("employee_id", u.getOrDefault("employee_id", "")); m.put("group", u.getOrDefault("group", "")); m.put("role", u.get("role")); m.put("created", u.get("created"));
            out.add(m);
        }
        out.sort(Comparator.comparing(m -> String.valueOf(m.get("name"))));
        return out;
    }

    /** The user whose password matches, or null. Local users are checked against their hash, LDAP users against the directory. */
    public static Current verify(String name, String password) {
        for (Map<String, Object> u : load()) {
            if (!name.equals(u.get("name"))) continue;
            Role role = Role.of(String.valueOf(u.get("role")));
            if (role == null) return null;
            boolean ok;
            if ("ldap".equals(u.get("source"))) ok = Ldap.authenticate(name, password);
            else {
                ok = Passwords.verify(u, password);
            }
            return ok ? new Current(name, role, false, String.valueOf(u.getOrDefault("group", "")), Boolean.TRUE.equals(u.get("must_change"))) : null;
        }
        // same work for an unknown name, so the time does not tell which names exist
        Passwords.hash(password, new byte[16]);
        return null;
    }

    /** Sign-in generation per user: a password an admin sets, or deleting the user, ends the user's open sessions. */
    private static final Map<String, Integer> GENERATION = new java.util.concurrent.ConcurrentHashMap<>();
    static int generation(String name) { return GENERATION.getOrDefault(name, 0); }
    static void endSessions(String name) { GENERATION.merge(name, 1, Integer::sum); }

    /** The user of a session, read again on every request so a new role or group counts at once; null when the user is gone. */
    public static Current lookup(String name) {
        for (Map<String, Object> u : load()) {
            if (!name.equals(u.get("name"))) continue;
            Role role = Role.of(String.valueOf(u.get("role")));
            return role == null ? null : new Current(name, role, false, String.valueOf(u.getOrDefault("group", "")), Boolean.TRUE.equals(u.get("must_change")));
        }
        return null;
    }

    /** Checks a new user or password change. Returns the problem as an English UI text, or null. */
    static String problem(String name, String group, String password, boolean isNew) {
        if (group != null && !groups().contains(group)) return "Choose one of the groups. An admin adds groups above.";
        if (isNew && !NAME.matcher(name).matches()) return "The user name needs 2 to 40 characters: lowercase letters, digits, dot, dash or underscore.";
        if (isNew && (name.equals(Settings.adminUser()) || load().stream().anyMatch(u -> name.equals(u.get("name"))))) return "This user name is taken.";
        if (password != null && password.length() < Passwords.MIN_LENGTH) return "The new password must have at least {n} characters.";
        if (password != null && password.equalsIgnoreCase(name)) return "The password cannot be the user name.";
        return null;
    }

    private static void hashed(Map<String, Object> u, String password) { Passwords.hashInto(u, password); }

    /** The groups an admin has made: name, description and how many users are in each, sorted by name. */
    public static List<Map<String, Object>> groupList() {
        Map<String, Integer> members = new HashMap<>();
        for (Map<String, Object> u : load()) members.merge(String.valueOf(u.getOrDefault("group", "")), 1, Integer::sum);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> g : loadGroups()) {
            Map<String, Object> m = new LinkedHashMap<>(g);
            m.put("users", members.getOrDefault(String.valueOf(g.get("name")), 0));
            out.add(m);
        }
        out.sort(Comparator.comparing(m -> String.valueOf(m.get("name"))));
        return out;
    }

    public static List<String> groups() {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> g : groupList()) out.add(String.valueOf(g.get("name")));
        return out;
    }

    /** Problem with a new group as an English UI text, or null. */
    static String groupProblem(String name) {
        if (!NAME.matcher(name).matches()) return "The group name needs 2 to 40 characters: lowercase letters, digits, dot, dash or underscore.";
        if (groups().contains(name)) return "This group already exists.";
        return null;
    }

    public static void addGroup(String name, String description) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> gs = loadGroups();
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("name", name); g.put("description", clean(description, 120)); g.put("created", System.currentTimeMillis() / 1000.0);
            gs.add(g);
            write("groups", gs);
        }
    }

    public static boolean updateGroup(String name, String description) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> gs = loadGroups();
            for (Map<String, Object> g : gs) if (name.equals(g.get("name"))) { g.put("description", clean(description, 120)); write("groups", gs); return true; }
            return false;
        }
    }

    /** Deletes an empty group. Returns "users" when users are still in it, "missing" when there is no such group, or null when it was deleted. */
    public static String deleteGroup(String name) throws IOException {
        synchronized (LOCK) {
            if (load().stream().anyMatch(u -> name.equals(u.get("group")))) return "users";
            List<Map<String, Object>> gs = loadGroups();
            if (!gs.removeIf(g -> name.equals(g.get("name")))) return "missing";
            write("groups", gs);
            return null;
        }
    }

    /** Full name, employee number (sicil) and descriptions: free text, trimmed, without control characters, cut to a safe length. */
    static String clean(String s, int max) {
        String v = s == null ? "" : s.strip().replaceAll("\\p{Cntrl}", "");
        return v.length() > max ? v.substring(0, max) : v;
    }

    /** Adds a user. A local user gets the password the admin chose and must change it at the first sign-in; an LDAP user has no password here. */
    public static void add(String name, String fullName, String employeeId, String group, Role role, String password, boolean ldap) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> users = load();
            Map<String, Object> u = new LinkedHashMap<>();
            u.put("name", name); u.put("full_name", clean(fullName, 80)); u.put("employee_id", clean(employeeId, 30)); u.put("group", group); u.put("role", role.key()); u.put("created", System.currentTimeMillis() / 1000.0);
            u.put("source", ldap ? "ldap" : "local");
            if (!ldap) { hashed(u, password); u.put("must_change", true); }
            users.add(u);
            save(users);
        }
    }

    /** Changes a user; returns false when there is no such user. A null role or password stays as it was. */
    public static boolean update(String name, String fullName, String employeeId, String group, Role role, String password) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> users = load();
            for (Map<String, Object> u : users) {
                if (!name.equals(u.get("name"))) continue;
                if (fullName != null) u.put("full_name", clean(fullName, 80));
                if (employeeId != null) u.put("employee_id", clean(employeeId, 30));
                if (group != null) u.put("group", group);
                if (role != null) u.put("role", role.key());
                // a password an admin sets is temporary: the user must choose a new one at the next sign-in
                if (password != null) { hashed(u, password); u.put("must_change", true); endSessions(name); }
                save(users);
                return true;
            }
            return false;
        }
    }

    /** A user's own new password; it ends the must-change state. */
    public static void setOwnPassword(String name, String password) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> users = load();
            for (Map<String, Object> u : users) if (name.equals(u.get("name"))) { hashed(u, password); u.remove("must_change"); }
            save(users);
        }
    }

    static boolean isLdap(String name) {
        return load().stream().anyMatch(u -> name.equals(u.get("name")) && "ldap".equals(u.get("source")));
    }

    public static boolean delete(String name) throws IOException {
        synchronized (LOCK) {
            List<Map<String, Object>> users = load();
            boolean removed = users.removeIf(u -> name.equals(u.get("name")));
            if (removed) endSessions(name);
            if (removed) save(users);
            return removed;
        }
    }
}
