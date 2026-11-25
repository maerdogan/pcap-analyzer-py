package io.pcapanalyzer;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.regex.Pattern;

/**
 * GET  /                    captures and upload form
 * POST /upload              analyze a capture
 * GET  /a/{id}[?tab=]       overview, URLs or connections
 * POST /a/{id}/delete|notes
 * GET  /api/a/{id}/{timeline|statuses|histogram|urls|connections|result}
 * POST /language
 */
@WebServlet(urlPatterns = {"", "/upload", "/language", "/a/*", "/api/a/*", "/analysis/*", "/api/analysis/*", "/export/*", "/capture-guide", "/preferences", "/audit", "/trend", "/compare", "/tokens", "/tokens/*", "/filters", "/filters/*", "/api/v1/*", "/password", "/users", "/users/*", "/security", "/security/*"})
@MultipartConfig(maxFileSize = Settings.MAX_UPLOAD, maxRequestSize = Settings.MAX_UPLOAD + (1 << 20), fileSizeThreshold = 1 << 20)
public class AppServlet extends HttpServlet {
    private static final Pattern ID = Pattern.compile("[0-9a-f]{16}");
    private static final Pattern HOST = Pattern.compile("[0-9A-Fa-f:.]{2,45}(/\\d{1,3})?");
    private static final Pattern NAME = Pattern.compile("[0-9a-f]{16}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] SECRET = new byte[32];
    static { RANDOM.nextBytes(SECRET); }
    private static final int TTL_DAYS = Settings.ttlDays();
    private static final String CSP = "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

    // ---- request helpers

    private static String token() {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal("csrf".getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A form or query value, or "" when it is missing. */
    private static String param(HttpServletRequest req, String name) {
        String v = req.getParameter(name);
        return v == null ? "" : v;
    }

    /** For the sign-in page, which the filter serves. */
    static Pages.Ctx context(HttpServletRequest req) { return ctx(req); }
    static boolean formTokenOk(HttpServletRequest req) { return csrfOk(req); }

    private static boolean csrfOk(HttpServletRequest req) {
        String t = req.getParameter("csrf_token");
        return t != null && MessageDigest.isEqual(t.getBytes(StandardCharsets.UTF_8), token().getBytes(StandardCharsets.UTF_8));
    }

    private static String language(HttpServletRequest req) {
        if (req.getCookies() != null) for (Cookie c : req.getCookies()) if (c.getName().equals("lang") && Knowledge.LANGUAGES.contains(c.getValue())) return c.getValue();
        String h = req.getHeader("Accept-Language");
        if (h != null) for (String part : h.split(",")) {
            String code = part.split(";")[0].trim().toLowerCase();
            if (code.length() >= 2 && Knowledge.LANGUAGES.contains(code.substring(0, 2))) return code.substring(0, 2);
        }
        return Knowledge.DEFAULT;
    }

    private static Pages.Ctx ctx(HttpServletRequest req) {
        String uri = req.getRequestURI().substring(req.getContextPath().length());
        if (req.getQueryString() != null) uri += "?" + req.getQueryString();
        return new Pages.Ctx(req.getContextPath(), language(req), token(), uri.isEmpty() ? "/" : uri, null, Records.baseline());
    }

    private static void html(HttpServletResponse res, int status, String body) throws IOException {
        res.setStatus(status);
        res.setContentType("text/html;charset=UTF-8");
        res.setHeader("Content-Security-Policy", CSP);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Referrer-Policy", "same-origin");
        res.getWriter().write(body);
    }

    private static void json(HttpServletResponse res, Object o) throws IOException {
        res.setContentType("application/json;charset=UTF-8");
        res.setHeader("Content-Security-Policy", CSP);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.getWriter().write(Json.write(o));
    }

    // ---- storage

    private static Path dir(String id) { return Settings.workdir().resolve(id); }

    @SuppressWarnings("unchecked")
    /** Parsed large files, so a page does not parse a result of tens of megabytes again. Soft references let the GC drop them when the heap is short. */
    private record Parsed(long modified, long size, java.lang.ref.SoftReference<Object> tree) {}
    private static final int CACHE_MIN_BYTES = 1 << 20, CACHE_ENTRIES = 4;
    private static final Map<Path, Parsed> PARSED = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Path, Parsed> e) { return size() > CACHE_ENTRIES; }
    });

    @SuppressWarnings("unchecked")
    private static Map<String, Object> read(Path file) {
        try {
            long size = Files.size(file), modified = Files.getLastModifiedTime(file).toMillis();
            if (size < CACHE_MIN_BYTES) return (Map<String, Object>) Json.parse(Vault.readText(file));
            Parsed p = PARSED.get(file);
            Object tree = p != null && p.modified() == modified && p.size() == size ? p.tree().get() : null;
            if (tree == null) {
                tree = Json.parse(Vault.readText(file));
                PARSED.put(file, new Parsed(modified, size, new java.lang.ref.SoftReference<>(tree)));
            }
            // pages change the maps they get, so each gets its own copy
            return (Map<String, Object>) Json.copy(tree);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Who uploaded a capture and in which group, written before the analysis starts. */
    private static void writeOwner(Path dir) throws IOException {
        Users.Current who = Users.current();
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("user", who == null ? "" : who.name());
        // an admin or token upload has no group of its own; it stays visible to admins only, unless the admin is also in a group
        o.put("group", who == null || who.group() == null ? "" : who.group());
        Vault.writeText(dir.resolve("owner.json"), Json.write(o));
    }

    static String ownerOf(String id) {
        Map<String, Object> o = read(dir(id).resolve("owner.json"));
        return o == null ? "" : String.valueOf(o.getOrDefault("user", ""));
    }

    /** Only the one who uploaded a capture, and admins, may delete it. */
    static boolean mayDelete(String id) {
        Users.Current who = Users.current();
        return who != null && (who.role() == Users.Role.ADMIN || (!who.name().isEmpty() && who.name().equals(ownerOf(id))));
    }

    private static final Map<String, Long> SEEN = new java.util.concurrent.ConcurrentHashMap<>();

    /** Marks an analysis as looked at, at most once an hour, by the time of an empty .seen file; the cleaner deletes what nobody looked at. */
    static void seen(String id) {
        long now = System.currentTimeMillis();
        Long last = SEEN.get(id);
        if (last != null && now - last < 3_600_000L) return;
        SEEN.put(id, now);
        try {
            Path f = dir(id).resolve(".seen");
            if (!Files.exists(f)) Files.createFile(f);
            Files.setLastModifiedTime(f, java.nio.file.attribute.FileTime.fromMillis(now));
        } catch (IOException ignored) { }
    }

    static String groupOf(String id) {
        Map<String, Object> o = read(dir(id).resolve("owner.json"));
        return o == null ? "" : String.valueOf(o.getOrDefault("group", ""));
    }

    /** True when the signed-in user may see this capture. Captures from before groups existed have no group, so only admins see them. */
    static boolean visible(String id) {
        Users.Current who = Users.current();
        return who == null || who.sees(groupOf(id));
    }

    /** Capture ids a request names, in its path or in its compare parameters. */
    private static List<String> named(HttpServletRequest req) {
        List<String> ids = new ArrayList<>();
        String path = req.getServletPath(), info = req.getPathInfo() == null ? "" : req.getPathInfo().substring(1);
        if (List.of("/a", "/api/a", "/export", "/analysis", "/api/analysis").contains(path)) ids.add(info.split("/")[0]);
        // every REST route that names an analysis: analyses/{id}..., captures/{id}, and jobs/{id}, whose id is the analysis id
        if (path.equals("/api/v1")) {
            String[] seg = info.split("/");
            if (seg.length >= 2 && (seg[0].equals("analyses") || seg[0].equals("captures") || seg[0].equals("jobs"))) ids.add(seg[1]);
        }
        for (String k : new String[] {"a", "b", "base", "baseline"}) if (req.getParameter(k) != null) ids.add(req.getParameter(k));
        ids.removeIf(i -> !ID.matcher(i).matches());
        return ids;
    }

    private static boolean allowed(HttpServletRequest req, HttpServletResponse res) throws IOException {
        for (String id : named(req)) if (!visible(id)) { res.sendError(404); return false; }
        return true;
    }

    private static List<Map<String, Object>> list(String search) {
        List<Map<String, Object>> out = new ArrayList<>();
        Path wd = Settings.workdir();
        if (!Files.isDirectory(wd)) return out;
        try (var ds = Files.newDirectoryStream(wd)) {
            for (Path d : ds) {
                if (!NAME.matcher(d.getFileName().toString()).matches()) continue;
                Map<String, Object> m = read(d.resolve("meta.json"));
                if (m == null) continue;
                if (!visible(d.getFileName().toString())) continue;
                if (!search.isEmpty()) {
                    Map<String, Object> n = notes(d.getFileName().toString());
                    String hay = (m.get("filename") + " " + n.get("case") + " " + n.get("tags") + " " + n.get("note")).toLowerCase();
                    if (!hay.contains(search.toLowerCase())) continue;
                }
                m.put("_deletable", mayDelete(d.getFileName().toString()));
                out.add(m);
            }
        } catch (IOException ignored) { }
        out.sort((a, b) -> Double.compare(Analysis.d(b.get("created")), Analysis.d(a.get("created"))));
        return out;
    }

    private static Map<String, Object> notes(String id) {
        Map<String, Object> n = read(dir(id).resolve("notes.json"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : new String[] {"case", "tags", "note"}) out.put(k, n != null && n.get(k) != null ? n.get(k) : "");
        return out;
    }

    private static void deleteTree(Path dir) {
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException ignored) { }
    }

    // ---- GET

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!allowed(req, res)) return;
        String path = req.getServletPath();
        String info = req.getPathInfo() == null ? "" : req.getPathInfo().substring(1);
        Pages.Ctx c = ctx(req);
        switch (path) {
            case "" -> {
                String q = param(req, "q").strip();
                List<Map<String, Object>> analyses = list(q);
                String main = Pages.home(c, analyses, q, (int) (Settings.MAX_UPLOAD >> 20), TTL_DAYS, null);
                html(res, 200, Pages.layout(c, c.t("Captures"), "captures", "", main, recent(), null));
            }
            case "/analysis" -> res.sendRedirect(req.getContextPath() + "/a/" + info);
            case "/api/analysis" -> {
                Map<String, Object> r = ID.matcher(info).matches() ? read(dir(info).resolve("result.json")) : null;
                if (r == null) { res.sendError(404); return; }
                json(res, r);
            }
            case "/export" -> export(req, res, c, info);
            case "/api/v1" -> apiV1(req, res, info, "GET");
            case "/password" -> html(res, 200, Pages.layout(c, c.t("Password"), "password", "", Pages.passwordPage(c, null), recent(), null));
            case "/capture-guide" -> {
                Map<String, String[]> q = req.getParameterMap();
                int seconds = Optional.ofNullable(Inspect.num(q, "seconds")).filter(n -> n > 0 && n <= 86400).orElse(CaptureGuide.DEFAULT_SECONDS);
                String port = Inspect.num(q, "port") == null ? null : String.valueOf(Inspect.num(q, "port"));
                String server = hostArg(Inspect.str(q, "server")), client = hostArg(Inspect.str(q, "client"));
                List<CaptureGuide.Point> points = CaptureGuide.commands(c, server, port, client, seconds, (int) (Settings.MAX_UPLOAD >> 20), word(Inspect.str(q, "interface"), "any"), word(Inspect.str(q, "namespace"), "default"),
                        word(Inspect.str(q, "pod"), "POD"), word(Inspect.str(q, "container"), "CONTAINER"), imageArg(Inspect.str(q, "image")));
                html(res, 200, Pages.layout(c, c.t("Capture guide"), "guide", "", Pages.guidePage(c, q, (int) (Settings.MAX_UPLOAD >> 20), seconds, points), recent(), null));
            }
            case "/preferences" -> preferences(req, res, c, null, null);
            case "/users" -> users(res, c, null, null);
            case "/security" -> security(res, c, null, null);
            case "/audit" -> {
                String event = Inspect.str(req.getParameterMap(), "event");
                html(res, 200, Pages.layout(c, c.t("Activity log"), "audit", "", Pages.auditPage(c, Records.readAudit(event, 500), event), recent(), null));
            }
            case "/trend" -> trend(req, res, c);
            case "/compare" -> compare(req, res, c);
            case "/a" -> page(req, res, c, info);
            case "/api/a" -> api(req, res, info);
            default -> res.sendError(404);
        }
    }

    private static void download(HttpServletResponse res, String type, String filename, byte[] data) throws IOException {
        res.setContentType(type);
        res.setHeader("Content-Disposition", "attachment; filename=\"" + filename.replaceAll("[^A-Za-z0-9._-]", "_") + "\"");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setContentLength(data.length);
        res.getOutputStream().write(data);
    }

    /** /export/{id}/{table}.{csv|json|xlsx}, /export/{id}/requests.har and /export/{id}/conn/{n}.pcapng */
    private void export(HttpServletRequest req, HttpServletResponse res, Pages.Ctx c, String info) throws IOException {
        String[] p = info.split("/");
        if (p.length < 2 || !ID.matcher(p[0]).matches()) { res.sendError(404); return; }
        Map<String, Object> meta = read(dir(p[0]).resolve("meta.json")), result = read(dir(p[0]).resolve("result.json"));
        if (meta == null || result == null) { res.sendError(404); return; }
        Records.audit("export", req.getRemoteAddr(), info);
        String base = Path.of((String) meta.get("filename")).getFileName().toString().replaceAll("\\.[^.]*$", "");
        if (p.length == 3 && p[1].equals("conn") && p[2].endsWith(".pcapng")) {
            String n = p[2].substring(0, p[2].length() - 7);
            Map<String, Object> conn = n.matches("\\d{1,9}") ? connOf(result, n) : null;
            if (conn == null || !kept(p[0])) { res.sendError(404); return; }
            try {
                download(res, "application/octet-stream", base + "-connection-" + n + ".pcapng", new TShark(Settings.tshark()).extract(dir(p[0]).resolve("capture.bin"), ((Number) conn.get("stream")).intValue(), 120));
            } catch (TShark.TsharkException e) { res.sendError(500, e.getMessage()); }
            return;
        }
        if (p.length == 3 && p[1].equals("object") && p[2].matches("\\d{4}-[A-Za-z0-9._-]+")) {
            Path f = dir(p[0]).resolve("objects").resolve(p[2]);
            if (!Files.isRegularFile(f)) { res.sendError(404); return; }
            byte[] body;
            try (InputStream in = Vault.in(f)) { body = in.readAllBytes(); }
            download(res, "application/octet-stream", p[2].substring(5), body);
            return;
        }
        if (p.length != 2) { res.sendError(404); return; }
        int dot = p[1].lastIndexOf('.');
        String name = dot < 0 ? p[1] : p[1].substring(0, dot), fmt = dot < 0 ? "" : p[1].substring(dot + 1);
        if (name.equals("report") && fmt.equals("html")) {
            String css;
            try (InputStream in = getServletContext().getResourceAsStream("/static/app.css")) { css = in == null ? "" : new String(in.readAllBytes(), StandardCharsets.UTF_8); }
            download(res, "text/html; charset=utf-8", base + "-report.html", Pages.reportPage(c, meta, result, css).getBytes(StandardCharsets.UTF_8));
            return;
        }
        if (name.equals("requests") && fmt.equals("har")) { download(res, "application/json", base + "-requests.har", Exports.har(Inspect.filtered(Inspect.query(req.getParameterMap()), result), details(p[0])).getBytes(StandardCharsets.UTF_8)); return; }
        if (!Exports.TABLES.contains(name) || !Exports.FORMATS.containsKey(fmt)) { res.sendError(404); return; }
        download(res, Exports.FORMATS.get(fmt), base + "-" + name + "." + fmt, Exports.render(Exports.table(name, result, c.lang()), fmt, c.lang()));
    }

    private static List<Map<String, Object>> recent() {
        List<Map<String, Object>> all = list("");
        return all.subList(0, Math.min(5, all.size()));
    }

    private static final Pattern WORD = Pattern.compile("[A-Za-z0-9._-]{1,63}");

    /** Values go into commands people paste into a shell, so only plain names and addresses are used. */
    private static String word(String v, String dflt) { return v != null && WORD.matcher(v).matches() ? v : dflt; }
    private static String hostArg(String v) { return v != null && v.matches("[0-9A-Fa-f:.]{2,45}") ? v : null; }
    private static String imageArg(String v) { return v != null && v.matches("[A-Za-z0-9._/:@-]{1,200}") ? v : CaptureGuide.DEFAULT_IMAGE; }

    private void security(HttpServletResponse res, Pages.Ctx c, String message, String error) throws IOException {
        html(res, error == null ? 200 : 422, Pages.layout(c, c.t("Encryption"), "security", "", Pages.securityPage(c, message, error), Vault.isUnlocked() ? recent() : List.of(), null));
    }

    /** Sets the master key the first time, which encrypts every file, or changes it later. Admin only. */
    private void securityPost(HttpServletRequest req, HttpServletResponse res, String info) throws IOException {
        Pages.Ctx c = ctx(req);
        if (info.equals("alerts/clear")) { Vault.clearAlerts(); res.sendRedirect(req.getContextPath() + "/security"); return; }
        Users.Current me = Users.current();
        if (me == null || !me.setupAdmin()) { security(res, c, null, c.t("Only the setup admin can set the master key, since it is wrapped with that admin's password.")); return; }
        String key = param(req, "master"), again = param(req, "again");
        String problem = Vault.masterProblem(key);
        if (problem == null && !key.equals(again)) problem = "The two keys are not the same.";
        if (problem != null) { security(res, c, null, c.t(problem)); return; }
        try {
            if (!Vault.isSetUp()) {
                // the master key is wrapped with the admin's password, so the admin gives it once more here
                String adminPassword = param(req, "password");
                if (!Passwords.matches(adminPassword)) { security(res, c, null, c.t("The current password is not correct.")); return; }
                Vault.setUp(adminPassword, key);
                PARSED.clear();
                Records.audit("vault_set_up", req.getRemoteAddr(), "");
                security(res, c, c.t("The master key is set. Every file in the data folder is now encrypted."), null);
            } else {
                Vault.changeMaster(key);
                Records.audit("master_key_changed", req.getRemoteAddr(), "");
                security(res, c, c.t("The master key was changed."), null);
            }
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    private void users(HttpServletResponse res, Pages.Ctx c, String message, String error) throws IOException {
        html(res, error == null ? 200 : 422, Pages.layout(c, c.t("Users"), "users", "", Pages.usersPage(c, Users.list(), Users.groupList(), message, error), recent(), null));
    }

    /** Adds, changes and deletes users. Admin only, which AuthFilter checks. */
    private void usersPost(HttpServletRequest req, HttpServletResponse res, String info) throws IOException {
        Pages.Ctx c = ctx(req);
        String name = param(req, "name").strip().toLowerCase(Locale.ROOT);
        String group = param(req, "group").strip().toLowerCase(Locale.ROOT);
        String password = req.getParameter("password");
        Users.Role role = Users.Role.of(req.getParameter("role"));
        String fullName = req.getParameter("full_name"), employeeId = req.getParameter("employee_id");
        String[] p = info.split("/");
        if (info.equals("ldap")) {
            Map<String, String> ls = new HashMap<>();
            for (String f : Ldap.FIELDS) ls.put(f, Optional.ofNullable(req.getParameter(f)).orElse("").strip());
            String problem = Ldap.problem(ls);
            if (problem != null) { users(res, c, null, c.t(problem)); return; }
            Ldap.save(ls);
            Records.audit("ldap_settings", req.getRemoteAddr(), ls.get("url"));
            users(res, c, c.t("LDAP settings saved."), null);
            return;
        }
        if (info.equals("ldap/test")) { users(res, c, Ldap.test(req.getParameter("test_user")), null); return; }
        if (info.equals("groups")) {
            String gname = param(req, "group_name").strip().toLowerCase(Locale.ROOT);
            String problem = Users.groupProblem(gname);
            if (problem != null) { users(res, c, null, c.t(problem)); return; }
            Users.addGroup(gname, req.getParameter("description"));
            Records.audit("group_added", req.getRemoteAddr(), gname);
            users(res, c, c.t("Group {name} was added.", "name", gname), null);
            return;
        }
        if (p.length == 3 && p[0].equals("groups")) {
            String gname = p[1];
            if (p[2].equals("update")) {
                if (!Users.updateGroup(gname, req.getParameter("description"))) { res.sendError(404); return; }
                Records.audit("group_changed", req.getRemoteAddr(), gname);
            } else if (p[2].equals("delete")) {
                String why = Users.deleteGroup(gname);
                if ("missing".equals(why)) { res.sendError(404); return; }
                if ("users".equals(why)) { users(res, c, null, c.t("Group {name} still has users. Move them to another group first.", "name", gname)); return; }
                Records.audit("group_deleted", req.getRemoteAddr(), gname);
            } else { res.sendError(404); return; }
            res.sendRedirect(req.getContextPath() + "/users");
            return;
        }
        if (info.isEmpty()) {
            boolean ldap = "ldap".equals(req.getParameter("source"));
            if (ldap && !Ldap.configured()) { users(res, c, null, c.t("Set up LDAP below before adding LDAP users.")); return; }
            String problem = role == null ? "Choose a role." : Users.problem(name, group, ldap ? null : password == null ? "" : password, true);
            if (problem != null) { users(res, c, null, c.t(problem, "n", Passwords.MIN_LENGTH)); return; }
            if (fullName == null || fullName.isBlank()) { users(res, c, null, c.t("Enter the person's full name.")); return; }
            Users.add(name, fullName, employeeId, group, role, password, ldap);
            Records.audit("user_added", req.getRemoteAddr(), name + " " + group + " " + role.key());
            users(res, c, c.t("{name} was added.", "name", name), null);
            return;
        }
        if (p.length != 2) { res.sendError(404); return; }
        String who = p[0];
        boolean ok;
        switch (p[1]) {
            case "update" -> {
                String problem = role == null ? "Choose a role." : Users.problem(who, group, null, false);
                if (problem != null) { users(res, c, null, c.t(problem)); return; }
                if (fullName != null && fullName.isBlank()) { users(res, c, null, c.t("Enter the person's full name.")); return; }
                ok = Users.update(who, fullName, employeeId, group, role, null);
                Records.audit("user_changed", req.getRemoteAddr(), who + " " + group + " " + role.key());
            }
            case "password" -> {
                if (Users.isLdap(who)) { users(res, c, null, c.t("An LDAP user's password is set in the directory.")); return; }
                String problem = Users.problem(who, null, password == null ? "" : password, false);
                if (problem != null) { users(res, c, null, c.t(problem, "n", Passwords.MIN_LENGTH)); return; }
                ok = Users.update(who, null, null, null, null, password);
                Records.audit("user_password", req.getRemoteAddr(), who);
            }
            case "delete" -> {
                ok = Users.delete(who);
                Records.audit("user_deleted", req.getRemoteAddr(), who);
            }
            default -> { res.sendError(404); return; }
        }
        if (!ok) { res.sendError(404); return; }
        res.sendRedirect(req.getContextPath() + "/users");
    }

    private void preferences(HttpServletRequest req, HttpServletResponse res, Pages.Ctx c, String newToken, String error) throws IOException {
        Map<String, Object> limits = Records.thresholds();
        StringBuilder targets = new StringBuilder();
        for (Object t : (List<?>) limits.get("targets")) { Map<?, ?> m = (Map<?, ?>) t; targets.append(m.get("pattern")).append(' ').append(Analysis.d(m.get("seconds"))).append('\n'); }
        html(res, 200, Pages.layout(c, c.t("Preferences"), "preferences", "", Pages.preferencesPage(c, limits, targets.toString(), Records.tokens(), newToken, error), recent(), null));
    }

    private void trend(HttpServletRequest req, HttpServletResponse res, Pages.Ctx c) throws IOException {
        String url = Optional.ofNullable(Inspect.str(req.getParameterMap(), "url")).orElse("");
        TreeSet<String> names = new TreeSet<>();
        List<Object[]> rows = new ArrayList<>();
        List<Map<String, Object>> metas = new ArrayList<>(list(""));
        metas.sort(Comparator.comparingDouble(m -> Analysis.d(m.get("capture_start") != null ? m.get("capture_start") : m.get("created"))));
        for (Map<String, Object> m : metas) {
            Map<String, Object> r = read(dir((String) m.get("id")).resolve("result.json"));
            if (r == null) continue;
            @SuppressWarnings("unchecked") List<Map<String, Object>> urls = (List<Map<String, Object>>) r.get("urls");
            for (Map<String, Object> u : urls) {
                names.add((String) u.get("url"));
                if (!url.isEmpty() && url.equals(u.get("url"))) rows.add(new Object[] {m, u});
            }
        }
        html(res, 200, Pages.layout(c, c.t("Trend"), "trend", "", Pages.trendPage(c, url, names.stream().limit(200).toList(), rows), recent(), null));
    }

    private void compare(HttpServletRequest req, HttpServletResponse res, Pages.Ctx c) throws IOException {
        Map<String, String[]> q = req.getParameterMap();
        String ia = Inspect.str(q, "a"), ib = Inspect.str(q, "b");
        Map<String, Object> ma = null, mb = null, result = null, points = null;
        if (ia != null && ib != null && ID.matcher(ia).matches() && ID.matcher(ib).matches()) {
            ma = read(dir(ia).resolve("meta.json")); mb = read(dir(ib).resolve("meta.json"));
            Map<String, Object> ra = read(dir(ia).resolve("result.json")), rb = read(dir(ib).resolve("result.json"));
            if (ma != null && mb != null && ra != null && rb != null) {
                if ("points".equals(Inspect.str(q, "mode"))) {
                    Double offset = null;
                    String raw = Optional.ofNullable(Inspect.str(q, "offset_ms")).orElse("").strip().replace(',', '.');
                    if (!raw.isEmpty()) try { offset = Double.parseDouble(raw) / 1000; } catch (NumberFormatException ignored) { }
                    points = Compare.twoPoint(ra, rb, offset);
                }
                else result = Compare.captures(c, ra, rb, side(q, "_a", null), side(q, "_b", side(q, "_a", null)));
            }
        }
        html(res, 200, Pages.layout(c, c.t("Compare captures"), "compare", "", Pages.comparePage(c, list(""), q, ma, mb, result, points), recent(), null));
    }

    /** Filters of one side. An empty field on B takes the value of A. */
    private static Inspect.Query side(Map<String, String[]> q, String suffix, Inspect.Query fallback) {
        Map<String, String[]> m = new HashMap<>();
        for (String k : new String[] {"src", "dst", "port", "url"}) { String[] v = q.get(k + suffix); if (v != null) m.put(k, v); }
        Inspect.Query own = Inspect.query(m);
        if (fallback == null) return own;
        return new Inspect.Query(own.src() != null ? own.src() : fallback.src(), own.srcPort() != null ? own.srcPort() : fallback.srcPort(), own.dst() != null ? own.dst() : fallback.dst(),
                own.port() != null ? own.port() : fallback.port(), own.kind() != null ? own.kind() : fallback.kind(), own.url() != null ? own.url() : fallback.url(), own.minSize(), own.sizeOf(), own.start(), own.end());
    }


    /** The display filter the user picked. Only a preset passes, since it goes to tshark as written. */
    private static String flt(HttpServletRequest req) {
        return DisplayFilters.allowed(req.getParameter("filter"));
    }

    /** Headers and body previews of each request, kept apart from the main result so it stays small. */
    private static Map<String, Object> details(String id) {
        Map<String, Object> d = read(dir(id).resolve("details.json"));
        return d == null ? new HashMap<>() : d;
    }

    private static boolean kept(String id) { return Files.isRegularFile(dir(id).resolve("capture.bin")); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> connOf(Map<String, Object> result, String n) {
        for (Map<String, Object> k : (List<Map<String, Object>>) result.get("connections")) if (String.valueOf(((Number) k.get("stream")).intValue()).equals(n)) return k;
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> txnsOf(Map<String, Object> result, int stream) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) if (((Number) x.get("stream")).intValue() == stream) out.add(x);
        return out;
    }

    private void page(HttpServletRequest req, HttpServletResponse res, Pages.Ctx c0, String info) throws IOException {
        String[] parts = info.split("/");
        String id = parts[0];
        if (!ID.matcher(id).matches()) { res.sendError(404); return; }
        Pages.Ctx c = c0.withId(id);
        Map<String, Object> meta = read(dir(id).resolve("meta.json")), result = read(dir(id).resolve("result.json"));
        if (meta == null || result == null) { res.sendError(404); return; }
        seen(id);
        if (!(result.get("version") instanceof Number v) || v.intValue() < Analysis.RESULT_VERSION) {
            String body = Pages.crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), null}})
                    + "<p class=\"warn\">" + Fmt.esc(c.t("This analysis was saved by an older version. Analyze the capture again to see TLS details.")) + "</p>"
                    + "<form method=\"post\" action=\"" + c.path() + "/a/" + id + "/delete\">" + Pages.csrf(c) + "<button class=\"link danger\">" + Fmt.esc(c.t("Delete")) + "</button></form>";
            html(res, 200, Pages.layout(c, (String) meta.get("filename"), "captures", "", body, recent(), id));
            return;
        }
        long issueCount = ((List<?>) result.get("issues")).size();
        String title = (String) meta.get("filename"), nav = null, main = null;
        if (parts.length == 1) {
            String tab = Optional.ofNullable(req.getParameter("tab")).orElse("overview");
            if (!List.of("urls", "connections", "issues", "hosts", "backends", "tls", "stats").contains(tab)) tab = "overview";
            main = Pages.analysis(c, meta, result, tab, notes(id), tab.equals("overview") ? drift(c, id, result) : null, kept(id), flt(req), tab.equals("stats") ? Views.sequences(result, details(id)) : List.of());
            nav = Pages.capnav(c, id, tab, issueCount);
        } else if (parts.length == 3 && parts[1].equals("issue")) {
            @SuppressWarnings("unchecked") Map<String, Object> detail = (Map<String, Object>) ((Map<String, Object>) result.get("issue_detail")).get(parts[2]);
            if (detail == null) { res.sendError(404); return; }
            main = Pages.issuePage(c, meta, parts[2], detail);
            nav = Pages.capnav(c, id, "issues", issueCount);
            title = parts[2];
        } else if (parts.length == 3 && parts[1].equals("stats") && parts[2].equals("services")) {
            if (!kept(id)) { res.sendError(404); return; }
            try {
                TShark ts = new TShark(Settings.tshark());
                Path cap = dir(id).resolve("capture.bin");
                html(res, 200, Pages.servicesFragment(c, Services.responseTimes(ts, cap), Services.quic(ts, cap, false), Services.voip(ts, cap)));
            } catch (TShark.TsharkException e) { html(res, 200, "<p class=\"error\">" + Fmt.esc(e.getMessage()) + "</p>"); }
            return;
        } else if (parts.length == 3 && parts[1].equals("stats") && parts[2].equals("overview")) {
            if (!kept(id)) { res.sendError(404); return; }
            try {
                TShark ts = new TShark(Settings.tshark());
                html(res, 200, Pages.statsOverview(c, Stats.hierarchy(ts, dir(id).resolve("capture.bin")), Stats.overview(ts, dir(id).resolve("capture.bin"))));
            } catch (TShark.TsharkException e) { html(res, 200, "<p class=\"error\">" + Fmt.esc(e.getMessage()) + "</p>"); }
            return;
        } else if (parts.length == 2 && parts[1].equals("flow")) {
            if (!kept(id)) { res.sendError(404); return; }
            Integer st = Inspect.num(req.getParameterMap(), "stream");
            String f = flt(req);
            Map<String, Object> flow;
            try { flow = Views.flow(new TShark(Settings.tshark()), dir(id).resolve("capture.bin"), f, st); }
            catch (TShark.TsharkException e) { flow = new LinkedHashMap<>(); flow.put("rows", new ArrayList<>()); flow.put("hosts", new ArrayList<>()); flow.put("filter", f); }
            main = Pages.flowPage(c, meta, flow, f, st);
            nav = Pages.capnav(c, id, "stats", issueCount);
            title = c.t("Flow graph");
        } else if (parts.length == 2 && parts[1].equals("objects")) {
            if (!kept(id)) { res.sendError(404); return; }
            Path folder = dir(id).resolve("objects"), index = dir(id).resolve("objects.json");
            List<Map<String, Object>> found;
            Object cached = Files.isRegularFile(index) ? Json.parse(Vault.readText(index)) : null;
            if (cached instanceof List<?> l) { @SuppressWarnings("unchecked") List<Map<String, Object>> fl = (List<Map<String, Object>>) l; found = fl; }
            else {
                try { found = Views.objects(new TShark(Settings.tshark()), dir(id).resolve("capture.bin"), folder); }
                catch (TShark.TsharkException e) { found = new ArrayList<>(); }
                // objects taken out of the capture are as secret as the capture
                if (Files.isDirectory(folder)) try (var ds = Files.newDirectoryStream(folder)) { for (Path o : ds) Vault.encryptInPlace(o); }
                Vault.writeText(index, Json.write(found));
            }
            main = Pages.objectsPage(c, meta, found);
            nav = Pages.capnav(c, id, "stats", issueCount);
            title = c.t("Export objects");
        } else if (parts.length == 2 && parts[1].equals("inspect")) {
            Map<String, String[]> params = req.getParameterMap();
            main = Pages.inspectPage(c, meta, params, result, Inspect.run(Inspect.query(params), result, Inspect.slow(params)));
            nav = Pages.capnav(c, id, "inspect", issueCount);
            title = c.t("Inspect traffic");
        } else if (parts.length >= 3 && parts[1].equals("conn")) {
            Map<String, Object> conn = connOf(result, parts[2]);
            if (conn == null) { res.sendError(404); return; }
            int stream = ((Number) conn.get("stream")).intValue();
            if (parts.length == 4 && parts[3].equals("packets")) { packets(res, c, id, stream); return; }
            if (parts.length == 4 && parts[3].equals("follow")) {
                String mode = Optional.ofNullable(req.getParameter("mode")).orElse("ascii");
                if (!List.of("ascii", "hex", "http").contains(mode)) mode = "ascii";
                List<Map<String, Object>> txns = txnsOf(result, stream);
                if (mode.equals("http")) {
                    Map<String, Object> det = details(id);
                    List<Map<String, Object>> ex = new ArrayList<>();
                    for (Map<String, Object> t : txns) {
                        @SuppressWarnings("unchecked") Map<String, Object> d = (Map<String, Object>) det.getOrDefault(String.valueOf(((Number) t.get("id")).intValue()), new HashMap<>());
                        boolean h1 = !String.valueOf(t.get("http_version")).startsWith("HTTP/2");
                        String request = (h1 ? t.get("method") + " " + t.get("uri") + " " + t.get("http_version") + "\n" : "") + Optional.ofNullable(d.get("req_headers")).orElse("") + (d.get("req_body") != null ? "\n\n" + d.get("req_body") : "");
                        String response = null;
                        if (Boolean.TRUE.equals(t.get("answered")))
                            response = (h1 ? t.get("http_version") + " " + t.get("status") + " " + Optional.ofNullable(t.get("phrase")).orElse("") + "\n" : "") + Optional.ofNullable(d.get("resp_headers")).orElse("") + (d.get("resp_body") != null ? "\n\n" + d.get("resp_body") : "");
                        Map<String, Object> x = new LinkedHashMap<>();
                        x.put("id", t.get("id")); x.put("h2_stream", t.get("h2_stream")); x.put("start", t.get("req_start")); x.put("total", t.get("total")); x.put("request", request.strip()); x.put("response", response == null ? null : response.strip());
                        ex.add(x);
                    }
                    main = Pages.followPage(c, meta, conn, mode, null, ex, !txns.isEmpty());
                } else {
                    if (!kept(id)) { res.sendError(404); return; }
                    Map<String, Object> f;
                    try { f = Views.follow(new TShark(Settings.tshark()), dir(id).resolve("capture.bin"), stream, mode); }
                    catch (TShark.TsharkException e) { f = new LinkedHashMap<>(); f.put("chunks", new ArrayList<>()); }
                    main = Pages.followPage(c, meta, conn, mode, f, List.of(), !txns.isEmpty());
                }
            } else if (parts.length == 3) {
                boolean percent = "true".equals(req.getParameter("percent"));
                List<Map<String, Object>> txns = txnsOf(result, stream);
                Map<Integer, Map<String, Object>> map = new HashMap<>();
                map.put(stream, conn);
                int n = percent ? Math.max(1, (int) Math.ceil(txns.size() * 0.1)) : 5;
                main = Pages.connectionPage(c, meta, conn, txns, Analysis.slowest(txns, map, Math.min(n, txns.size())), percent, kept(id));
            } else { res.sendError(404); return; }
            nav = Pages.capnav(c, id, "connections", issueCount);
            title = c.t("Connection {n}", "n", stream);
        } else if ((parts.length == 3 || (parts.length == 4 && parts[3].equals("packets"))) && parts[1].equals("txn")) {
            @SuppressWarnings("unchecked") List<Map<String, Object>> all = (List<Map<String, Object>>) result.get("transactions");
            Map<String, Object> t = null;
            for (Map<String, Object> x : all) if (String.valueOf(((Number) x.get("id")).intValue()).equals(parts[2])) { t = x; break; }
            if (t == null) { res.sendError(404); return; }
            Map<String, Object> conn = connOf(result, String.valueOf(((Number) t.get("stream")).intValue()));
            if (parts.length == 4) { requestPackets(res, c, id, t); return; }
            main = Pages.transactionPage(c, meta, t, conn, (Map<String, Object>) details(id).get(String.valueOf(((Number) t.get("id")).intValue())), kept(id));
            nav = Pages.capnav(c, id, "connections", issueCount);
            title = t.get("method") + " " + t.get("uri");
        } else { res.sendError(404); return; }
        html(res, 200, Pages.layout(c, title, "captures", nav, main, recent(), id));
    }

    private static String drift(Pages.Ctx c, String id, Map<String, Object> result) {
        String base = Records.baseline();
        Map<String, Object> br = null, bm = null;
        if (base != null && !base.equals(id)) { br = read(dir(base).resolve("result.json")); bm = read(dir(base).resolve("meta.json")); }
        @SuppressWarnings("unchecked") List<Map<String, Object>> targets = (List<Map<String, Object>>) Records.thresholds().get("targets");
        return Pages.driftPanels(c, result, br, bm == null ? "" : (String) bm.get("filename"), targets);
    }

    /** Bir baglantinin tum paketleri, Wireshark paket listesindeki gibi bayraklar, sira/onay numaralari ve TCP isaretleriyle. */
    private void packets(HttpServletResponse res, Pages.Ctx c, String id, int stream) throws IOException {
        if (!kept(id)) { res.sendError(404); return; }
        try {
            html(res, 200, Pages.packetsFragment(c, Packets.connection(new TShark(Settings.tshark()), dir(id).resolve("capture.bin"), stream)));
        } catch (TShark.TsharkException e) {
            html(res, 200, "<p class=\"error\" role=\"alert\">" + Fmt.esc(e.getMessage()) + "</p>");
        }
    }

    /** Tek bir HTTP isteginin paketleri: el sikisma (istek baglantiyi actiysa), istek, yanit ve onayi. */
    private void requestPackets(HttpServletResponse res, Pages.Ctx c, String id, Map<String, Object> t) throws IOException {
        if (!kept(id)) { res.sendError(404); return; }
        try {
            html(res, 200, Pages.packetsFragment(c, Packets.request(new TShark(Settings.tshark()), dir(id).resolve("capture.bin"), t)));
        } catch (TShark.TsharkException e) {
            html(res, 200, "<p class=\"error\" role=\"alert\">" + Fmt.esc(e.getMessage()) + "</p>");
        }
    }

    private void api(HttpServletRequest req, HttpServletResponse res, String info) throws IOException {
        String[] p = info.split("/");
        if ((p.length != 2 && p.length != 3) || !ID.matcher(p[0]).matches()) { res.sendError(404); return; }
        Map<String, Object> r = read(dir(p[0]).resolve("result.json"));
        if (r == null) { res.sendError(404); return; }
        if (p.length == 3) {
            Map<String, Object> conn = connOf(r, p[2]);
            if (conn == null) { res.sendError(404); return; }
            int stream = ((Number) conn.get("stream")).intValue();
            if (p[1].equals("waterfall")) json(res, waterfall(r, conn, stream));
            else if (p[1].equals("tcpgraph") && kept(p[0])) json(res, tcpgraph(p[0], conn, stream));
            else res.sendError(404);
            return;
        }
        switch (p[1]) {
            case "timeline", "statuses", "histogram", "urls", "connections", "hosts" -> json(res, r.get(p[1]));
            case "result" -> json(res, r);
            case "io" -> {
                if (!kept(p[0])) { res.sendError(404); return; }
                try { json(res, Stats.io(new TShark(Settings.tshark()), dir(p[0]).resolve("capture.bin"), flt(req))); }
                catch (TShark.TsharkException e) { res.sendError(422, e.getMessage()); }
            }
            case "waterfall", "tcpgraph" -> { res.sendError(404); }
            default -> res.sendError(404);
        }
    }

    private Map<String, Object> waterfall(Map<String, Object> r, Map<String, Object> conn, int stream) {
        Pages.Ctx c = new Pages.Ctx("", Knowledge.DEFAULT, "", "/", null, null);
        Map<String, Object> phaseNames = new LinkedHashMap<>();
        for (String name : Analysis.PHASES) phaseNames.put(name, Knowledge.phaseLabel(name, Knowledge.DEFAULT));
        List<Map<String, Object>> rows = new ArrayList<>();
        double t0 = Analysis.d(conn.get("start_time"));
        for (Map<String, Object> x : txnsOf(r, stream)) {
            if (rows.size() >= 100) break;
            Map<String, Object> row = new LinkedHashMap<>();
            String uri = String.valueOf(x.get("uri"));
            row.put("id", x.get("id")); row.put("label", x.get("method") + " " + (uri.length() > 48 ? uri.substring(0, 48) : uri)); row.put("status", x.get("status"));
            row.put("start", Analysis.d(x.get("req_start")) - t0);
            @SuppressWarnings("unchecked") Map<String, Object> ph = (Map<String, Object>) x.get("phases");
            for (String name : Analysis.PHASES) row.put(name, Analysis.d(ph.get(name)));
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("phases", phaseNames); out.put("rows", rows);
        return out;
    }

    /** Sequence numbers, throughput, round trip and window of each side, read again from the kept capture. */
    private Map<String, Object> tcpgraph(String id, Map<String, Object> conn, int stream) throws IOException {
        List<String> fields = List.of("frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport", "tcp.seq", "tcp.len", "tcp.window_size", "tcp.analysis.ack_rtt",
                "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission");
        List<String[]> rows;
        try {
            rows = new TShark(Settings.tshark()).query(dir(id).resolve("capture.bin"), "tcp.stream == " + stream, fields, 200_000, 120);
        } catch (TShark.TsharkException e) {
            rows = new ArrayList<>();
        }
        Map<String, Object> sides = new LinkedHashMap<>();
        Map<String, Map<String, Object>> by = new LinkedHashMap<>();
        double t0 = rows.isEmpty() ? 0 : Double.parseDouble(rows.get(0)[0]), tN = t0;
        for (String[] r : rows) if (r.length >= 10 && !r[0].isEmpty()) tN = Math.max(tN, Double.parseDouble(r[0]));
        double step = Math.max((tN - t0) / 100, 0.01);
        Map<String, Map<Long, Double>> bytes = new HashMap<>();
        String client = String.valueOf(conn.get("client"));
        List<String[]> acks = new ArrayList<>();
        for (String[] r : rows) {
            if (r.length < 10 || r[0].isEmpty()) continue;
            String endpoint = (r[1].isEmpty() ? r[2] : r[1]) + ":" + r[3];
            double t = Double.parseDouble(r[0]) - t0;
            Map<String, Object> side = by.computeIfAbsent(endpoint, k -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("side", k); m.put("client", k.equals(client)); m.put("stevens", new ArrayList<>());
                Map<String, Object> th = new LinkedHashMap<>(); th.put("rows", new ArrayList<>());
                m.put("throughput", th); m.put("rtt", new ArrayList<>()); m.put("window", new ArrayList<>());
                return m;
            });
            long seq = r[4].isEmpty() ? 0 : Long.parseLong(r[4]), len = r[5].isEmpty() ? 0 : Long.parseLong(r[5]);
            @SuppressWarnings("unchecked") List<Object> stevens = (List<Object>) side.get("stevens");
            if (len > 0) stevens.add(List.of(t, seq + len, !r[8].isEmpty() || !r[9].isEmpty() ? 1 : 0));
            if (!r[6].isEmpty()) { @SuppressWarnings("unchecked") List<Object> w = (List<Object>) side.get("window"); w.add(List.of(t, Long.parseLong(r[6]))); }
            bytes.computeIfAbsent(endpoint, k -> new TreeMap<>()).merge((long) (t / step), (double) len, Double::sum);
            if (!r[7].isEmpty()) acks.add(new String[] {endpoint, String.valueOf(t), r[7]});
        }
        for (String[] a : acks) {
            // The round trip belongs to the side that sent the data, which is the other side.
            for (var e : by.entrySet()) if (!e.getKey().equals(a[0])) {
                @SuppressWarnings("unchecked") List<Object> l = (List<Object>) e.getValue().get("rtt");
                l.add(List.of(Double.parseDouble(a[1]), Double.parseDouble(a[2])));
            }
        }
        for (var e : by.entrySet()) {
            @SuppressWarnings("unchecked") Map<String, Object> th = (Map<String, Object>) e.getValue().get("throughput");
            @SuppressWarnings("unchecked") List<Object> out = (List<Object>) th.get("rows");
            for (var b : bytes.getOrDefault(e.getKey(), Map.of()).entrySet()) out.add(List.of(b.getKey() * step, b.getValue() * 8 / step));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sides", new ArrayList<>(by.values()));
        return result;
    }

    // ---- POST

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        String path = req.getServletPath();
        String info = req.getPathInfo() == null ? "" : req.getPathInfo().substring(1);
        if (path.equals("/api/v1")) { if (allowed(req, res)) apiV1(req, res, info, "POST"); return; }
        if (!csrfOk(req)) { res.sendError(403, "Invalid form token"); return; }
        if (!allowed(req, res)) return;
        switch (path) {
            case "/language" -> {
                String lang = req.getParameter("language");
                if (lang != null && Knowledge.LANGUAGES.contains(lang)) {
                    Cookie ck = new Cookie("lang", lang);
                    ck.setPath(req.getContextPath().isEmpty() ? "/" : req.getContextPath());
                    ck.setHttpOnly(true);
                    ck.setMaxAge(365 * 86400);
                    res.addCookie(ck);
                }
                String back = Optional.ofNullable(req.getParameter("back")).orElse("/");
                if (!back.startsWith("/") || back.startsWith("//") || back.contains("\\") || back.contains("\n") || back.contains("\r")) back = "/";
                res.sendRedirect(req.getContextPath() + back);
            }
            case "/upload" -> upload(req, res);
            case "/users" -> usersPost(req, res, info);
            case "/security" -> securityPost(req, res, info);
            case "/password" -> {
                Pages.Ctx c = ctx(req);
                Users.Current me = Users.current();
                if (me != null && !me.setupAdmin() && Users.isLdap(me.name())) { res.sendError(400, "An LDAP user's password is set in the directory."); return; }
                if (me != null && !me.setupAdmin()) {
                    // a user of users.json changes only their own password
                    String cur = param(req, "current"), nw = param(req, "new"), ag = param(req, "again");
                    String err = Users.verify(me.name(), cur) == null ? c.t("The current password is not correct.") : !nw.equals(ag) ? c.t("The two new passwords are not the same.") : null;
                    if (err == null) { String pr = Users.problem(me.name(), null, nw, false); if (pr != null) err = c.t(pr, "n", Passwords.MIN_LENGTH); }
                    if (err != null) { html(res, 422, Pages.layout(c, c.t("Password"), "password", "", Pages.passwordPage(c, err), recent(), null)); return; }
                    Users.setOwnPassword(me.name(), nw);
                    Records.audit("password", req.getRemoteAddr(), me.name());
                    res.sendRedirect(req.getContextPath() + "/");
                    return;
                }
                String current = param(req, "current"), next = param(req, "new"), again = param(req, "again");
                String error = null;
                if (!Passwords.matches(current)) error = c.t("The current password is not correct.");
                else if (next.length() < Passwords.MIN_LENGTH) error = c.t("The new password must have at least {n} characters.", "n", Passwords.MIN_LENGTH);
                else if (!next.equals(again)) error = c.t("The two new passwords are not the same.");
                else if (next.equalsIgnoreCase("admin") || next.equalsIgnoreCase(Settings.adminUser())) error = c.t("The password cannot be the user name.");
                if (error != null) { html(res, 422, Pages.layout(c, c.t("Password"), "password", "", Pages.passwordPage(c, error), recent(), null)); return; }
                // with the vault set up, the admin password is the key of the admin key pair: it is re-wrapped, not stored
                if (Vault.isSetUp()) {
                    try { Vault.changeAdminPassword(current, next); } catch (java.security.GeneralSecurityException e) { throw new IOException(e); }
                } else Passwords.save(next);
                Records.audit("password", req.getRemoteAddr(), "");
                res.sendRedirect(req.getContextPath() + (Vault.isSetUp() ? "/preferences" : "/security"));
            }
            case "/preferences" -> {
                List<String> bad = new ArrayList<>();
                List<Map<String, Object>> targets = Records.parseTargets(param(req, "targets"), bad);
                double slow;
                try { slow = Double.parseDouble(param(req, "slow").strip()); if (!(slow > 0 && slow < 3600)) throw new NumberFormatException(); }
                catch (NumberFormatException e) { preferences(req, res, ctx(req), null, ctx(req).t("The slow limit must be a number of seconds.")); return; }
                if (!bad.isEmpty()) { preferences(req, res, ctx(req), null, ctx(req).t("These lines could not be read: {lines}", "lines", String.join("; ", bad))); return; }
                Records.saveThresholds(slow, targets);
                Records.audit("thresholds", req.getRemoteAddr(), "");
                res.sendRedirect(req.getContextPath() + "/preferences");
            }
            case "/filters" -> {
                String back = Optional.ofNullable(req.getParameter("back")).orElse("/");
                if (!back.matches("/a/[0-9a-f]{16}/inspect")) back = "/";
                String[] fp = info.split("/");
                if (fp.length == 2 && fp[1].equals("delete") && fp[0].matches("[0-9a-f]{8}")) Records.removeFilter(fp[0]);
                else if (info.isEmpty()) {
                    String name = cut(req.getParameter("filter_name"), 80);
                    if (name.isEmpty()) { res.sendError(400); return; }
                    Map<String, String> values = new HashMap<>();
                    for (String k : Records.FILTER_FIELDS) values.put(k, cut(req.getParameter(k), 200));
                    Records.addFilter(name, values);
                }
                res.sendRedirect(req.getContextPath() + back);
            }
            case "/tokens" -> {
                String[] tp = info.split("/");
                if (tp.length == 2 && tp[1].equals("delete") && tp[0].matches("[0-9a-f]{8}")) {
                    Records.revokeToken(tp[0]);
                    Records.audit("token_revoked", req.getRemoteAddr(), tp[0]);
                    res.sendRedirect(req.getContextPath() + "/preferences");
                    return;
                }
                String name = cut(req.getParameter("name"), 80);
                if (name.isEmpty()) { res.sendError(400); return; }
                String token = Records.createToken(name);
                Records.audit("token_created", req.getRemoteAddr(), name);
                preferences(req, res, ctx(req), token, null);
            }
            case "/a" -> {
                String[] p = info.split("/");
                if (p.length != 2 || !ID.matcher(p[0]).matches() || !Files.isDirectory(dir(p[0]))) { res.sendError(404); return; }
                if (p[1].equals("baseline")) {
                    Records.setBaseline(p[0]);
                    Records.audit("baseline", req.getRemoteAddr(), p[0]);
                    res.sendRedirect(req.getContextPath() + "/a/" + p[0]);
                } else if (p[1].equals("delete")) {
                    if (!mayDelete(p[0])) { res.sendError(403, "Only the one who uploaded it, or an admin, can delete this capture."); return; }
                    Records.audit("delete", req.getRemoteAddr(), p[0]);
                    deleteTree(dir(p[0]));
                    res.sendRedirect(req.getContextPath() + "/");
                } else if (p[1].equals("notes")) {
                    Map<String, Object> n = new LinkedHashMap<>();
                    n.put("case", cut(req.getParameter("case"), 80));
                    n.put("tags", cut(req.getParameter("tags"), 200));
                    n.put("note", cut(req.getParameter("note"), 4000));
                    Vault.writeText(dir(p[0]).resolve("notes.json"), Json.write(n));
                    Records.audit("notes", req.getRemoteAddr(), p[0]);
                    res.sendRedirect(req.getContextPath() + "/a/" + p[0]);
                } else res.sendError(404);
            }
            default -> res.sendError(404);
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!req.getServletPath().equals("/api/v1")) { res.sendError(405); return; }
        if (!allowed(req, res)) return;
        apiV1(req, res, req.getPathInfo() == null ? "" : req.getPathInfo().substring(1), "DELETE");
    }

    /** The token-based REST API, as docs/api.md describes it. */
    @SuppressWarnings("unchecked")
    private void apiV1(HttpServletRequest req, HttpServletResponse res, String info, String method) throws IOException {
        String[] p = info.split("/");
        try {
            if (method.equals("POST") && info.equals("captures")) { upload(req, res, true); return; }
            if (method.equals("GET") && p.length == 2 && p[0].equals("jobs")) {
                String[] j = JOBS.get(p[1]);
                if (j == null) { apiError(res, 404, "No such job."); return; }
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("job", p[1]); out.put("state", j[0]); out.put("analysis", j[1]); out.put("error", j[2]);
                json(res, out);
                return;
            }
            if (p.length >= 1 && p[0].equals("analyses")) {
                if (p.length == 1 && method.equals("GET")) { json(res, list("")); return; }
                if (p.length >= 2 && !ID.matcher(p[1]).matches()) { apiError(res, 404, "No such analysis."); return; }
                if (p.length == 2 && method.equals("DELETE")) {
                    if (!Files.isDirectory(dir(p[1]))) { apiError(res, 404, "No such analysis."); return; }
                    if (!mayDelete(p[1])) { apiError(res, 403, "Only the one who uploaded it, or an admin, can delete this capture."); return; }
                    Records.audit("delete", req.getRemoteAddr(), p[1]);
                    deleteTree(dir(p[1]));
                    res.setStatus(204);
                    return;
                }
                Map<String, Object> meta = read(dir(p[1]).resolve("meta.json")), result = read(dir(p[1]).resolve("result.json"));
                if (meta == null || result == null) { apiError(res, 404, "No such analysis."); return; }
                if (p.length == 2) { json(res, meta); return; }
                if (p.length == 3 && method.equals("GET")) {
                    Map<String, Object> out = new LinkedHashMap<>();
                    switch (p[2]) {
                        case "overview" -> { for (String k : new String[] {"summary", "http", "tcp", "kinds", "capture_points", "budget", "quality"}) out.put(k, result.get(k)); json(res, out); return; }
                        case "urls", "connections", "hosts" -> { json(res, result.get(p[2])); return; }
                        case "slowest" -> { json(res, result.get("slow")); return; }
                        case "issues" -> {
                            List<Object> rows = new ArrayList<>();
                            for (Map<String, Object> i : (List<Map<String, Object>>) result.get("issues")) {
                                String[] t = Knowledge.issue((String) i.get("key"), language(req));
                                Map<String, Object> m = new LinkedHashMap<>(i);
                                m.put("title", t[0]); m.put("why", t[1]);
                                rows.add(m);
                            }
                            json(res, rows);
                            return;
                        }
                        case "check" -> { json(res, check(result, req)); return; }
                        case "statistics", "services", "voip" -> {
                            if (!kept(p[1])) { apiError(res, 404, "The original capture was not kept."); return; }
                            TShark ts = new TShark(Settings.tshark());
                            Path cap = dir(p[1]).resolve("capture.bin");
                            if (p[2].equals("statistics")) { out.put("hierarchy", Stats.hierarchy(ts, cap)); out.put("overview", Stats.overview(ts, cap)); json(res, out); }
                            else if (p[2].equals("services")) json(res, Services.responseTimes(ts, cap));
                            else json(res, Services.voip(ts, cap));
                            return;
                        }
                        default -> { }
                    }
                }
            }
            apiError(res, 404, "No such call.");
        } catch (TShark.TsharkException e) {
            apiError(res, 422, e.getMessage());
        } catch (ServletException e) {
            apiError(res, 400, String.valueOf(e.getMessage()));
        }
    }

    /** Compares an analysis with limits, so a pipeline can stop on a slow build. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> check(Map<String, Object> result, HttpServletRequest req) {
        Map<String, Object> http = (Map<String, Object>) result.get("http");
        double requests = Analysis.d(http.get("requests")), failed = Analysis.d(http.get("failed"));
        double rate = requests > 0 ? failed / requests * 100 : 0;
        List<Object> broken = new ArrayList<>();
        Map<String, String[]> q = req.getParameterMap();
        Double p95 = Inspect.dbl(q, "p95"), er = Inspect.dbl(q, "error_rate"), slowest = Inspect.dbl(q, "slowest");
        if (p95 != null && Analysis.d(http.get("p95_total")) > p95) broken.add(limit("p95", http.get("p95_total"), p95));
        if (slowest != null && Analysis.d(http.get("max_total")) > slowest) broken.add(limit("slowest", http.get("max_total"), slowest));
        if (er != null && rate > er) broken.add(limit("error_rate", rate, er));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requests", http.get("requests")); out.put("failed", http.get("failed")); out.put("error_rate", rate); out.put("p95", http.get("p95_total")); out.put("slowest", http.get("max_total"));
        out.put("broken", broken); out.put("ok", broken.isEmpty());
        return out;
    }

    private static Map<String, Object> limit(String name, Object value, double allowed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("limit", name); m.put("value", value); m.put("allowed", allowed);
        return m;
    }

    private static String cut(String s, int n) {
        s = s == null ? "" : s.strip();
        return s.length() > n ? s.substring(0, n) : s;
    }

    private static Double epoch(String local) {
        if (local == null || local.isBlank()) return null;
        try {
            if (local.length() == 16) local += ":00";
            return LocalDateTime.parse(local).atZone(ZoneId.systemDefault()).toEpochSecond() * 1.0;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The tshark display filter for the "analyze only part" fields. Every value is checked, since it goes to tshark as written. */
    private static String filter(HttpServletRequest req) throws IllegalArgumentException {
        List<String> parts = new ArrayList<>();
        for (String name : new String[] {"host_a", "host_b"}) {
            String h = Optional.ofNullable(req.getParameter(name)).orElse("").strip();
            if (h.isEmpty()) continue;
            if (!HOST.matcher(h).matches()) throw new IllegalArgumentException("host");
            try {
                InetAddress.getByName(h.split("/")[0]);
            } catch (Exception e) { throw new IllegalArgumentException("host"); }
            parts.add((h.contains(":") ? "ipv6" : "ip") + ".addr == " + h);
        }
        String port = param(req, "port").strip();
        if (!port.isEmpty()) {
            try {
                int n = Integer.parseInt(port);
                if (n < 1 || n > 65535) throw new NumberFormatException();
                parts.add("tcp.port == " + n);
            } catch (NumberFormatException e) { throw new IllegalArgumentException("port"); }
        }
        Double from = epoch(req.getParameter("start")), until = epoch(req.getParameter("end"));
        if (from != null) parts.add("frame.time_epoch >= " + from);
        if (until != null) parts.add("frame.time_epoch <= " + until);
        String display = param(req, "display_filter").strip();
        if (!display.isEmpty()) {
            if (!DisplayFilters.PRESETS.containsKey(display)) throw new IllegalArgumentException("filter");
            parts.add("(" + display + ")");
        }
        return String.join(" and ", parts);
    }

    private void upload(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        upload(req, res, false);
    }

    private void upload(HttpServletRequest req, HttpServletResponse res, boolean api) throws IOException, ServletException {
        Pages.Ctx c = ctx(req);
        Part part = req.getPart("capture");
        if (part == null || part.getSize() == 0) { if (api) apiError(res, 400, c.t("Choose a capture file.")); else fail(res, c, c.t("Choose a capture file.")); return; }
        String filter;
        try {
            filter = filter(req);
        } catch (IllegalArgumentException e) {
            if (api) apiError(res, 400, c.t("The filter is not valid.")); else fail(res, c, c.t("The filter is not valid."));
            return;
        }
        String id = Settings.randomHex(8);
        Path dir = dir(id);
        Files.createDirectories(dir);
        writeOwner(dir);
        Path cap = dir.resolve("capture.bin");
        try (InputStream in = part.getInputStream()) {
            Files.copy(in, cap);
        }
        String name = Path.of(Optional.ofNullable(part.getSubmittedFileName()).orElse("capture")).getFileName().toString();
        Path keylog = null;
        try {
            // Several key logs, such as one per TLS leg on both sides of a NetScaler, are joined into one.
            List<Path> logs = new ArrayList<>();
            long keyBytes = 0;
            for (Part kp : req.getParts()) {
                if (!"keylog".equals(kp.getName()) || kp.getSize() == 0) continue;
                keyBytes += kp.getSize();
                if (keyBytes > KeyLogs.MAX_BYTES) throw new TShark.TsharkException(c.t("Key log is too large."));
                Path one = dir.resolve("keylog-" + logs.size() + ".tmp");
                try (InputStream in = kp.getInputStream()) { Files.copy(in, one); }
                logs.add(one);
                if (!KeyLogs.looksLikeKeyLog(one)) throw new TShark.TsharkException(c.t("This is not a TLS key log."));
            }
            if (!logs.isEmpty()) {
                keylog = dir.resolve("keylog.tmp");
                KeyLogs.join(logs, keylog);
                for (Path one : logs) Files.deleteIfExists(one);
            }
            Path rsa = null;
            Part rp = req.getPart("rsa_key");
            if (rp != null && rp.getSize() > 0) {
                if (rp.getSize() > (1L << 20)) throw new TShark.TsharkException(c.t("The key is too large."));
                rsa = dir.resolve("rsa.tmp");
                try (InputStream in = rp.getInputStream()) { Files.copy(in, rsa); }
                if (!new String(Files.readAllBytes(rsa), StandardCharsets.ISO_8859_1).contains("-----BEGIN")) throw new TShark.TsharkException(c.t("This is not a key or certificate file."));
            }
            List<String> decode = new ArrayList<>();
            for (String rule : param(req, "decode_as").split("[;\\n]")) {
                String r = rule.replace(" ", "").strip();
                if (r.isEmpty()) continue;
                java.util.regex.Matcher m = DECODE_AS.matcher(r);
                if (!m.matches() || Integer.parseInt(m.group(2)) < 1 || Integer.parseInt(m.group(2)) > 65535) throw new TShark.TsharkException(c.t("Decode As rule is not valid: {rule}. Write it as tcp.port==8080,http", "rule", rule.strip()));
                decode.add(r);
            }
            unpack(cap);
            List<Path> parts = new ArrayList<>(List.of(cap));
            int n = 0;
            for (Part extra : req.getParts()) {
                if (!extra.getName().equals("more") || extra.getSize() == 0) continue;
                Path pp = dir.resolve("part-" + (n++) + ".bin");
                try (InputStream in = extra.getInputStream()) { Files.copy(in, pp); }
                unpack(pp);
                parts.add(pp);
            }
            if (parts.size() > 1) {
                long total = 0;
                for (Path pp : parts) { if (!looksLikeCapture(pp)) throw new TShark.TsharkException(c.t("This is not a pcap, pcapng or NetScaler trace capture.")); total += Files.size(pp); }
                if (total > Settings.MAX_UPLOAD) throw new TShark.TsharkException(c.t("The capture is larger than the limit."));
                Path joined = dir.resolve("joined.bin");
                TShark.merge(parts, joined, 300);
                for (Path pp : parts) Files.deleteIfExists(pp);
                Files.move(joined, cap);
            }
            if (!looksLikeCapture(cap)) throw new TShark.TsharkException(c.t("This is not a pcap, pcapng or NetScaler trace capture."));
            // the capture is encrypted before tshark reads it, which then reads it through the vault
            Vault.encryptInPlace(cap);
            if (api) {
                final Path fcap = cap, fkey = keylog, frsa = rsa;
                final List<String> fdecode = decode;
                final String ffilter = filter, fname = name, fclient = req.getRemoteAddr();
                JOBS.put(id, new String[] {"waiting", null, null});
                EXECUTOR.submit(() -> {
                    JOBS.get(id)[0] = "running";
                    try {
                        Runner.analyze(id, dir, fcap, fkey, frsa, fdecode, ffilter, fname, fclient);
                        JOBS.get(id)[0] = "done"; JOBS.get(id)[1] = id;
                    } catch (TShark.TsharkException | IOException | RuntimeException e) {
                        deleteTree(dir);
                        JOBS.get(id)[0] = "failed"; JOBS.get(id)[2] = String.valueOf(e.getMessage());
                    }
                });
                res.setStatus(202);
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("job", id);
                json(res, out);
                return;
            }
            Runner.analyze(id, dir, cap, keylog, rsa, decode, filter, name, req.getRemoteAddr());
            res.sendRedirect(req.getContextPath() + "/a/" + id);
        } catch (TShark.TsharkException e) {
            deleteTree(dir);
            if (api) { res.setStatus(422); Map<String, Object> out = new LinkedHashMap<>(); out.put("error", e.getMessage()); json(res, out); }
            else fail(res, c, e.getMessage());
        }
    }

    private static final Map<String, String[]> JOBS = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.concurrent.ExecutorService EXECUTOR = java.util.concurrent.Executors.newFixedThreadPool(2, r -> { Thread t = new Thread(r, "pcap-analysis"); t.setDaemon(true); return t; });


    private static void apiError(HttpServletResponse res, int status, String message) throws IOException {
        res.setStatus(status);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", message);
        json(res, out);
    }

    private void fail(HttpServletResponse res, Pages.Ctx c, String message) throws IOException {
        String main = Pages.home(c, list(""), "", (int) (Settings.MAX_UPLOAD >> 20), TTL_DAYS, message);
        html(res, 422, Pages.layout(c, c.t("Captures"), "captures", "", main, recent(), null));
    }

    private static final Pattern DECODE_AS = Pattern.compile("(tcp|udp|sctp)\\.port==(\\d{1,5}),([a-z0-9][a-z0-9_.-]{0,31})");

    /** A gzip file is unpacked in place. The unpacked size is checked against the limit while it is written. */
    private static void unpack(Path f) throws IOException, TShark.TsharkException {
        byte[] h = new byte[2];
        try (InputStream in = Files.newInputStream(f)) { if (in.readNBytes(h, 0, 2) < 2) return; }
        if (h[0] != (byte) 0x1f || h[1] != (byte) 0x8b) return;
        Path out = f.resolveSibling(f.getFileName() + ".unpacked");
        long written = 0;
        try (InputStream in = new java.util.zip.GZIPInputStream(Files.newInputStream(f)); java.io.OutputStream os = Files.newOutputStream(out)) {
            byte[] buf = new byte[1 << 16];
            int r;
            while ((r = in.read(buf)) > 0) {
                written += r;
                if (written > Settings.MAX_UPLOAD) { Files.deleteIfExists(out); throw new TShark.TsharkException("The unpacked capture is larger than the limit."); }
                os.write(buf, 0, r);
            }
        } catch (java.util.zip.ZipException e) {
            Files.deleteIfExists(out);
            throw new TShark.TsharkException("The gzip file could not be read.");
        }
        Files.move(out, f, StandardCopyOption.REPLACE_EXISTING);
    }

    static boolean looksLikeCapture(Path f) throws IOException {
        byte[] h = new byte[512];
        int n;
        try (InputStream in = Files.newInputStream(f)) { n = in.readNBytes(h, 0, h.length); }
        if (n < 4) return false;
        int m = ((h[0] & 0xff) << 24) | ((h[1] & 0xff) << 16) | ((h[2] & 0xff) << 8) | (h[3] & 0xff);
        return m == 0xa1b2c3d4 || m == 0xd4c3b2a1 || m == 0xa1b23c4d || m == 0x4d3cb2a1 || m == 0x0a0d0d0a || isNsTrace(h, n);
    }

    /** A NetScaler trace (nstrace, from "start nstrace") opens with a signature record that names its version,
     *  such as "NetScaler V35 Performance Data". tshark reads versions 1.0 to 3.5. */
    static boolean isNsTrace(byte[] head, int n) {
        String text = new String(head, 0, n, StandardCharsets.ISO_8859_1);
        return java.util.regex.Pattern.compile("NetScaler V\\d\\d Performance Data").matcher(text).find();
    }
}
