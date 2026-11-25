package io.pcapanalyzer;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/** Sign-in with a form and a session for pages, HTTP Basic or a token for the API; roles, the first-run password change and the master key setup. */
@WebFilter("/*")
public class AuthFilter implements Filter {
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(AuthFilter.class.getName());

    @Override
    public void init(FilterConfig config) {
        try {
            if (Passwords.adoptEnvironment())
                LOG.warning("PCAP_ANALYZER_ADMIN_PASSWORD was saved as a hash in password.json and is ignored from now on. Remove it from the server settings.");
            else if (!Settings.adminPassword().isEmpty())
                LOG.warning("PCAP_ANALYZER_ADMIN_PASSWORD is set but ignored, since password.json holds the password. Remove it from the server settings.");
        } catch (IOException e) {
            LOG.log(java.util.logging.Level.WARNING, "PCAP_ANALYZER_ADMIN_PASSWORD could not be saved as a hash", e);
        }
    }

    @Override
    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) rq;
        HttpServletResponse res = (HttpServletResponse) rs;
        // forms are sent as UTF-8 without saying so; read them that way, or names such as "Yılmaz" are garbled
        if (req.getCharacterEncoding() == null) req.setCharacterEncoding("UTF-8");
        String path = req.getServletPath();
        if (path.startsWith("/static/")) { chain.doFilter(rq, rs); return; }  // style, script and logo, also for the sign-in page
        if (path.equals("/login")) { login(req, res); return; }
        if (path.equals("/logout")) { logout(req, res); return; }
        if (path.equals("/language") && fromSession(req) == null) { chain.doFilter(rq, rs); return; }  // choosing a language works on the sign-in page too
        String h = req.getHeader("Authorization");
        boolean api = path.equals("/api/a") || path.equals("/api/analysis") || path.equals("/api/v1") || path.equals("/export");
        if (h != null && h.regionMatches(true, 0, "Bearer ", 0, 7)
                && ((req.getMethod().equals("GET") && (path.equals("/api/a") || path.equals("/api/analysis"))) || path.equals("/api/v1"))
                && Records.validToken(h.substring(7).trim())) {
            // an API token uploads and deletes like an analyst
            run(req, res, chain, new Users.Current("api-token", Users.Role.ANALYST, false, null, false));
            return;
        }
        Users.Current who;
        if (api && h != null && h.regionMatches(true, 0, "Basic ", 0, 6)) {
            // scripts and the command line sign in on every call; pages use the sign-in form and a session
            String[] up;
            try { up = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8).split(":", 2); }
            catch (IllegalArgumentException e) { up = new String[0]; }
            if (up.length == 2 && !isSetupName(up[0]) && Vault.isSetUp() && !Vault.isUnlocked()) { locked(res); return; }
            who = up.length == 2 ? verify(up[0], up[1]) : null;
            if (who == null) {
                Records.audit("login_failed", req.getRemoteAddr(), up.length == 2 ? up[0] : "");
                res.setHeader("WWW-Authenticate", "Basic realm=\"pcap-analyzer\", charset=\"UTF-8\"");
                res.sendError(401);
                return;
            }
        } else {
            who = fromSession(req);
            if (who == null) {
                if (api) { res.setHeader("WWW-Authenticate", "Basic realm=\"pcap-analyzer\", charset=\"UTF-8\""); res.sendError(401); return; }
                String next = req.getRequestURI().substring(req.getContextPath().length()) + (req.getQueryString() == null ? "" : "?" + req.getQueryString());
                res.sendRedirect(req.getContextPath() + "/login" + (req.getMethod().equals("GET") && !next.equals("/") ? "?next=" + java.net.URLEncoder.encode(next, StandardCharsets.UTF_8) : ""));
                return;
            }
        }
        if (who.mustChange()) {
            // first sign-in, or a password an admin set: nothing but choosing a new password until it is done
            if (!(path.equals("/password") || path.equals("/language"))) { res.sendRedirect(req.getContextPath() + "/password"); return; }
        } else if (who.setupAdmin() && !Vault.isSetUp()) {
            // then the admin chooses the master key, and every file is encrypted with it
            if (!(path.equals("/security") || path.equals("/password") || path.equals("/language"))) { res.sendRedirect(req.getContextPath() + "/security"); return; }
        } else if (!who.setupAdmin() && !Vault.isSetUp()) {
            locked(res);
            return;
        }
        Users.Role needed = needed(req.getMethod(), path, req.getPathInfo());
        if (!who.role().atLeast(needed)) { res.sendError(403, "Your role cannot do this."); return; }
        run(req, res, chain, who);
    }

    private static void run(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Users.Current who) throws IOException, ServletException {
        Users.set(who);
        try { chain.doFilter(req, res); } finally { Users.set(null); }
    }

    private static boolean isSetupName(String name) { return same(name, Settings.adminUser()); }

    /** The user with this name and password, or null. For the setup admin the password also opens the encrypted data after a restart. */
    private static Users.Current verify(String name, String password) {
        if (isSetupName(name)) return Passwords.matches(password) ? new Users.Current(name, Users.Role.ADMIN, true, null, Passwords.mustChange()) : null;
        return Users.verify(name, password);
    }

    /** The signed-in user of the session, read again on every request; null when there is none, or the user was deleted or got a new password from an admin. */
    private static Users.Current fromSession(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        if (s == null || !(s.getAttribute("user") instanceof String name)) return null;
        Object gen = s.getAttribute("generation");
        if (!(gen instanceof Integer g) || g != Users.generation(name)) { s.invalidate(); return null; }
        if (isSetupName(name)) return new Users.Current(name, Users.Role.ADMIN, true, null, Passwords.mustChange());
        if (!Vault.isUnlocked()) { s.invalidate(); return null; }
        Users.Current who = Users.lookup(name);
        if (who == null) s.invalidate();
        return who;
    }

    /** The sign-in page, and signing in: a new session id each time, so a session fixed beforehand is worthless. */
    private static void login(HttpServletRequest req, HttpServletResponse res) throws IOException {
        Pages.Ctx c = AppServlet.context(req);
        String next = safeNext(req.getParameter("next"));
        if (!req.getMethod().equals("POST")) {
            if (fromSession(req) != null) { res.sendRedirect(req.getContextPath() + next); return; }
            page(res, 200, Pages.loginPage(c, next, null));
            return;
        }
        if (!AppServlet.formTokenOk(req)) { res.sendError(403, "Invalid form token"); return; }
        String name = String.valueOf(req.getParameter("user")).strip(), password = req.getParameter("password");
        if (password == null || name.isEmpty()) { page(res, 401, Pages.loginPage(c, next, c.t("The user name or password is not correct."))); return; }
        if (!isSetupName(name) && Vault.isSetUp() && !Vault.isUnlocked()) {
            page(res, 503, Pages.loginPage(c, next, c.t("The data is encrypted and opens only when the admin signs in after a restart. Try again in a few minutes.")));
            return;
        }
        if (!isSetupName(name) && !Vault.isSetUp()) {
            page(res, 503, Pages.loginPage(c, next, c.t("The admin has not finished the setup yet. Try again later.")));
            return;
        }
        Users.Current who = verify(name, password);
        if (who == null) {
            Records.audit("login_failed", req.getRemoteAddr(), name);
            try { Thread.sleep(400); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            page(res, 401, Pages.loginPage(c, next, c.t("The user name or password is not correct.")));
            return;
        }
        HttpSession s = req.getSession(true);
        req.changeSessionId();
        s.setAttribute("user", who.name());
        s.setAttribute("generation", Users.generation(who.name()));
        Users.set(who);
        try { Records.audit("login", req.getRemoteAddr(), ""); } finally { Users.set(null); }
        res.sendRedirect(req.getContextPath() + next);
    }

    private static void logout(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!req.getMethod().equals("POST") || !AppServlet.formTokenOk(req)) { res.sendError(403, "Invalid form token"); return; }
        Users.Current who = fromSession(req);
        HttpSession s = req.getSession(false);
        if (s != null) s.invalidate();
        if (who != null) {
            Users.set(who);
            try { Records.audit("logout", req.getRemoteAddr(), ""); } finally { Users.set(null); }
        }
        res.sendRedirect(req.getContextPath() + "/login");
    }

    /** Where to go after signing in: a path of this app only, never another site. */
    static String safeNext(String next) {
        if (next == null || !next.startsWith("/") || next.startsWith("//") || next.contains("\\") || next.contains("\n") || next.contains("\r") || next.startsWith("/login")) return "/";
        return next;
    }

    private static void page(HttpServletResponse res, int status, String html) throws IOException {
        res.setStatus(status);
        res.setContentType("text/html;charset=utf-8");
        res.setHeader("Cache-Control", "no-store");
        res.getWriter().write(html);
    }

    private static void locked(HttpServletResponse res) throws IOException {
        res.setStatus(503);
        res.setContentType("text/html;charset=utf-8");
        res.setHeader("Retry-After", "60");
        res.getWriter().write("<!doctype html><meta charset=utf-8><title>pcap-analyzer</title><body style=\"font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem\">"
            + "<h1>Waiting for the admin</h1><p>The data of this app is encrypted. After a restart, or before the first setup is done, it opens only when the admin signs in. Try again in a few minutes.</p>"
            + "<p lang=\"tr\">Uygulamanın verileri şifreli. Yeniden başlatmadan sonra ya da ilk kurulum bitmeden, admin giriş yapana kadar açılmaz. Birkaç dakika sonra yeniden deneyin.</p></body>");
    }

    /** The least role a request needs. Reading is open to every user; changing captures needs an analyst; settings, users, tokens and the audit log need an admin. */
    static Users.Role needed(String method, String path, String info) {
        String i = info == null ? "" : info;
        if (path.equals("/preferences") || path.equals("/audit") || path.equals("/tokens") || path.equals("/users") || path.equals("/security")) return Users.Role.ADMIN;
        boolean write = !method.equals("GET") && !method.equals("HEAD");
        if (!write) return Users.Role.VIEWER;
        if (path.equals("/language") || path.equals("/password")) return Users.Role.VIEWER;
        return Users.Role.ANALYST;
    }

    private static boolean same(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
