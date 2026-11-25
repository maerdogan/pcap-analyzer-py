package io.pcapanalyzer;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/** HTTP Basic sign-in, roles and the first-run password change. */
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
        String h = req.getHeader("Authorization");
        String path = req.getServletPath();
        if (h != null && h.regionMatches(true, 0, "Bearer ", 0, 7)
                && ((req.getMethod().equals("GET") && (path.equals("/api/a") || path.equals("/api/analysis"))) || path.equals("/api/v1"))
                && Records.validToken(h.substring(7).trim())) {
            // an API token uploads and deletes like an analyst
            Users.set(new Users.Current("api-token", Users.Role.ANALYST, false, null, false));
            try { chain.doFilter(rq, rs); } finally { Users.set(null); }
            return;
        }
        if (h != null && h.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String[] up = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8).split(":", 2);
                Users.Current who = null;
                boolean setupName = up.length == 2 && same(up[0], Settings.adminUser());
                if (up.length == 2 && !setupName && Vault.isSetUp() && !Vault.isUnlocked()) {
                    // after a restart the user list is still encrypted: only the setup admin can open it
                    locked(res);
                    return;
                }
                if (setupName & Passwords.matches(up[1])) who = new Users.Current(up[0], Users.Role.ADMIN, true, null, Passwords.mustChange());
                else if (up.length == 2 && !setupName) who = Users.verify(up[0], up[1]);
                if (who != null && who.mustChange()) {
                    // first sign-in, or a password an admin set: nothing but choosing a new password until it is done
                    boolean open = path.equals("/password") || path.equals("/language") || path.startsWith("/static");
                    if (!open) { res.sendRedirect(req.getContextPath() + "/password"); return; }
                } else if (who != null && who.setupAdmin() && !Vault.isSetUp()) {
                    // then the admin chooses the master key, and every file is encrypted with it
                    boolean open = path.equals("/security") || path.equals("/password") || path.equals("/language") || path.startsWith("/static");
                    if (!open) { res.sendRedirect(req.getContextPath() + "/security"); return; }
                } else if (who != null && !who.setupAdmin() && !Vault.isSetUp()) {
                    locked(res);
                    return;
                }
                if (who != null) {
                    Users.Role needed = needed(req.getMethod(), path, req.getPathInfo());
                    if (!who.role().atLeast(needed)) { res.sendError(403, "Your role cannot do this."); return; }
                    if (who.setupAdmin()) req.setAttribute("pcap.admin.password", up[1]);
                    Users.set(who);
                    try { chain.doFilter(rq, rs); } finally { Users.set(null); }
                    return;
                }
            } catch (IllegalArgumentException ignored) { }
        }
        if (h != null) Records.audit("login_failed", req.getRemoteAddr(), "");
        res.setHeader("WWW-Authenticate", "Basic realm=\"pcap-analyzer\", charset=\"UTF-8\"");
        res.sendError(401);
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
