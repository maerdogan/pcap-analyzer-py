package io.pcapanalyzer;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/** HTTP Basic sign-in. With no password configured, every request is refused. */
@WebFilter("/*")
public class AuthFilter implements Filter {
    @Override
    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) rq;
        HttpServletResponse res = (HttpServletResponse) rs;
        if (!Passwords.configured()) {
            res.sendError(503, "Set PCAP_ANALYZER_ADMIN_PASSWORD to enable sign-in.");
            return;
        }
        String h = req.getHeader("Authorization");
        String path = req.getServletPath();
        if (h != null && h.regionMatches(true, 0, "Bearer ", 0, 7)
                && ((req.getMethod().equals("GET") && (path.equals("/api/a") || path.equals("/api/analysis"))) || path.equals("/api/v1"))
                && Records.validToken(h.substring(7).trim())) {
            chain.doFilter(rq, rs);
            return;
        }
        if (h != null && h.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String[] up = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8).split(":", 2);
                if (up.length == 2 && same(up[0], Settings.adminUser()) & Passwords.matches(up[1])) {
                    chain.doFilter(rq, rs);
                    return;
                }
            } catch (IllegalArgumentException ignored) { }
        }
        if (h != null) Records.audit("login_failed", req.getRemoteAddr(), "");
        res.setHeader("WWW-Authenticate", "Basic realm=\"pcap-analyzer\", charset=\"UTF-8\"");
        res.sendError(401);
    }

    private static boolean same(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
