package io.pcapanalyzer;

import java.util.*;

import static io.pcapanalyzer.Fmt.esc;

/** HTML of the pages, following the Python templates and their CSS classes. */
public final class Pages {
    public static final String VERSION = "0.7.6";

    /** What every page needs: where the app lives, the language and the form token. */
    public record Ctx(String path, String lang, String csrf, String uri, String id, String baseline) {
        Ctx withId(String id) { return new Ctx(path, lang, csrf, uri, id, baseline); }
        String t(String text, Object... kv) {
            String s = Knowledge.ui(text, lang);
            for (int i = 0; i + 1 < kv.length; i += 2) s = s.replace("{" + kv[i] + "}", String.valueOf(kv[i + 1]));
            return s;
        }
    }

    private Pages() {}

    private static final Map<String, String> ICONS = Map.ofEntries(
            Map.entry("captures", "<path d=\"M4 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z\"/>"),
            Map.entry("overview", "<rect x=\"4\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"13\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"4\" y=\"13\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"13\" y=\"13\" width=\"7\" height=\"7\" rx=\"1.5\"/>"),
            Map.entry("urls", "<path d=\"M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1\"/><path d=\"M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1\"/>"),
            Map.entry("connections", "<path d=\"M4 8h13l-3-3M20 16H7l3 3\"/>"),
            Map.entry("issues", "<path d=\"M12 4l9 16H3z\"/><path d=\"M12 10v4M12 17.5v.01\"/>"),
            Map.entry("hosts", "<rect x=\"4\" y=\"4\" width=\"16\" height=\"7\" rx=\"1.5\"/><rect x=\"4\" y=\"13\" width=\"16\" height=\"7\" rx=\"1.5\"/><path d=\"M8 7.5h.01M8 16.5h.01\"/>"),
            Map.entry("backends", "<ellipse cx=\"12\" cy=\"6\" rx=\"7\" ry=\"2.5\"/><path d=\"M5 6v12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V6M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5\"/>"),
            Map.entry("inspect", "<circle cx=\"11\" cy=\"11\" r=\"6\"/><path d=\"M20 20l-4.5-4.5\"/>"),
            Map.entry("tls", "<rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"1.5\"/><path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/>"),
            Map.entry("compare", "<rect x=\"3\" y=\"4\" width=\"7\" height=\"16\" rx=\"1.5\"/><rect x=\"14\" y=\"4\" width=\"7\" height=\"16\" rx=\"1.5\"/>"),
            Map.entry("trend", "<path d=\"M3 17l6-6 4 4 8-8\"/><path d=\"M15 7h6v6\"/>"),
            Map.entry("guide", "<path d=\"M4 5.5A1.5 1.5 0 0 1 5.5 4H11v16H5.5A1.5 1.5 0 0 1 4 18.5z\"/><path d=\"M20 5.5A1.5 1.5 0 0 0 18.5 4H13v16h5.5a1.5 1.5 0 0 0 1.5-1.5z\"/>"),
            Map.entry("preferences", "<path d=\"M4 7h10M18 7h2M4 17h4M12 17h8\"/><circle cx=\"16\" cy=\"7\" r=\"2\"/><circle cx=\"10\" cy=\"17\" r=\"2\"/>"),
            Map.entry("stats", "<path d=\"M4 20h16M7 16v-5M12 16V6M17 16v-8\"/>"),
            Map.entry("menu", "<path d=\"M4 7h16M4 12h16M4 17h16\"/>"));

    static String icon(String name) {
        return "<svg class=\"icon\" viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" focusable=\"false\">"
                + ICONS.getOrDefault(name, "") + "</svg>";
    }

    // ---- layout

    @SuppressWarnings("unchecked")
    public static String layout(Ctx c, String title, String section, String captureNav, String main, List<Map<String, Object>> recent, String currentId) {
        StringBuilder words = new StringBuilder("{");
        String[] used = {"Method", "URL", "Requests", "Failed", "Average", "95th pct", "Slowest", "Service", "Status", "none", "Start", "Client", "Server", "Type",
                "Server name", "Packets", "Bytes", "Open for", "Round trip", "Retrans.", "Closed", "Save as PNG", "Save as SVG", "Errors", "Retransmissions",
                "Open connections", "95th percentile", "Host", "Connections", "Addresses"};
        for (int i = 0; i < used.length; i++) words.append(i > 0 ? "," : "").append(Json.write(used[i])).append(':').append(Json.write(c.t(used[i])));
        words.append('}');
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html>\n<html lang=\"").append(c.lang()).append("\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.append("<title>").append(esc(title)).append("</title>\n");
        String p = c.path();
        sb.append("<link rel=\"icon\" href=\"").append(p).append("/static/brand/favicon.png\" type=\"image/png\">\n");
        sb.append("<link rel=\"stylesheet\" href=\"").append(p).append("/static/vendor/ag-grid.min.css\">\n");
        sb.append("<link rel=\"stylesheet\" href=\"").append(p).append("/static/vendor/ag-theme-quartz.min.css\">\n");
        sb.append("<link rel=\"stylesheet\" href=\"").append(p).append("/static/app.css?v=").append(VERSION).append("\">\n");
        sb.append("<script src=\"").append(p).append("/static/vendor/ag-grid.min.js\" defer></script>\n");
        sb.append("<script src=\"").append(p).append("/static/vendor/echarts.min.js\" defer></script>\n");
        sb.append("<script src=\"").append(p).append("/static/app.js?v=").append(VERSION).append("\" defer></script>\n</head>\n");
        sb.append("<body class=\"app\" data-words='").append(esc(words.toString()).replace("&quot;", "\"").replace("&#39;", "&apos;")).append("'>\n");
        sb.append("<a class=\"skip\" href=\"#main\">").append(esc(c.t("Skip to content"))).append("</a>\n");
        sb.append("<aside class=\"side\" id=\"side\">\n<a class=\"side-brand\" href=\"").append(p).append("/\" aria-label=\"pcap-analyzer\"><img src=\"").append(p)
          .append("/static/brand/logo-on-dark.png\" alt=\"\" width=\"176\" height=\"64\"></a>\n<div class=\"side-scroll\">\n");
        sb.append("<nav class=\"side-group\" aria-label=\"").append(esc(c.t("Main"))).append("\"><p class=\"side-label\" aria-hidden=\"true\">").append(esc(c.t("Main"))).append("</p>\n");
        String[][] mainNav = {{"captures", "/", "Captures"}, {"compare", "/compare", "Compare"}, {"trend", "/trend", "Trend"}, {"guide", "/capture-guide", "Capture guide"}, {"preferences", "/preferences", "Preferences"}};
        for (String[] n : mainNav)
            sb.append("<a href=\"").append(p).append(n[1]).append("\"").append(section.equals(n[0]) ? " aria-current=\"page\"" : "").append(">").append(icon(n[0])).append("<span>").append(esc(c.t(n[2]))).append("</span></a>");
        sb.append("</nav>\n");
        sb.append(captureNav);
        if (!recent.isEmpty()) {
            sb.append("<nav class=\"ticker\" aria-label=\"").append(esc(c.t("Recent captures"))).append("\"><p class=\"side-label ticker-name\" aria-hidden=\"true\">")
              .append(esc(c.t("Recent captures"))).append("</p><ol>");
            for (Map<String, Object> r : recent) {
                sb.append("<li><a href=\"").append(p).append("/a/").append(r.get("id")).append("\" title=\"").append(esc(r.get("filename"))).append("\"")
                  .append(r.get("id").equals(currentId) ? " aria-current=\"true\"" : "").append("><b>").append(esc(r.get("filename"))).append("</b><span><time>")
                  .append(Fmt.clock(Analysis.d(r.get("created")))).append("</time> · ").append(esc(c.t("{n} requests", "n", r.get("transactions")))).append("</span></a></li>");
            }
            sb.append("</ol></nav>\n");
        }
        sb.append("</div>\n<p class=\"side-foot\">").append(esc(c.t("Version {n}", "n", VERSION))).append("</p>\n</aside>\n<div class=\"scrim\" data-nav-close hidden></div>\n<div class=\"shell\">\n");
        sb.append("<header class=\"top\"><button type=\"button\" class=\"icon-button nav-toggle\" aria-controls=\"side\" aria-expanded=\"false\" data-nav-toggle>")
          .append(icon("menu")).append("<span class=\"sr\">").append(esc(c.t("Menu"))).append("</span></button>\n<div class=\"top-end\">\n");
        sb.append("<form method=\"post\" action=\"").append(p).append("/language\" class=\"language\"><input type=\"hidden\" name=\"back\" value=\"").append(esc(c.uri()))
          .append("\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><label><span>").append(esc(c.t("Language"))).append("</span><select name=\"language\" data-submit>");
        for (String code : Knowledge.LANGUAGES)
            sb.append("<option value=\"").append(code).append("\"").append(code.equals(c.lang()) ? " selected" : "").append(">").append(Knowledge.LANGUAGE_NAMES.get(code)).append("</option>");
        sb.append("</select></label><noscript><button>").append(esc(c.t("Save"))).append("</button></noscript></form>\n</div></header>\n");
        sb.append("<main class=\"page\" id=\"main\">").append(main).append("</main>\n</div>\n</body>\n</html>\n");
        return sb.toString();
    }

    static String crumbs(Ctx c, String[][] steps) {
        StringBuilder sb = new StringBuilder("<nav class=\"crumbs\" aria-label=\"" + esc(c.t("Location")) + "\"><ol>");
        for (String[] s : steps) sb.append("<li>").append(s[1] != null ? "<a href=\"" + s[1] + "\">" + esc(s[0]) + "</a>" : esc(s[0])).append("</li>");
        return sb.append("</ol></nav>").toString();
    }

    public static String capnav(Ctx c, String id, String current, long issueCount) {
        String[][] tabs = {{"overview", "", "Overview"}, {"issues", "?tab=issues", "Issues"}, {"urls", "?tab=urls", "URLs"}, {"connections", "?tab=connections", "Connections"},
                {"hosts", "?tab=hosts", "Hosts"}, {"backends", "?tab=backends", "Servers"}, {"tls", "?tab=tls", "TLS"}, {"stats", "?tab=stats", "Statistics"}, {"inspect", "/inspect", "Inspect traffic"}};
        StringBuilder sb = new StringBuilder("<nav class=\"side-group views\" aria-label=\"" + esc(c.t("Capture views")) + "\"><p class=\"side-label\" aria-hidden=\"true\">"
                + esc(c.t("Capture views")) + "</p>\n");
        for (String[] t : tabs)
            sb.append("<a href=\"").append(c.path()).append("/a/").append(id).append(t[1]).append("\"").append(t[0].equals(current) ? " aria-current=\"page\"" : "").append(">")
              .append(icon(t[0])).append("<span>").append(esc(t[2].equals("URLs") || t[2].equals("TLS") ? t[2] : c.t(t[2]))).append("</span>")
              .append(t[0].equals("issues") && issueCount > 0 ? "<span class=\"count\">" + issueCount + "</span>" : "").append("</a>\n");
        return sb.append("</nav>\n").toString();
    }

    // ---- home

    @SuppressWarnings("unchecked")
    public static String home(Ctx c, List<Map<String, Object>> analyses, String search, int maxMb, int ttlDays, String error) {
        StringBuilder sb = new StringBuilder();
        sb.append("<header class=\"page-head\"><div><h1>").append(esc(c.t("Captures"))).append("</h1><p class=\"muted\">")
          .append(esc(c.t("Upload a capture, or open one you analyzed earlier."))).append("</p></div></header>\n");
        if (error != null) sb.append("<p class=\"error\" role=\"alert\">").append(esc(error)).append("</p>");
        sb.append("<div class=\"columns\">\n<section class=\"panel flush\">\n<div class=\"section-head\"><h2>").append(esc(c.t("Analyzed captures"))).append("</h2>");
        if (!analyses.isEmpty() || !search.isEmpty())
            sb.append("<span class=\"hint\">").append(esc(c.t("Kept for {n} days. Everyone with the login sees this list.", "n", ttlDays))).append("</span>");
        sb.append("</div>\n<form class=\"list-search\" method=\"get\" action=\"").append(c.path()).append("/\" role=\"search\"><input type=\"search\" id=\"q\" name=\"q\" value=\"")
          .append(esc(search)).append("\" aria-label=\"").append(esc(c.t("Search files, cases, tags and notes"))).append("\" placeholder=\"").append(esc(c.t("Search files, cases, tags and notes"))).append("\"></form>\n");
        if (analyses.isEmpty()) {
            sb.append("<p class=\"empty\">").append(esc(c.t("Nothing here yet. Upload a capture above to see where its time went."))).append("</p>");
        } else {
            sb.append("<ol class=\"captures\">\n");
            String lastDay = null;
            for (Map<String, Object> m : analyses) {
                String day = Fmt.day(Analysis.d(m.get("created")));
                if (!day.equals(lastDay)) { sb.append("<li class=\"day\">").append(day).append("</li>\n"); lastDay = day; }
                String id = (String) m.get("id");
                sb.append("<li class=\"capture-row\"><time>").append(Fmt.clock(Analysis.d(m.get("created")))).append("</time><div class=\"capture-name\"><a href=\"")
                  .append(c.path()).append("/a/").append(id).append("\">").append(esc(m.get("filename"))).append("</a>");
                if (m.get("filter") != null && !m.get("filter").toString().isEmpty()) sb.append("<span class=\"hint\">").append(esc(m.get("filter"))).append("</span>");
                sb.append("</div><dl class=\"tiles\"><div><dt>").append(esc(c.t("Size"))).append("</dt><dd>").append(Fmt.size((Number) m.get("size"))).append("</dd></div><div><dt>")
                  .append(esc(c.t("Connections"))).append("</dt><dd>").append(m.get("connections")).append("</dd></div><div><dt>").append(esc(c.t("Requests"))).append("</dt><dd>")
                  .append(m.get("transactions")).append("</dd></div></dl>");
                sb.append("<form method=\"post\" action=\"").append(c.path()).append("/a/").append(id).append("/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf())
                  .append("\"><button class=\"link danger\" aria-label=\"").append(esc(c.t("Delete {name}", "name", m.get("filename")))).append("\">").append(esc(c.t("Delete"))).append("</button></form></li>\n");
            }
            sb.append("</ol>");
        }
        sb.append("</section>\n<section class=\"panel\">\n<h2>").append(esc(c.t("Analyze a capture"))).append("</h2>\n");
        sb.append("<form method=\"post\" action=\"").append(c.path()).append("/upload\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\">\n");
        sb.append("<label class=\"drop\"><span>").append(esc(c.t("Capture file, up to {n} MB (.cap, .pcap, .pcapng)", "n", maxMb))).append("</span><input type=\"file\" name=\"capture\" required></label>\n");
        sb.append("<details><summary>").append(esc(c.t("Add more parts of the same capture"))).append("</summary><div class=\"fields\"><label>").append(esc(c.t("More parts"))).append(" <input type=\"file\" name=\"more\" multiple></label></div><p class=\"hint\">")
          .append(esc(c.t("Parts are joined in time order. gzip files are unpacked first. The limit applies to the joined size."))).append("</p></details>\n");
        sb.append("<details><summary>").append(esc(c.t("Decrypt HTTPS"))).append("</summary><div class=\"fields\"><label>").append(esc(c.t("TLS key log file"))).append(" <input type=\"file\" name=\"keylog\"></label><label>")
          .append(esc(c.t("RSA private key"))).append(" <input type=\"file\" name=\"rsa_key\"></label></div><p class=\"hint\">")
          .append(esc(c.t("A key log works for all modern TLS. An RSA key only reads old RSA key exchange. Keys are removed after the analysis."))).append("</p></details>\n");
        sb.append("<details><summary>").append(esc(c.t("Analyze only part of the capture"))).append("</summary><div class=\"fields\">");
        sb.append("<label>").append(esc(c.t("Host"))).append(" <input name=\"host_a\" placeholder=\"10.0.0.5, 10.0.0.0/24\"></label>");
        sb.append("<label>").append(esc(c.t("Second host"))).append(" <input name=\"host_b\"></label>");
        sb.append("<label>").append(esc(c.t("TCP port"))).append(" <input name=\"port\" inputmode=\"numeric\"></label>");
        sb.append("<label>").append(esc(c.t("From"))).append(" <input name=\"start\" type=\"datetime-local\" step=\"1\"></label>");
        sb.append("<label>").append(esc(c.t("Until"))).append(" <input name=\"end\" type=\"datetime-local\" step=\"1\"></label>");
        sb.append("<label class=\"wide\">").append(esc(c.t("Wireshark display filter"))).append(" <input name=\"display_filter\" spellcheck=\"false\" placeholder=\"http.host contains &quot;example&quot;\"></label>");
        sb.append("<label class=\"wide\">").append(esc(c.t("Decode As"))).append(" <input name=\"decode_as\" spellcheck=\"false\" placeholder=\"tcp.port==9000,http; udp.port==4433,quic\"><span class=\"hint\">")
          .append(esc(c.t("Read a port as another protocol, as Wireshark's Decode As does. Separate rules with ;"))).append("</span></label></div></details>\n<button class=\"primary\">").append(esc(c.t("Analyze capture"))).append("</button>\n</form>\n</section>\n</div>\n");
        return sb.toString();
    }

    // ---- analysis

    static String status(Ctx c, Object code) {
        if (code instanceof Number n) return "<span class=\"status s" + (n.intValue() / 100) + "\">" + n.intValue() + "</span>";
        return "<span class=\"status s0\" title=\"" + esc(c.t("No response")) + "\" aria-label=\"" + esc(c.t("No response")) + "\">–</span>";
    }

    @SuppressWarnings("unchecked")
    static String strip(Ctx c, Map<String, Object> phases) {
        double total = phases.values().stream().mapToDouble(Analysis::d).sum();
        StringBuilder label = new StringBuilder(), spans = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Object> e : phases.entrySet()) {
            double sec = Analysis.d(e.getValue());
            if (sec <= 0) continue;
            String name = Knowledge.phaseLabel(e.getKey(), c.lang());
            label.append(first ? "" : ", ").append(name).append(' ').append(Fmt.seconds(sec));
            first = false;
            spans.append("<span class=\"ph-").append(e.getKey()).append("\" style=\"width:").append(String.format(Locale.ROOT, "%.2f", total > 0 ? sec / total * 100 : 0))
                 .append("%\" title=\"").append(esc(name)).append(": ").append(Fmt.seconds(sec)).append("\"></span>");
        }
        return "<div class=\"strip\" role=\"img\" aria-label=\"" + esc(label) + "\">" + spans + "</div>";
    }

    @SuppressWarnings("unchecked")
    static String breakdown(Ctx c, List<Map<String, Object>> budget) {
        double total = budget.stream().mapToDouble(p -> Analysis.d(p.get("seconds"))).sum();
        List<Map<String, Object>> rows = new ArrayList<>(budget);
        rows.removeIf(p -> Analysis.d(p.get("seconds")) <= 0);
        rows.sort((a, b) -> Double.compare(Analysis.d(b.get("seconds")), Analysis.d(a.get("seconds"))));
        StringBuilder sb = new StringBuilder("<table class=\"breakdown\"><thead><tr><th>" + esc(c.t("Phase")) + "</th><th class=\"num\">" + esc(c.t("Time")) + "</th><th class=\"num\">"
                + esc(c.t("Share")) + "</th></tr></thead><tbody>");
        for (Map<String, Object> p : rows) {
            String name = (String) p.get("name");
            double sec = Analysis.d(p.get("seconds"));
            sb.append("<tr><td title=\"").append(esc(Knowledge.phaseAbout(name, c.lang()))).append("\"><i class=\"swatch ph-").append(name).append("\"></i>").append(esc(Knowledge.phaseLabel(name, c.lang())))
              .append("</td><td class=\"num\">").append(Fmt.seconds(sec)).append("</td><td class=\"num\">")
              .append(esc(c.t("{n}%", "n", String.format(Locale.ROOT, "%.1f", total > 0 ? sec / total * 100 : 0)))).append("</td></tr>");
        }
        return sb.append("</tbody></table>").toString();
    }

    @SuppressWarnings("unchecked")
    static String waterfall(Ctx c, List<Map<String, Object>> rows) {
        double longest = rows.stream().mapToDouble(r -> Analysis.d(r.get("longest"))).max().orElse(0);
        StringBuilder sb = new StringBuilder("<ol class=\"waterfall\">\n");
        for (Map<String, Object> t : rows) {
            String cause = (String) t.get("cause");
            String uri = String.valueOf(t.get("uri"));
            if (uri.length() > 90) uri = uri.substring(0, 89) + "…";
            String why = Knowledge.summary(cause, (Map<String, Object>) t.get("facts"), c.lang());
            double width = longest > 0 ? Analysis.d(t.get("longest")) / longest * 100 : 0;
            String label = esc(t.get("method") + " " + uri);
            String head = t.get("id") != null && c.id() != null ? "<a class=\"wf-url\" href=\"" + c.path() + "/a/" + c.id() + "/txn/" + t.get("id") + "\">" + label + "</a>" : "<span class=\"wf-url\">" + label + "</span>";
            sb.append("<li>").append(status(c, t.get("status"))).append("<div class=\"wf-main\">").append(head).append("<p class=\"why\"><b>")
              .append(esc(Knowledge.topicLabel(cause, c.lang()))).append(".</b> ").append(esc(why)).append("</p></div><div class=\"wf-bar\"><div class=\"bar-fill\" style=\"width:")
              .append(String.format(Locale.ROOT, "%.1f", width)).append("%\">").append(strip(c, (Map<String, Object>) t.get("phases"))).append("</div></div><span class=\"took\">")
              .append(Fmt.seconds(Analysis.dn(t.get("longest")))).append("</span></li>\n");
        }
        return sb.append("</ol>").toString();
    }

    static String score(Ctx c, Map<String, Object> h) {
        long failed = ((Number) h.get("failed")).longValue();
        return "<div class=\"score\"><div class=\"score-side\"><b class=\"good\">" + esc(c.t("Successful")) + "</b></div><div class=\"score-mid\"><strong><span class=\"good\">" + h.get("ok")
                + "</span><i>–</i><span" + (failed > 0 ? " class=\"bad\"" : "") + ">" + failed + "</span></strong><small>" + esc(c.t("95th percentile")) + ": " + Fmt.seconds(Analysis.dn(h.get("p95_total")))
                + "</small></div><div class=\"score-side\"><b" + (failed > 0 ? " class=\"bad\"" : "") + ">" + esc(c.t("Failed")) + "</b></div></div>";
    }

    static String metrics(Ctx c, Map<String, Object> h) {
        return "<dl class=\"metrics\"><div><dt>" + esc(c.t("Requests")) + "</dt><dd>" + h.get("requests") + "</dd></div><div><dt>" + esc(c.t("Average")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(h.get("avg_total")))
                + "</dd></div><div><dt>" + esc(c.t("Median")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(h.get("p50_total"))) + "</dd></div><div><dt>" + esc(c.t("95th percentile")) + "</dt><dd>"
                + Fmt.seconds(Analysis.dn(h.get("p95_total"))) + "</dd></div><div><dt>" + esc(c.t("Slowest")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(h.get("max_total"))) + "</dd></div></dl>";
    }

    @SuppressWarnings("unchecked")
    static String quality(Ctx c, Map<String, Object> q) {
        String level = (String) q.get("level");
        String label = c.t(Character.toUpperCase(level.charAt(0)) + level.substring(1));
        StringBuilder sb = new StringBuilder("<section class=\"panel trust trust-" + level + "\"><h2>" + esc(c.t("Capture trust: {level}", "level", label)) + "</h2>");
        List<Map<String, Object>> found = (List<Map<String, Object>>) q.get("findings");
        if (found.isEmpty()) sb.append("<p>").append(esc(c.t("No problems were found in the capture itself."))).append("</p>");
        else {
            sb.append("<ul>");
            for (Map<String, Object> f : found) sb.append("<li>").append(esc(Knowledge.quality((String) f.get("key"), ((Number) f.get("n")).longValue(), c.lang()))).append("</li>");
            sb.append("</ul>");
        }
        return sb.append("</section>").toString();
    }

    static String chart(Ctx c, String kind, String id, String name, boolean tall, boolean withBase) {
        return "<div class=\"chart" + (tall ? " tall" : "") + "\" data-chart=\"" + kind + "\" data-src=\"" + c.path() + "/api/a/" + id + "/" + name + "\" data-name=\"" + name + "\"></div>";
    }

    @SuppressWarnings("unchecked")
    public static String analysis(Ctx c, Map<String, Object> meta, Map<String, Object> r, String tab, Map<String, Object> notes, String drift, boolean kept, String flt, List<Map<String, Object>> seqs) {
        String id = (String) meta.get("id");
        String filename = (String) meta.get("filename");
        String label = switch (tab) { case "urls" -> "URLs"; case "connections" -> "Connections"; case "issues" -> "Issues"; case "hosts" -> "Hosts"; case "backends" -> "Servers"; case "tls" -> "TLS"; case "stats" -> "Statistics"; default -> "Overview"; };
        String heading = label.equals("URLs") || label.equals("TLS") ? label : c.t(label);
        Map<String, Object> http = (Map<String, Object>) r.get("http"), tcp = (Map<String, Object>) r.get("tcp");
        long requests = ((Number) http.get("requests")).longValue();
        StringBuilder sb = new StringBuilder();
        sb.append(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {filename, c.path() + "/a/" + id}, {heading, null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(heading)).append("</h1><p class=\"muted\">")
          .append(esc(c.t("{file}, {size}, {packets} packets. Captured {when}.", "file", filename, "size", Fmt.size((Number) meta.get("size")), "packets", meta.get("packets"),
                  "when", Fmt.when(Analysis.dn(meta.get("capture_start")))))).append("</p></div>\n");
        sb.append("<div class=\"actions\"><details class=\"menu\"><summary>").append(esc(c.t("Download"))).append("</summary><div class=\"menu-body\"><a href=\"").append(c.path()).append("/api/a/")
          .append(id).append("/result\">").append(esc(c.t("Full report"))).append(" (JSON)</a><a href=\"").append(c.path()).append("/export/").append(id).append("/report.html\">").append(esc(c.t("Full report (HTML)"))).append("</a><a href=\"").append(c.path()).append("/export/").append(id).append("/requests.har\">").append(esc(c.t("Requests (HAR)"))).append("</a><table>");
        String[][] tables = {{"requests", "Requests"}, {"urls", "URLs"}, {"connections", "Connections"}, {"hosts", "Hosts"}, {"issues", "Issues"}};
        for (String[] t : tables) {
            String tableLabel = t[1].equals("URLs") ? "URLs" : c.t(t[1]);
            sb.append("<tr><td>").append(esc(tableLabel)).append("</td>");
            for (String[] f : new String[][] {{"csv", "CSV"}, {"xlsx", "Excel"}, {"json", "JSON"}})
                sb.append("<td><a href=\"").append(c.path()).append("/export/").append(id).append("/").append(t[0]).append(".").append(f[0]).append("\" aria-label=\"").append(esc(tableLabel + " " + f[1])).append("\">").append(f[1]).append("</a></td>");
            sb.append("</tr>");
        }
        sb.append("</table></div></details>");
        if (id.equals(c.baseline())) sb.append("<span class=\"status s2\">").append(esc(c.t("Baseline"))).append("</span>");
        else sb.append("<form method=\"post\" action=\"").append(c.path()).append("/a/").append(id).append("/baseline\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><button>").append(esc(c.t("Set as baseline"))).append("</button></form>");
        sb.append("<a class=\"button primary\" href=\"").append(c.path()).append("/a/").append(id).append("/inspect\">").append(esc(c.t("Inspect traffic"))).append("</a></div></div>\n");
        if (tab.equals("overview") && requests > 0) sb.append(score(c, http)).append(metrics(c, http));
        sb.append("</header>\n<div id=\"tab\">");
        if (tab.equals("issues")) {
            sb.append(issuesTab(c, id, (List<Map<String, Object>>) r.get("issues")));
        } else if (tab.equals("hosts")) {
            sb.append("<p class=\"hint\">").append(esc(c.t("Named from the HTTP Host header or TLS SNI. The server address is used when neither is visible."))).append("</p>\n");
            sb.append("<div class=\"grid short ag-theme-quartz\" data-grid=\"hosts\" data-src=\"").append(c.path()).append("/api/a/").append(id).append("/hosts\"></div>");
        } else if (tab.equals("stats")) {
            sb.append(statsTab(c, id, (List<Map<String, Object>>) Stats.httpLoad(r), kept, flt, seqs));
        } else if (tab.equals("tls")) {
            sb.append(tlsTab(c, id, (Map<String, Object>) r.get("tls")));
        } else if (tab.equals("backends")) {
            sb.append(backendsTab(c, id, (List<Map<String, Object>>) r.get("backends")));
        } else if (tab.equals("urls")) {
            sb.append("<p class=\"hint\">").append(esc(c.t("Similar URLs are grouped, so /users/123 and /users/456 appear as one line. Select a row to inspect it."))).append("</p>\n");
            sb.append("<div class=\"grid ag-theme-quartz\" data-grid=\"urls\" data-src=\"").append(c.path()).append("/api/a/").append(id).append("/urls\" data-base=\"").append(c.path()).append("/a/").append(id).append("\"></div>");
        } else if (tab.equals("connections")) {
            sb.append("<p class=\"hint\">").append(esc(c.t("Every TCP connection in the capture. Select one to see all its packets in order, follow its TCP or HTTP stream, and its TCP details."))).append("</p>\n");
            sb.append("<div class=\"grid ag-theme-quartz\" data-grid=\"connections\" data-src=\"").append(c.path()).append("/api/a/").append(id).append("/connections\" data-base=\"").append(c.path()).append("/a/").append(id).append("\"></div>");
        } else {
            sb.append(quality(c, (Map<String, Object>) r.get("quality")));
            for (Object w : (List<Object>) r.getOrDefault("warnings", new ArrayList<>())) sb.append("<p class=\"warn\">").append(esc(Knowledge.warning((String) w, c.lang()))).append("</p>");
            sb.append(drift != null ? drift : "");
            sb.append("<div class=\"columns\"><div class=\"stack\">");
            if (requests > 0) {
                sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Traffic over time"))).append("</h2>").append(chart(c, "timeline", id, "timeline", true, false)).append("</section>");
                sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Slowest requests"))).append("</h2>").append(waterfall(c, (List<Map<String, Object>>) r.get("slow"))).append("</section>");
                sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Response time spread"))).append("</h2>").append(chart(c, "histogram", id, "histogram", false, false)).append("</section>");
            }
            sb.append("</div><div class=\"stack\"><section class=\"panel\"><h2>").append(esc(c.t("Where the time went"))).append("</h2>");
            List<Map<String, Object>> budget = (List<Map<String, Object>>) r.get("budget");
            double total = budget.stream().mapToDouble(p -> Analysis.d(p.get("seconds"))).sum();
            if (total > 0) {
                Map<String, Object> phases = new LinkedHashMap<>();
                budget.forEach(p -> phases.put((String) p.get("name"), p.get("seconds")));
                sb.append("<div class=\"budget\">").append(strip(c, phases)).append("</div>").append(breakdown(c, budget));
                Double cs = Analysis.dn(meta.get("capture_start")), ce = Analysis.dn(meta.get("capture_end"));
                String hint = ce != null && cs != null
                        ? c.t("{requests} requests over {connections} connections, spanning {time}.", "requests", requests, "connections", tcp.get("connections"), "time", Fmt.seconds(ce - cs))
                        : c.t("{requests} requests over {connections} connections.", "requests", requests, "connections", tcp.get("connections"));
                sb.append("<p class=\"hint\">").append(esc(hint)).append("</p>");
            } else {
                sb.append("<p>").append(esc(c.t("No HTTP requests were found, so only TCP data is available. If the traffic is HTTPS, analyze it again with a key log."))).append("</p>");
            }
            sb.append("</section>");
            if (requests > 0) sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Status codes"))).append("</h2>").append(chart(c, "statuses", id, "statuses", false, false)).append("</section>");
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Case and notes"))).append("</h2><form method=\"post\" action=\"").append(c.path()).append("/a/").append(id)
              .append("/notes\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><div class=\"fields\"><label>").append(esc(c.t("Case number")))
              .append(" <input id=\"case\" name=\"case\" maxlength=\"80\" value=\"").append(esc(notes.get("case"))).append("\"></label><label>").append(esc(c.t("Tags")))
              .append(" <input id=\"tags\" name=\"tags\" maxlength=\"200\" value=\"").append(esc(notes.get("tags"))).append("\"></label><label class=\"wide\">").append(esc(c.t("Note")))
              .append(" <textarea id=\"note\" name=\"note\" rows=\"3\" maxlength=\"4000\">").append(esc(notes.get("note"))).append("</textarea></label></div><button>")
              .append(esc(c.t("Save notes"))).append("</button></form></section>");
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("TCP"))).append("</h2><dl class=\"facts\">");
            fact(sb, c.t("Connections"), tcp.get("connections"));
            fact(sb, c.t("Handshakes seen"), tcp.get("handshakes"));
            fact(sb, c.t("Resets"), tcp.get("resets"));
            fact(sb, c.t("Retransmissions"), tcp.get("retransmissions"));
            fact(sb, c.t("Average connect"), Fmt.seconds(Analysis.dn(tcp.get("avg_connect"))));
            fact(sb, c.t("Average round trip"), Fmt.seconds(Analysis.dn(tcp.get("avg_rtt_server"))));
            StringBuilder kinds = new StringBuilder(), points = new StringBuilder();
            for (Map<String, Object> k : (List<Map<String, Object>>) r.get("kinds")) kinds.append(kinds.length() > 0 ? ", " : "").append(k.get("kind")).append(" (").append(k.get("connections")).append(")");
            for (Map<String, Object> k : (List<Map<String, Object>>) r.get("capture_points")) {
                String raw = String.valueOf(k.get("capture_point")).replace('_', ' ');
                points.append(points.length() > 0 ? ", " : "").append(c.t(Character.toUpperCase(raw.charAt(0)) + raw.substring(1))).append(" (").append(k.get("connections")).append(")");
            }
            fact(sb, c.t("Traffic types"), kinds);
            fact(sb, c.t("Capture point"), points);
            sb.append("</dl></section></div></div>");
        }
        return sb.append("</div>").toString();
    }

    private static void fact(StringBuilder sb, String name, Object value) {
        sb.append("<div><dt>").append(esc(name)).append("</dt><dd>").append(esc(value)).append("</dd></div>");
    }

    @SuppressWarnings("unchecked")
    static String issuesTab(Ctx c, String id, List<Map<String, Object>> issues) {
        if (issues.isEmpty()) return "<p class=\"empty\">" + esc(c.t("No problems stand out in this capture.")) + "</p>";
        StringBuilder sb = new StringBuilder("<section class=\"panel flush\"><ul class=\"issues\">");
        for (Map<String, Object> i : issues) {
            String[] info = Knowledge.issue((String) i.get("key"), c.lang());
            sb.append("<li class=\"sev-").append(i.get("severity")).append("\"><span class=\"n\">").append(i.get("count")).append("</span><div>");
            if (Boolean.TRUE.equals(i.get("drill"))) sb.append("<a href=\"").append(c.path()).append("/a/").append(id).append("/issue/").append(i.get("key")).append("\">").append(esc(info[0])).append("</a>");
            else sb.append("<b>").append(esc(info[0])).append("</b>");
            sb.append("<p>").append(esc(info[1])).append("</p></div></li>");
        }
        return sb.append("</ul></section>").toString();
    }

    @SuppressWarnings("unchecked")
    static String backendsTab(Ctx c, String id, List<Map<String, Object>> backends) {
        if (backends.isEmpty()) return "<p class=\"empty\">" + esc(c.t("No HTTP requests were found, so there are no servers to compare.")) + "</p>";
        StringBuilder sb = new StringBuilder();
        if (backends.size() < 2) sb.append("<p class=\"hint\">").append(esc(c.t("Only one server is visible here. To compare servers, capture behind the load balancer."))).append("</p>");
        sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Server"))).append("</th><th>").append(esc(c.t("Compared with the others"))).append("</th>");
        for (String h : new String[] {"Connections", "Requests", "Failed", "Median", "95th percentile", "Median service", "Resets", "Retransmissions"})
            sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
        sb.append("</tr></thead><tbody>");
        for (Map<String, Object> b : backends) {
            Object flag = b.get("flag");
            sb.append("<tr").append(flag != null ? " class=\"flagged\"" : "").append("><td>").append(esc(b.get("server_ip") + ":" + b.get("server_port"))).append("</td><td>");
            sb.append("slow".equals(flag) ? "<b>" + esc(c.t("Slower than the others")) + "</b>" : "errors".equals(flag) ? "<b>" + esc(c.t("More errors than the others")) + "</b>" : esc(c.t("Normal")));
            sb.append("</td><td class=\"num\">").append(b.get("connections")).append("</td><td class=\"num\">").append(b.get("requests")).append("</td><td class=\"num\">").append(b.get("failed"))
              .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(b.get("p50_total")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(b.get("p95_total"))))
              .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(b.get("p50_service")))).append("</td><td class=\"num\">").append(b.get("resets")).append("</td><td class=\"num\">")
              .append(b.get("retransmissions")).append("</td></tr>");
        }
        sb.append("</tbody></table></div><p class=\"hint\">").append(esc(c.t("Servers on the same port are compared, and each needs at least 5 requests. Different URLs can explain a difference, so open a server to check."))).append("</p>");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String issuePage(Ctx c, Map<String, Object> meta, String key, Map<String, Object> detail) {
        String id = (String) meta.get("id");
        String[] info = Knowledge.issue(key, c.lang());
        StringBuilder sb = new StringBuilder();
        sb.append(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Issues"), c.path() + "/a/" + id + "?tab=issues"}, {info[0], null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(info[0])).append("</h1><p class=\"muted\">").append(esc(info[1])).append("</p></div></div></header>");
        sb.append(guidePanel(c, Knowledge.guide(info[2], null, c.lang())));
        List<Map<String, Object>> conns = (List<Map<String, Object>>) detail.get("connections"), txns = (List<Map<String, Object>>) detail.get("transactions");
        if (!conns.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Connections"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Client"))).append("</th><th>")
              .append(esc(c.t("Server"))).append("</th><th>").append(esc(c.t("Type"))).append("</th><th class=\"num\">").append(esc(c.t("Duration"))).append("</th><th>").append(esc(c.t("Closed by"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> k : conns) {
                String by = k.get("closed_by") == null ? "–" : String.valueOf(k.get("closed_by"));
                sb.append("<tr><td>").append(esc(k.get("client"))).append("</td><td>").append(esc(k.get("server"))).append("</td><td>").append(esc(k.get("kind"))).append("</td><td class=\"num\">")
                  .append(Fmt.seconds(Analysis.dn(k.get("duration")))).append("</td><td>").append(esc(c.t(Character.toUpperCase(by.charAt(0)) + by.substring(1))))
                  .append(k.get("close_type") != null ? " (" + k.get("close_type") + ")" : "").append("</td></tr>");
            }
            sb.append("</tbody></table></div></section>");
        }
        List<Map<String, Object>> details = (List<Map<String, Object>>) detail.getOrDefault("details", new ArrayList<>()), pairs = (List<Map<String, Object>>) detail.getOrDefault("pairs", new ArrayList<>()),
                packets = (List<Map<String, Object>>) detail.getOrDefault("packets", new ArrayList<>());
        Map<String, String> labels = Map.ofEntries(Map.entry("format_error", "Format error"), Map.entry("server_failure", "Server failure (SERVFAIL)"), Map.entry("no_such_name", "No such name (NXDOMAIN)"), Map.entry("not_implemented", "Not implemented"),
                Map.entry("refused", "Refused"), Map.entry("network", "Network unreachable"), Map.entry("host", "Host unreachable"), Map.entry("protocol", "Protocol unreachable"), Map.entry("port", "Port unreachable"),
                Map.entry("fragmentation_needed", "Fragmentation needed"), Map.entry("network_prohibited", "Network prohibited"), Map.entry("host_prohibited", "Host prohibited"),
                Map.entry("administratively_prohibited", "Administratively prohibited"), Map.entry("no_route", "No route"), Map.entry("address", "Address unreachable"));
        if (details.size() > 1 || (!details.isEmpty() && details.get(0).get("detail") != null)) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Kinds"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Kind"))).append("</th><th class=\"num\">").append(esc(c.t("Packets"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> d : details) { String k = d.get("detail") == null ? "–" : d.get("detail").toString(); sb.append("<tr><td>").append(esc(c.t(labels.getOrDefault(k, k)))).append("</td><td class=\"num\">").append(d.get("n")).append("</td></tr>"); }
            sb.append("</tbody></table></div></section>");
        }
        if (!pairs.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Source and destination"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Source"))).append("</th><th>").append(esc(c.t("Destination")))
              .append("</th><th class=\"num\">").append(esc(c.t("Packets"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> x : pairs) sb.append("<tr><td>").append(esc(x.get("src") == null ? "–" : x.get("src"))).append("</td><td>").append(esc(x.get("dst") == null ? "–" : x.get("dst"))).append("</td><td class=\"num\">").append(x.get("n")).append("</td></tr>");
            sb.append("</tbody></table></div></section>");
        }
        if (!packets.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Packets"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th class=\"num\">").append(esc(c.t("Frame"))).append("</th><th>").append(esc(c.t("Time")))
              .append("</th><th>").append(esc(c.t("Source"))).append("</th><th>").append(esc(c.t("Destination"))).append("</th><th>").append(esc(c.t("Detail"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> x : packets)
                sb.append("<tr><td class=\"num\">").append(x.get("frame")).append("</td><td>").append(Fmt.clock(Analysis.d(x.get("time")))).append("</td><td>").append(esc(x.get("src") == null ? "–" : x.get("src"))).append("</td><td>")
                  .append(esc(x.get("dst") == null ? "–" : x.get("dst"))).append("</td><td>").append(esc(x.get("detail") == null ? "–" : x.get("detail"))).append("</td></tr>");
            sb.append("</tbody></table></div></section>");
        }
        if (!txns.isEmpty()) sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Requests"))).append("</h2>").append(waterfall(c, txns)).append("</section>");
        return sb.toString();
    }

    // ---- connection, request and inspect pages

    private static String facts(StringBuilder sb, String name, Object value) {
        sb.append("<div><dt>").append(esc(name)).append("</dt><dd>").append(esc(value)).append("</dd></div>");
        return "";
    }

    @SuppressWarnings("unchecked")
    public static String connectionPage(Ctx c, Map<String, Object> meta, Map<String, Object> conn, List<Map<String, Object>> txns, List<Map<String, Object>> top, boolean percent, boolean kept) {
        String id = (String) meta.get("id");
        Object stream = conn.get("stream");
        StringBuilder sb = new StringBuilder();
        sb.append(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Connections"), c.path() + "/a/" + id + "?tab=connections"},
                {conn.get("client_ip") + ":" + conn.get("client_port"), null}}));
        String closed = conn.get("close_type") == null ? c.t("Still open when the capture ended.")
                : "client".equals(conn.get("closed_by")) ? c.t("Closed by the client with {how}.", "how", conn.get("close_type")) : c.t("Closed by the server with {how}.", "how", conn.get("close_type"));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(c.t("Connection {n}", "n", stream))).append("</h1><p class=\"muted\">")
          .append(esc(c.t("{kind}, {n} requests, open for {time}.", "kind", conn.get("kind"), "n", txns.size(), "time", Fmt.seconds(Analysis.dn(conn.get("duration")))) + " " + closed)).append("</p></div>");
        if (kept) sb.append("<div class=\"actions\"><a class=\"button\" href=\"").append(c.path()).append("/a/").append(id).append("/conn/").append(stream).append("/follow\">").append(esc(c.t("Follow TCP stream"))).append("</a><a class=\"button\" href=\"").append(c.path()).append("/export/").append(id).append("/conn/").append(stream)
              .append(".pcapng\">").append(esc(c.t("Download this connection as PCAP"))).append("</a></div>");
        sb.append("</div><div class=\"score ends\"><div class=\"score-side\"><small>").append(esc(c.t("Client"))).append("</small><b>").append(esc(conn.get("client"))).append("</b></div><div class=\"score-mid\"><strong>")
          .append(txns.size()).append("</strong><small>").append(esc(c.t("Requests"))).append("</small></div><div class=\"score-side\"><small>").append(esc(c.t("Server"))).append("</small><b>")
          .append(esc(conn.get("server"))).append("</b></div></div></header>\n");
        String base = c.path() + "/a/" + id + "/conn/" + stream;
        if (!top.isEmpty()) {
            sb.append("<section class=\"panel flush\"><div class=\"section-head\"><h2>").append(esc(c.t("Slowest requests"))).append("</h2><p class=\"switch\"><a href=\"?percent=false\"")
              .append(!percent ? " aria-current=\"true\"" : "").append(">").append(esc(c.t("First 5"))).append("</a><a href=\"?percent=true\"").append(percent ? " aria-current=\"true\"" : "").append(">")
              .append(esc(c.t("Top 10%"))).append("</a></p></div>").append(waterfall(c, top)).append("</section>");
        }
        if (!txns.isEmpty())
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Requests on a time axis"))).append("</h2><div class=\"chart\" data-chart=\"waterfall\" data-src=\"").append(c.path()).append("/api/a/").append(id)
              .append("/waterfall/").append(stream).append("\" data-name=\"connection-").append(stream).append("\"></div></section>");
        if (kept) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("All packets"))).append("</h2><p class=\"muted pad\">").append(esc(c.t("Every packet of this connection in order, as Wireshark's packet list shows it.")))
              .append("</p><div id=\"conn-packets\" data-load=\"").append(base).append("/packets\"><p class=\"empty\">").append(esc(c.t("Reading the packets again. A large capture can take a few minutes the first time."))).append("</p></div></section>");
            sb.append("<section class=\"panel\"><div class=\"section-head\"><h2>").append(esc(c.t("TCP graphs"))).append("</h2><p class=\"switch\" data-graph-switch>");
            String[][] kinds = {{"stevens", "Stevens"}, {"throughput", "Throughput"}, {"rtt", "Round trip"}, {"window", "Window"}};
            for (String[] k : kinds) sb.append("<a href=\"#\" data-kind=\"").append(k[0]).append("\"").append(k[0].equals("stevens") ? " aria-current=\"true\"" : "").append(">").append(esc(c.t(k[1]))).append("</a>");
            sb.append("</p></div><div class=\"chart tall\" data-chart=\"tcpgraph\" data-kind=\"stevens\" data-src=\"").append(c.path()).append("/api/a/").append(id).append("/tcpgraph/").append(stream)
              .append("\" data-name=\"connection-").append(stream).append("-graph\"></div><p class=\"hint\">")
              .append(esc(c.t("Stevens: sequence numbers over time, resent segments in red. Throughput: bits per second each side sent. Round trip: the time until each segment was acknowledged. Window: the receive window each side offered.")))
              .append("</p></section>");
        }
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("TCP details"))).append("</h2><dl class=\"facts\">");
        facts(sb, c.t("Connect time"), Fmt.seconds(Analysis.dn(conn.get("connect_time"))));
        facts(sb, c.t("Round trip to server"), Fmt.seconds(Analysis.dn(conn.get("rtt_server"))));
        facts(sb, c.t("Round trip to client"), Fmt.seconds(Analysis.dn(conn.get("rtt_client"))));
        String raw = String.valueOf(conn.get("capture_point")).replace('_', ' ');
        facts(sb, c.t("Capture point"), c.t(Character.toUpperCase(raw.charAt(0)) + raw.substring(1)));
        facts(sb, "MSS", conn.get("mss") == null ? "–" : conn.get("mss"));
        facts(sb, "SACK", Boolean.TRUE.equals(conn.get("sack")) ? c.t("Yes") : c.t("No"));
        facts(sb, c.t("Window scale"), conn.get("wscale") == null ? "–" : conn.get("wscale"));
        facts(sb, c.t("Smallest window"), conn.get("min_window") == null ? "–" : conn.get("min_window"));
        facts(sb, c.t("Retransmissions"), conn.get("retransmissions"));
        facts(sb, c.t("Zero windows"), conn.get("zero_windows"));
        facts(sb, c.t("Client sent"), Fmt.size((Number) conn.get("payload_client")));
        facts(sb, c.t("Server sent"), Fmt.size((Number) conn.get("payload_server")));
        facts(sb, c.t("Byte ratio"), conn.get("byte_ratio_db") == null ? "–" : conn.get("byte_ratio_db") + " dB");
        return sb.append("</dl></section>").toString();
    }

    /** Paket listesi parcasi (baglanti veya istek sayfasi icin), Python surumundeki _conn_packets.html ile ayni duzende. */
    @SuppressWarnings("unchecked")
    public static String packetsFragment(Ctx c, Map<String, Object> p) {
        List<Map<String, Object>> rows = (List<Map<String, Object>>) p.get("rows");
        if (rows == null || rows.isEmpty()) return "<p class=\"empty\">" + esc(c.t("No packets match.")) + "</p>";
        StringBuilder sb = new StringBuilder("<div class=\"table-wrap packets\"><table><thead><tr><th class=\"num\">").append(esc(c.t("Frame"))).append("</th><th class=\"num\">").append(esc(c.t("Time")))
                .append("</th><th>").append(esc(c.t("Direction"))).append("</th><th>").append(esc(c.t("Flags"))).append("</th><th class=\"num\">Seq</th><th class=\"num\">Ack</th><th class=\"num\">")
                .append(esc(c.t("Length"))).append("</th><th class=\"num\">").append(esc(c.t("Window"))).append("</th><th>").append(esc(c.t("Protocol"))).append("</th><th>").append(esc(c.t("Info"))).append("</th></tr></thead><tbody>");
        for (Map<String, Object> r : rows) {
            boolean fromClient = Boolean.TRUE.equals(r.get("from_client"));
            List<String> flags = (List<String>) r.get("flags");
            List<String> marks = (List<String>) r.get("marks");
            sb.append("<tr class=\"").append(fromClient ? "from-client" : "from-server").append(marks.isEmpty() ? "" : " marked").append("\"><td class=\"num\">").append(esc(r.get("frame")))
              .append("</td><td class=\"num\">").append(String.format(Locale.ROOT, "%.6f", ((Number) r.get("t")).doubleValue())).append("</td><td>")
              .append(esc(c.t(fromClient ? "Client \u2192 server" : "Server \u2192 client"))).append("</td><td>").append(flags.isEmpty() ? "\u2013" : esc(String.join(", ", flags)))
              .append("</td><td class=\"num\">").append(r.get("seq") == null ? "\u2013" : esc(r.get("seq"))).append("</td><td class=\"num\">").append(r.get("ack") == null ? "\u2013" : esc(r.get("ack")))
              .append("</td><td class=\"num\">").append(esc(r.get("len"))).append("</td><td class=\"num\">").append(r.get("win") == null ? "\u2013" : esc(r.get("win")))
              .append("</td><td>").append(esc(r.get("protocol"))).append("</td><td>");
            for (String m : marks) sb.append("<span class=\"status s4\">").append(esc(c.t(m))).append("</span> ");
            sb.append(esc(r.get("info"))).append("</td></tr>");
        }
        sb.append("</tbody></table></div><dl class=\"legend pad\">");
        for (Map<String, Object> x : (List<Map<String, Object>>) p.get("legend"))
            sb.append("<div><dt>").append(esc(x.get("flag"))).append("</dt><dd>").append(esc(c.t((String) x.get("meaning")))).append("</dd></div>");
        sb.append("<div><dt>Seq</dt><dd>").append(esc(c.t("where this packet's data starts in the sender's byte stream, counted from 0"))).append("</dd></div>")
          .append("<div><dt>Ack</dt><dd>").append(esc(c.t("the next byte the sender expects from the other side"))).append("</dd></div></dl>");
        if (Boolean.TRUE.equals(p.get("cut")))
            sb.append("<p class=\"hint pad\">").append(esc(c.t("Only the first {n} packets are shown. Download the connection as PCAP to see all of it.", "n", p.get("limit")))).append("</p>");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String transactionPage(Ctx c, Map<String, Object> meta, Map<String, Object> t, Map<String, Object> conn, Map<String, Object> det) {
        return transactionPage(c, meta, t, conn, det, false);
    }

    @SuppressWarnings("unchecked")
    public static String transactionPage(Ctx c, Map<String, Object> meta, Map<String, Object> t, Map<String, Object> conn, Map<String, Object> det, boolean kept) {
        String id = (String) meta.get("id");
        String cause = (String) t.get("cause");
        Map<String, Object> facts = Analysis.facts(t, conn);
        StringBuilder sb = new StringBuilder();
        sb.append(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Connections"), c.path() + "/a/" + id + "?tab=connections"},
                {c.t("Connection {n}", "n", t.get("stream")), c.path() + "/a/" + id + "/conn/" + t.get("stream")}, {t.get("method") + " " + t.get("uri"), null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(status(c, t.get("status"))).append(' ').append(esc(t.get("method") + " " + t.get("uri"))).append("</h1><p class=\"muted\"><b>")
          .append(esc(Knowledge.topicLabel(cause, c.lang()))).append(".</b> ").append(esc(Knowledge.summary(cause, facts, c.lang()))).append("</p></div></div>");
        sb.append(metrics2(c, t)).append("</header>");
        sb.append(guidePanel(c, Knowledge.guide(cause, facts, c.lang())));
        Map<String, Object> phases = (Map<String, Object>) t.get("phases");
        List<Map<String, Object>> budget = new ArrayList<>();
        phases.forEach((k, v) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("name", k); m.put("seconds", v); budget.add(m); });
        sb.append("<div class=\"columns\"><section class=\"panel\"><h2>").append(esc(c.t("Where the time went"))).append("</h2><div class=\"budget\">").append(strip(c, phases)).append("</div>")
          .append(breakdown(c, budget)).append("</section><section class=\"panel\"><h2>").append(esc(c.t("Request"))).append("</h2><dl class=\"facts\">");
        facts(sb, c.t("Host"), t.get("host") == null ? "–" : t.get("host"));
        facts(sb, c.t("Client"), t.get("client"));
        facts(sb, c.t("Server"), t.get("server"));
        facts(sb, "HTTP", t.get("http_version"));
        facts(sb, c.t("Request size"), Fmt.size((Number) t.get("req_bytes")));
        facts(sb, c.t("Response size"), Fmt.size((Number) t.get("resp_bytes")));
        facts(sb, c.t("Content type"), t.get("content_type") == null ? "–" : t.get("content_type"));
        facts(sb, c.t("Started"), Fmt.when(Analysis.dn(t.get("req_start"))));
        facts(sb, c.t("Request frame"), t.get("req_frame"));
        facts(sb, c.t("Response frame"), t.get("resp_frame") == null ? "–" : t.get("resp_frame"));
        sb.append("</dl></section></div>");
        if (kept) {
            // Bu istegin paketleri, kayitli yakalamadan sonradan okunur
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Packets of this request"))).append("</h2><p class=\"muted pad\">")
              .append(esc(c.t("Every packet of this request in order: the connection setup when the request opened the connection, the request, the response and its acknowledgment.")))
              .append(" <a href=\"").append(c.path()).append("/a/").append(id).append("/conn/").append(t.get("stream")).append("\">").append(esc(c.t("All packets of the connection")))
              .append("</a></p><div id=\"txn-packets\" data-load=\"").append(c.path()).append("/a/").append(id).append("/txn/").append(t.get("id")).append("/packets\"><p class=\"empty\">")
              .append(esc(c.t("Reading the packets again. A large capture can take a few minutes the first time."))).append("</p></div></section>");
        }
        if (det != null) {
            String[][] blocks = {{"req_headers", "Request headers"}, {"req_body", "Request body"}, {"resp_headers", "Response headers"}, {"resp_body", "Response body"}};
            for (String[] b : blocks)
                if (det.get(b[0]) != null && !det.get(b[0]).toString().isEmpty())
                    sb.append("<section class=\"panel\"><h2>").append(esc(c.t(b[1]))).append("</h2><pre class=\"command\" style=\"white-space:pre-wrap;overflow-wrap:anywhere\">").append(esc(det.get(b[0]))).append("</pre></section>");
        }
        return sb.toString();
    }

    private static String metrics2(Ctx c, Map<String, Object> t) {
        return "<dl class=\"metrics\"><div><dt>" + esc(c.t("Connect time")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(t.get("connect_time"))) + "</dd></div><div><dt>" + esc(c.t("Wait")) + "</dt><dd>"
                + Fmt.seconds(Analysis.dn(t.get("wait"))) + "</dd></div><div><dt>" + esc(c.t("Service")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(t.get("service"))) + "</dd></div><div><dt>"
                + esc(c.t("Transfer")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(t.get("transfer"))) + "</dd></div><div><dt>" + esc(c.t("Total")) + "</dt><dd>" + Fmt.seconds(Analysis.dn(t.get("total"))) + "</dd></div></dl>";
    }

    @SuppressWarnings("unchecked")
    public static String inspectPage(Ctx c, Map<String, Object> meta, Map<String, String[]> params, Map<String, Object> result, Map<String, Object> inspected) {
        String id = (String) meta.get("id");
        List<Map<String, Object>> conns = (List<Map<String, Object>>) result.get("connections");
        StringBuilder sb = new StringBuilder();
        sb.append(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Inspect traffic"), null}}));
        sb.append("<header class=\"page-head\"><div><h1>").append(esc(c.t("Inspect traffic"))).append("</h1><p class=\"muted\">").append(esc(c.t("Focus on one source, destination or URL in {name}.", "name", meta.get("filename")))).append("</p></div></header>");
        sb.append("<section class=\"panel\"><form id=\"f\" method=\"get\" action=\"").append(c.path()).append("/a/").append(id).append("/inspect\"><div class=\"fields\">");
        field(sb, c.t("Source IP"), "src", params, "100.10.10.101", "srcs");
        field(sb, c.t("Source port"), "src_port", params, "51245", null);
        field(sb, c.t("Destination IP"), "dst", params, "100.10.100.101", "dsts");
        field(sb, c.t("Destination port"), "port", params, "8080", null);
        TreeSet<String> kinds = new TreeSet<>(), srcs = new TreeSet<>(), dsts = new TreeSet<>();
        for (Map<String, Object> k : conns) { kinds.add((String) k.get("kind")); srcs.add((String) k.get("client_ip")); dsts.add((String) k.get("server_ip")); }
        String kind = Inspect.str(params, "kind");
        sb.append("<label>").append(esc(c.t("Connection type"))).append(" <select name=\"kind\"><option value=\"\">").append(esc(c.t("All"))).append("</option>");
        for (String k : kinds) sb.append("<option").append(k.equals(kind) ? " selected" : "").append(">").append(esc(k)).append("</option>");
        sb.append("</select></label>");
        field(sb, c.t("URL contains"), "url", params, "/api/orders", null);
        field(sb, c.t("Larger than (bytes)"), "min_size", params, "", null);
        String sizeOf = Optional.ofNullable(Inspect.str(params, "size_of")).orElse("total");
        sb.append("<label>").append(esc(c.t("Size of"))).append(" <select name=\"size_of\">");
        String[][] sizes = {{"total", "Request and response"}, {"request", "Request"}, {"response", "Response"}, {"packet", "Largest packet"}};
        for (String[] z : sizes) sb.append("<option value=\"").append(z[0]).append("\"").append(z[0].equals(sizeOf) ? " selected" : "").append(">").append(esc(c.t(z[1]))).append("</option>");
        sb.append("</select></label></div>");
        for (String hidden : new String[] {"start", "end"}) if (Inspect.str(params, hidden) != null) sb.append("<input type=\"hidden\" name=\"").append(hidden).append("\" value=\"").append(esc(Inspect.str(params, hidden))).append("\">");
        sb.append("<datalist id=\"srcs\">"); for (String x : srcs) sb.append("<option>").append(esc(x)).append("</option>");
        sb.append("</datalist><datalist id=\"dsts\">"); for (String x : dsts) sb.append("<option>").append(esc(x)).append("</option>");
        sb.append("</datalist><button class=\"primary\">").append(esc(c.t("Inspect"))).append("</button></form>");
        sb.append("<div class=\"filter-row\">");
        List<Map<String, Object>> saved = Records.filters();
        if (!saved.isEmpty()) {
            sb.append("<ul class=\"saved\">");
            for (Map<String, Object> f : saved) {
                StringBuilder qs = new StringBuilder();
                for (String k : Records.FILTER_FIELDS) if (f.get(k) != null && !f.get(k).toString().isEmpty()) qs.append(k).append('=').append(java.net.URLEncoder.encode(f.get(k).toString(), java.nio.charset.StandardCharsets.UTF_8)).append('&');
                sb.append("<li><a href=\"").append(c.path()).append("/a/").append(id).append("/inspect?").append(qs).append("\">").append(esc(f.get("name"))).append("</a><form method=\"post\" action=\"").append(c.path()).append("/filters/").append(f.get("id"))
                  .append("/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><input type=\"hidden\" name=\"back\" value=\"/a/").append(id).append("/inspect\"><button class=\"link danger\" aria-label=\"")
                  .append(esc(c.t("Delete filter {name}", "name", f.get("name")))).append("\">").append(esc(c.t("Delete"))).append("</button></form></li>");
            }
            sb.append("</ul>");
        }
        sb.append("<details class=\"save\"><summary>").append(esc(c.t("Save this filter"))).append("</summary><form method=\"post\" action=\"").append(c.path()).append("/filters\" class=\"inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"")
          .append(c.csrf()).append("\"><input type=\"hidden\" name=\"back\" value=\"/a/").append(id).append("/inspect\">");
        for (String k : Records.FILTER_FIELDS) sb.append("<input type=\"hidden\" name=\"").append(k).append("\" value=\"").append(esc(Optional.ofNullable(Inspect.str(params, k)).orElse(""))).append("\">");
        sb.append("<label>").append(esc(c.t("Name"))).append(" <input name=\"filter_name\" required maxlength=\"80\"></label><button>").append(esc(c.t("Save filter"))).append("</button></form><p class=\"hint\">")
          .append(esc(c.t("Saves the filter as it was last applied."))).append("</p></details></div></section>");
        Map<String, Object> cs = (Map<String, Object>) inspected.get("connections"), rq = (Map<String, Object>) inspected.get("requests");
        if (((Number) cs.get("connections")).intValue() == 0) return sb.append("<p class=\"empty\">").append(esc(c.t("Nothing in this capture matches. Check the addresses, or clear a filter."))).append("</p>").toString();
        if (((Number) rq.get("requests")).intValue() > 0) sb.append("<section class=\"hero\">").append(score(c, rq)).append(metrics(c, rq)).append("</section>");
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Summary"))).append("</h2><dl class=\"facts\">");
        facts(sb, c.t("TCP connections"), cs.get("connections")); facts(sb, c.t("Successful"), cs.get("ok")); facts(sb, c.t("Carrying HTTP"), cs.get("http")); facts(sb, c.t("TCP only"), cs.get("tcp_only"));
        facts(sb, c.t("Average connect"), Fmt.seconds(Analysis.dn(cs.get("avg_connect")))); facts(sb, c.t("Average round trip"), Fmt.seconds(Analysis.dn(cs.get("avg_rtt"))));
        sb.append("</dl></section>");
        List<Map<String, Object>> urls = (List<Map<String, Object>>) inspected.get("urls");
        if (!urls.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("By URL"))).append("</h2><p class=\"hint pad\">").append(esc(c.t("Select a column title to sort by it, and again to turn the order around.")))
              .append("</p><div class=\"table-wrap\"><table data-sortable><thead><tr><th data-sort=\"text\">").append(esc(c.t("Method"))).append("</th><th data-sort=\"text\">URL</th>");
            for (String h : new String[] {"Requests", "Failed", "Average", "95th percentile", "Slowest"}) sb.append("<th class=\"num\" data-sort=\"num\">").append(esc(c.t(h))).append("</th>");
            sb.append("<th data-sort=\"text\">").append(esc(c.t("Status"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> u : urls) {
                sb.append("<tr><td>").append(esc(u.get("method"))).append("</td><td>").append(esc(u.get("url"))).append("</td>");
                for (String k : new String[] {"requests", "failed"}) sb.append("<td class=\"num\" data-value=\"").append(u.get(k)).append("\">").append(u.get(k)).append("</td>");
                for (String k : new String[] {"avg_total", "p95_total", "max_total"}) sb.append("<td class=\"num\" data-value=\"").append(u.get(k) == null ? -1 : u.get(k)).append("\">").append(Fmt.seconds(Analysis.dn(u.get(k)))).append("</td>");
                StringBuilder st = new StringBuilder();
                for (Map<String, Object> x : (List<Map<String, Object>>) u.get("statuses")) st.append(st.length() > 0 ? ", " : "").append(x.get("status") == null ? c.t("none") : x.get("status")).append(" ×").append(x.get("requests"));
                sb.append("<td>").append(esc(st)).append("</td></tr>");
            }
            sb.append("</tbody></table></div></section>");
        }
        List<Map<String, Object>> slow = (List<Map<String, Object>>) inspected.get("slowest");
        if (!slow.isEmpty()) sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Slowest {n} requests", "n", slow.size()))).append("</h2>").append(waterfall(c, slow)).append("</section>");
        return sb.toString();
    }

    private static void field(StringBuilder sb, String label, String name, Map<String, String[]> params, String placeholder, String list) {
        String v = Inspect.str(params, name);
        sb.append("<label>").append(esc(label)).append(" <input name=\"").append(name).append("\"").append(list != null ? " list=\"" + list + "\"" : "").append(" value=\"").append(esc(v == null ? "" : v))
          .append("\" placeholder=\"").append(esc(placeholder)).append("\"></label>");
    }

    @SuppressWarnings("unchecked")
    static String tlsTab(Ctx c, String id, Map<String, Object> tls) {
        List<Map<String, Object>> versions = (List<Map<String, Object>>) tls.get("versions");
        if (versions.isEmpty()) return "<p class=\"empty\">" + esc(c.t("No TLS traffic was found in this capture.")) + "</p>";
        StringBuilder sb = new StringBuilder("<section class=\"panel flush\"><h2>" + esc(c.t("Handshakes")) + "</h2><div class=\"table-wrap\"><table><thead><tr><th>" + esc(c.t("Version")) + "</th><th>" + esc(c.t("Cipher"))
                + "</th><th>ALPN</th><th class=\"num\">" + esc(c.t("Connections")) + "</th><th class=\"num\">" + esc(c.t("Resumed")) + "</th><th class=\"num\">" + esc(c.t("Average handshake")) + "</th></tr></thead><tbody>");
        for (Map<String, Object> v : versions)
            sb.append("<tr><td>").append(esc(v.get("version"))).append("</td><td>").append(esc(v.get("cipher"))).append("</td><td>").append(esc(v.get("alpn"))).append("</td><td class=\"num\">").append(v.get("connections"))
              .append("</td><td class=\"num\">").append(v.get("resumed")).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(v.get("avg_handshake")))).append("</td></tr>");
        sb.append("</tbody></table></div></section>");
        List<Map<String, Object>> problems = (List<Map<String, Object>>) tls.get("problems");
        if (!problems.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("TLS problems"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Client"))).append("</th><th>").append(esc(c.t("Server")))
              .append("</th><th>").append(esc(c.t("Server name"))).append("</th><th>").append(esc(c.t("Problem"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> p : problems)
                sb.append("<tr><td><a href=\"").append(c.path()).append("/a/").append(id).append("/conn/").append(p.get("stream")).append("\">").append(esc(p.get("client"))).append("</a></td><td>").append(esc(p.get("server")))
                  .append("</td><td>").append(esc(p.get("sni") == null ? "–" : p.get("sni"))).append("</td><td>").append(esc(Boolean.TRUE.equals(p.get("tls_no_answer")) ? c.t("No answer to ClientHello") : p.get("tls_alert"))).append("</td></tr>");
            sb.append("</tbody></table></div></section>");
        }
        List<Map<String, Object>> certs = (List<Map<String, Object>>) tls.get("certificates");
        if (!certs.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Certificates seen"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Server name"))).append("</th><th>")
              .append(esc(c.t("Expires"))).append("</th><th class=\"num\">").append(esc(c.t("Connections"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> k : certs) sb.append("<tr><td>").append(esc(k.get("name"))).append("</td><td>").append(esc(k.get("expires"))).append("</td><td class=\"num\">").append(k.get("connections")).append("</td></tr>");
            sb.append("</tbody></table></div><p class=\"hint\">").append(esc(c.t("TLS 1.3 encrypts the certificate, so it is visible only with a key log."))).append("</p></section>");
        }
        return sb.toString();
    }

    // ---- baseline drift and URL targets

    @SuppressWarnings("unchecked")
    public static String driftPanels(Ctx c, Map<String, Object> result, Map<String, Object> baseResult, String baseName, List<Map<String, Object>> targets) {
        StringBuilder sb = new StringBuilder();
        if (baseResult != null) {
            Map<String, Map<String, Object>> before = new HashMap<>();
            for (Map<String, Object> u : (List<Map<String, Object>>) baseResult.get("urls")) before.put(u.get("method") + " " + u.get("url"), u);
            List<Object[]> found = new ArrayList<>();
            for (Map<String, Object> u : (List<Map<String, Object>>) result.get("urls")) {
                Map<String, Object> b = before.get(u.get("method") + " " + u.get("url"));
                double fail = Analysis.d(u.get("failed")), req = Math.max(Analysis.d(u.get("requests")), 1);
                if (b == null) found.add(new Object[] {u, "new", null});
                else if (fail > Analysis.d(b.get("failed")) && fail / req > Analysis.d(b.get("failed")) / Math.max(Analysis.d(b.get("requests")), 1)) found.add(new Object[] {u, "failing", b.get("p95_total")});
                else if (u.get("p95_total") != null && b.get("p95_total") != null && Analysis.d(u.get("p95_total")) > 1.5 * Analysis.d(b.get("p95_total")) && Analysis.d(u.get("p95_total")) - Analysis.d(b.get("p95_total")) >= Analysis.SLOW_S)
                    found.add(new Object[] {u, "slower", b.get("p95_total")});
            }
            if (!found.isEmpty()) {
                sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Different from the baseline ({name})", "name", baseName))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Method")))
                  .append("</th><th>URL</th><th>").append(esc(c.t("Change"))).append("</th><th class=\"num\">").append(esc(c.t("Baseline"))).append("</th><th class=\"num\">").append(esc(c.t("Now"))).append("</th></tr></thead><tbody>");
                for (Object[] f : found) {
                    Map<String, Object> u = (Map<String, Object>) f[0];
                    String why = (String) f[1];
                    sb.append("<tr><td>").append(esc(u.get("method"))).append("</td><td>").append(esc(u.get("url"))).append("</td><td>").append(esc(c.t(why.equals("new") ? "New URL" : why.equals("failing") ? "More failures" : "Slower")))
                      .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(f[2]))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("p95_total")))).append("</td></tr>");
                }
                sb.append("</tbody></table></div></section>");
            }
        }
        List<String> rows = new ArrayList<>();
        Map<String, List<Map<String, Object>>> txnsByUrl = new HashMap<>();
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) txnsByUrl.computeIfAbsent(x.get("method") + " " + x.get("url_template"), k -> new ArrayList<>()).add(x);
        StringBuilder missed = new StringBuilder();
        for (Map<String, Object> g : (List<Map<String, Object>>) result.get("urls")) {
            Map<String, Object> target = null;
            for (Map<String, Object> t : targets) if (Records.matches((String) g.get("url"), (String) t.get("pattern"))) { target = t; break; }
            if (target == null || g.get("p95_total") == null || Analysis.d(g.get("p95_total")) <= Analysis.d(target.get("seconds"))) continue;
            long over = txnsByUrl.getOrDefault(g.get("method") + " " + g.get("url"), List.of()).stream().filter(x -> x.get("total") != null && Analysis.d(x.get("total")) > Analysis.d(((Map<String, Object>) g).get("p95_total")) * 0 + 0).count();
            Map<String, Object> tt = target;
            over = txnsByUrl.getOrDefault(g.get("method") + " " + g.get("url"), List.of()).stream().filter(x -> x.get("total") != null && Analysis.d(x.get("total")) > Analysis.d(tt.get("seconds"))).count();
            missed.append("<tr><td>").append(esc(g.get("method"))).append("</td><td>").append(esc(g.get("url"))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(target.get("seconds")))).append("</td><td class=\"num\">")
                  .append(Fmt.seconds(Analysis.dn(g.get("p95_total")))).append("</td><td class=\"num\">").append(over).append("</td></tr>");
        }
        if (missed.length() > 0)
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Over the URL targets"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Method"))).append("</th><th>URL</th><th class=\"num\">")
              .append(esc(c.t("Target"))).append("</th><th class=\"num\">").append(esc(c.t("95th percentile"))).append("</th><th class=\"num\">").append(esc(c.t("Requests over target"))).append("</th></tr></thead><tbody>").append(missed).append("</tbody></table></div></section>");
        return sb.toString();
    }

    // ---- guide, preferences, activity log, trend, compare

    public static String guidePage(Ctx c, Map<String, String[]> q, int maxMb, int seconds, List<CaptureGuide.Point> points) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Capture guide")) + "</h1><p class=\"muted\">" + esc(c.t("Get a command to take the right capture. Files stay under the {n} MB limit.", "n", maxMb)) + "</p></div></header>");
        sb.append("<section class=\"panel\"><form method=\"get\" action=\"").append(c.path()).append("/capture-guide\"><div class=\"fields\">");
        field(sb, c.t("Server IP"), "server", q, "10.0.0.5", null); field(sb, c.t("TCP port"), "port", q, "8080", null); field(sb, c.t("Client IP"), "client", q, "", null);
        sb.append("<label>").append(esc(c.t("Seconds"))).append(" <input name=\"seconds\" inputmode=\"numeric\" value=\"").append(seconds).append("\"></label>");
        field(sb, c.t("Interface"), "interface", q, "any", null); field(sb, c.t("Namespace"), "namespace", q, "default", null); field(sb, c.t("Pod"), "pod", q, "POD", null);
        field(sb, c.t("Container"), "container", q, "CONTAINER", null); field(sb, c.t("Debug image"), "image", q, "nicolaka/netshoot", null);
        sb.append("</div><button class=\"primary\">").append(esc(c.t("Show commands"))).append("</button></form></section>");
        for (CaptureGuide.Point p : points) {
            sb.append("<section class=\"panel guide\"><h2>").append(esc(p.title())).append("</h2><p>").append(rich(p.text())).append("</p>");
            for (String line : p.lines()) sb.append("<pre class=\"command\">").append(esc(line)).append("</pre>");
            sb.append("<dl class=\"facts two-col\"><div><dt>").append(esc(c.t("What it shows"))).append("</dt><dd>").append(esc(p.shows())).append("</dd></div><div><dt>").append(esc(c.t("What it cannot show")))
              .append("</dt><dd>").append(esc(p.hides())).append("</dd></div></dl></section>");
        }
        return sb.append("<p class=\"hint\">").append(esc(c.t("To measure NetScaler, capture on both sides at the same time and open the two captures in Compare."))).append(" <a href=\"").append(c.path()).append("/compare\">").append(esc(c.t("Compare"))).append("</a></p>").toString();
    }

    private static final java.util.regex.Pattern SENTENCE_END = java.util.regex.Pattern.compile("(?<=[.!?])\\s+(?=[A-ZÇĞİÖŞÜÁÉÍÓÚÑÄ0-9`(])");

    /** The explanation of a result: one line of meaning, what this capture shows and three checks. The rest opens on demand. */
    @SuppressWarnings("unchecked")
    static String guidePanel(Ctx c, Map<String, Object> g) {
        if (g == null) return "";
        Map<String, String> h = (Map<String, String>) g.get("headings");
        String[] parts = SENTENCE_END.split((String) g.get("meaning"), 2);
        List<String> evidence = (List<String>) g.get("evidence"), checks = (List<String>) g.get("checks");
        List<Map<String, String>> sources = (List<Map<String, String>>) g.get("sources");
        String misread = (String) g.get("misread");
        StringBuilder sb = new StringBuilder("<section class=\"panel guide\"><h2>").append(esc(h.get("title"))).append("</h2><div class=\"guide-cols\"><div><h3>").append(esc(h.get("meaning"))).append("</h3><p>").append(esc(parts[0])).append("</p>");
        if (parts.length > 1) sb.append("<details class=\"more\"><summary>").append(esc(c.t("More"))).append("</summary><p>").append(esc(parts[1])).append("</p></details>");
        sb.append("</div>");
        if (!evidence.isEmpty()) {
            sb.append("<div><h3>").append(esc(h.get("evidence"))).append("</h3><ul>");
            for (String line : evidence) sb.append("<li>").append(rich(line)).append("</li>");
            sb.append("</ul></div>");
        }
        sb.append("<div><h3>").append(esc(h.get("checks"))).append("</h3><ul>");
        for (int i = 0; i < Math.min(3, checks.size()); i++) sb.append("<li>").append(rich(checks.get(i))).append("</li>");
        sb.append("</ul>");
        if (checks.size() > 3) {
            sb.append("<details class=\"more\"><summary>").append(esc(c.t("{n} more checks", "n", checks.size() - 3))).append("</summary><ul>");
            for (String line : checks.subList(3, checks.size())) sb.append("<li>").append(rich(line)).append("</li>");
            sb.append("</ul></details>");
        }
        sb.append("</div></div><details class=\"more notes\"><summary>").append(esc((misread != null ? h.get("misread") + " · " : "") + h.get("sources"))).append("</summary>");
        if (misread != null) sb.append("<p>").append(rich(misread)).append("</p>");
        sb.append("<ul class=\"sources\">");
        for (Map<String, String> s : sources)
            sb.append("<li><a href=\"").append(esc(s.get("url"))).append("\" rel=\"noreferrer noopener\">").append(esc(s.get("title"))).append("</a>: ").append(esc(s.get("where"))).append("</li>");
        return sb.append("</ul><p class=\"hint\">").append(esc(h.get("origin"))).append("</p></details></section>").toString();
    }

    static String rich(String line) {
        StringBuilder sb = new StringBuilder();
        String[] parts = line.split("`", -1);
        for (int i = 0; i < parts.length; i++) sb.append(i % 2 == 1 ? "<code>" + esc(parts[i]) + "</code>" : esc(parts[i]));
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String preferencesPage(Ctx c, Map<String, Object> limits, String targetsText, List<Map<String, Object>> tokens, String newToken, String error) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Preferences")) + "</h1><p class=\"muted\">" + esc(c.t("These apply to everyone who uses this install.")) + " <a href=\"" + c.path() + "/audit\">" + esc(c.t("Activity log")) + "</a></p></div></header>");
        if (error != null) sb.append("<p class=\"error\" role=\"alert\">").append(esc(error)).append("</p>");
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Limits"))).append("</h2><form method=\"post\" action=\"").append(c.path()).append("/preferences\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf())
          .append("\"><div class=\"fields\"><label>").append(esc(c.t("Slow request limit (seconds)"))).append(" <input id=\"slow\" name=\"slow\" inputmode=\"decimal\" value=\"").append(limits.get("slow_s")).append("\"></label><label class=\"wide\">")
          .append(esc(c.t("URL targets"))).append(" <textarea id=\"targets\" name=\"targets\" rows=\"5\" spellcheck=\"false\" placeholder=\"/api/orders/* 0.5\">").append(esc(targetsText)).append("</textarea></label></div><p class=\"hint\">")
          .append(esc(c.t("One URL pattern and its limit in seconds per line. The slow limit applies to captures you analyze from now on. URL targets apply to every capture."))).append("</p><button class=\"primary\">").append(esc(c.t("Save limits"))).append("</button></form></section>");
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Password"))).append("</h2><a class=\"button\" href=\"").append(c.path()).append("/password\">").append(esc(c.t("Change the password"))).append("</a></section>");
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("API tokens"))).append("</h2>");
        if (newToken != null) sb.append("<p class=\"warn\">").append(esc(c.t("Copy this token now. It is not shown again."))).append("</p><pre class=\"command\">").append(esc(newToken)).append("</pre>");
        if (!tokens.isEmpty()) {
            sb.append("<table><thead><tr><th>").append(esc(c.t("Name"))).append("</th><th>").append(esc(c.t("Created"))).append("</th><th></th></tr></thead><tbody>");
            for (Map<String, Object> t : tokens)
                sb.append("<tr><td>").append(esc(t.get("name") == null || t.get("name").toString().isEmpty() ? t.get("id") : t.get("name"))).append("</td><td>").append(Fmt.when(Analysis.dn(t.get("created")))).append("</td><td class=\"num\"><form method=\"post\" action=\"")
                  .append(c.path()).append("/tokens/").append(t.get("id")).append("/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><button class=\"link danger\">").append(esc(c.t("Revoke"))).append("</button></form></td></tr>");
            sb.append("</tbody></table>");
        }
        sb.append("<form method=\"post\" action=\"").append(c.path()).append("/tokens\" class=\"inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><label>").append(esc(c.t("Name")))
          .append(" <input id=\"tokenName\" name=\"name\" required maxlength=\"80\"></label><button>").append(esc(c.t("Create token"))).append("</button></form></section>");
        return sb.toString();
    }

    public static String auditPage(Ctx c, List<Map<String, Object>> rows, String event) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Activity log")) + "</h1><p class=\"muted\">" + esc(c.t("The login is shared, so this shows events, addresses and times, not people.")) + "</p></div></header>");
        sb.append("<section class=\"panel\"><form method=\"get\" action=\"").append(c.path()).append("/audit\" class=\"inline\"><label>").append(esc(c.t("Event"))).append(" <select id=\"event\" name=\"event\" data-submit><option value=\"\">").append(esc(c.t("All"))).append("</option>");
        for (String e : new String[] {"upload", "delete", "export", "notes", "baseline", "thresholds", "token_created", "token_revoked", "login_failed"})
            sb.append("<option").append(e.equals(event) ? " selected" : "").append(">").append(e).append("</option>");
        sb.append("</select></label></form></section>");
        if (rows.isEmpty()) return sb.append("<p class=\"empty\">").append(esc(c.t("No events yet."))).append("</p>").toString();
        sb.append("<section class=\"panel flush\"><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Time"))).append("</th><th>").append(esc(c.t("Event"))).append("</th><th>").append(esc(c.t("Address"))).append("</th><th>").append(esc(c.t("Details"))).append("</th></tr></thead><tbody>");
        for (Map<String, Object> r : rows) sb.append("<tr><td>").append(Fmt.when(Analysis.dn(r.get("time")))).append("</td><td>").append(esc(r.get("event"))).append("</td><td>").append(esc(r.get("client"))).append("</td><td>").append(esc(r.get("detail"))).append("</td></tr>");
        return sb.append("</tbody></table></div></section>").toString();
    }

    @SuppressWarnings("unchecked")
    public static String trendPage(Ctx c, String url, List<String> names, List<Object[]> rows) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Trend")) + "</h1><p class=\"muted\">" + esc(c.t("Follow one URL across your saved analyses.")) + "</p></div></header>");
        sb.append("<section class=\"panel\"><form method=\"get\" action=\"").append(c.path()).append("/trend\" class=\"inline\"><label>URL <input id=\"url\" name=\"url\" list=\"urls\" value=\"").append(esc(url)).append("\" placeholder=\"/api/orders/{id}\"></label><datalist id=\"urls\">");
        for (String n : names) sb.append("<option>").append(esc(n)).append("</option>");
        sb.append("</datalist><button class=\"primary\">").append(esc(c.t("Show trend"))).append("</button></form></section>");
        if (!rows.isEmpty()) {
            sb.append("<section class=\"panel flush\"><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Captured"))).append("</th><th>").append(esc(c.t("File"))).append("</th><th class=\"num\">").append(esc(c.t("Requests")))
              .append("</th><th class=\"num\">").append(esc(c.t("Failed"))).append("</th><th class=\"num\">").append(esc(c.t("Median"))).append("</th><th class=\"num\">").append(esc(c.t("95th percentile"))).append("</th></tr></thead><tbody>");
            for (Object[] r : rows) {
                Map<String, Object> meta = (Map<String, Object>) r[0], g = (Map<String, Object>) r[1];
                sb.append("<tr><td>").append(Fmt.when(Analysis.dn(meta.get("capture_start") != null ? meta.get("capture_start") : meta.get("created")))).append("</td><td><a href=\"").append(c.path()).append("/a/").append(meta.get("id")).append("\">")
                  .append(esc(meta.get("filename"))).append("</a></td><td class=\"num\">").append(g.get("requests")).append("</td><td class=\"num\">").append(g.get("failed")).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(g.get("p50_total"))))
                  .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(g.get("p95_total")))).append("</td></tr>");
            }
            sb.append("</tbody></table></div></section>");
        } else if (!url.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No saved analysis has this URL."))).append("</p>");
        return sb.toString();
    }

    private static String duel(Ctx c, List<Map<String, Object>> rows) {
        StringBuilder sb = new StringBuilder("<ul class=\"duel\">");
        for (Map<String, Object> r : rows) {
            boolean time = !Boolean.FALSE.equals(r.get("is_time"));
            double a = Analysis.d(r.get("a")), b = Analysis.d(r.get("b")), top = Math.max(a, b);
            Double delta = Analysis.dn(r.get("delta")), percent = Analysis.dn(r.get("percent"));
            String change = delta == null ? "–" : time ? (delta > 0 ? "+" : "") + String.format(Locale.ROOT, "%.1f ms", delta * 1000) : (delta > 0 ? "+" : "") + (delta == Math.rint(delta) ? String.valueOf((long) (double) delta) : String.valueOf(delta));
            if (percent != null) change += " (" + String.format(Locale.ROOT, "%+.0f%%", percent) + ")";
            sb.append("<li><div class=\"duel-row\"><b>").append(r.get("a") == null ? "–" : time ? Fmt.seconds(a) : String.valueOf((long) a)).append("</b><span class=\"duel-name\">").append(esc(r.get("label")))
              .append(" <small class=\"").append(delta != null && delta > 0 ? "up" : delta != null && delta < 0 ? "down" : "").append("\">").append(esc(change)).append("</small></span><b>").append(r.get("b") == null ? "–" : time ? Fmt.seconds(b) : String.valueOf((long) b))
              .append("</b></div><div class=\"duel-bars\" aria-hidden=\"true\"><div><span style=\"width:").append(String.format(Locale.ROOT, "%.1f", top > 0 ? a / top * 100 : 0)).append("%\"></span></div><div><span style=\"width:")
              .append(String.format(Locale.ROOT, "%.1f", top > 0 ? b / top * 100 : 0)).append("%\"></span></div></div></li>");
        }
        return sb.append("</ul>").toString();
    }

    @SuppressWarnings("unchecked")
    public static String comparePage(Ctx c, List<Map<String, Object>> analyses, Map<String, String[]> q, Map<String, Object> metaA, Map<String, Object> metaB, Map<String, Object> result, Map<String, Object> points) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Compare captures")) + "</h1><p class=\"muted\">" + esc(c.t("See what changed between two captures, or how the same traffic looks at two points.")) + "</p></div></header>");
        if (analyses.size() < 2) return sb.append("<p class=\"empty\">").append(esc(c.t("Analyze at least two captures first. They will appear here."))).append(" <a href=\"").append(c.path()).append("/\">").append(esc(c.t("Go to your captures"))).append("</a></p>").toString();
        sb.append("<section class=\"panel\"><form method=\"get\" action=\"").append(c.path()).append("/compare\"><div class=\"compare-pick\">");
        for (String side : new String[] {"a", "b"}) {
            sb.append("<fieldset><legend>").append(esc(c.t(side.equals("a") ? "Capture A" : "Capture B"))).append("</legend><label>").append(esc(c.t("Capture"))).append(" <select name=\"").append(side).append("\" required><option value=\"\">")
              .append(esc(c.t("Choose a capture"))).append("</option>");
            String chosen = Inspect.str(q, side);
            for (Map<String, Object> m : analyses)
                sb.append("<option value=\"").append(m.get("id")).append("\"").append(m.get("id").equals(chosen) ? " selected" : "").append(">").append(esc(m.get("filename"))).append(" (").append(Fmt.when(Analysis.dn(m.get("created")))).append(")</option>");
            sb.append("</select></label><div class=\"fields\">");
            field(sb, c.t("Source IP"), "src_" + side, q, "", null); field(sb, c.t("Destination IP"), "dst_" + side, q, "", null); field(sb, c.t("Destination port"), "port_" + side, q, "", null); field(sb, c.t("URL contains"), "url_" + side, q, "", null);
            sb.append("</div></fieldset>");
        }
        String mode = Optional.ofNullable(Inspect.str(q, "mode")).orElse("captures");
        sb.append("</div><p class=\"hint\">").append(esc(c.t("Filters left empty on B use the values of A. Fill B when addresses differ, for example before and after NAT."))).append("</p>")
          .append("<label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"captures\"").append(!mode.equals("points") ? " checked" : "").append("> ").append(esc(c.t("Before and after: compare the two as a whole"))).append("</label>")
          .append("<label class=\"check\"><input type=\"radio\" name=\"mode\" value=\"points\"").append(mode.equals("points") ? " checked" : "").append("> ").append(esc(c.t("Same traffic at two points: match each request. A is nearer the client"))).append("</label>")
          .append("<button class=\"primary\">").append(esc(c.t("Compare"))).append("</button></form></section>");
        if (result != null) {
            for (String n : (List<String>) result.get("notes")) sb.append("<p class=\"warn\">").append(esc(n)).append("</p>");
            Map<String, Object> p95 = ((List<Map<String, Object>>) result.get("summary")).stream().filter(r -> r.get("key").equals("p95_total")).findFirst().orElse(Map.of());
            sb.append("<header class=\"hero\"><div class=\"score ends\"><div class=\"score-side pick-a\"><small>").append(esc(c.t("Capture A"))).append("</small><b>").append(esc(metaA.get("filename"))).append("</b></div><div class=\"score-mid\"><strong><span>")
              .append(Fmt.seconds(Analysis.dn(p95.get("a")))).append("</span><i>–</i><span>").append(Fmt.seconds(Analysis.dn(p95.get("b")))).append("</span></strong><small>").append(esc(c.t("95th percentile"))).append("</small></div><div class=\"score-side pick-b\"><small>")
              .append(esc(c.t("Capture B"))).append("</small><b>").append(esc(metaB.get("filename"))).append("</b></div></div></header>");
            sb.append("<div class=\"columns even\"><section class=\"panel\"><h2>").append(esc(c.t("Summary"))).append("</h2>").append(duel(c, (List<Map<String, Object>>) result.get("summary"))).append("</section><section class=\"panel\"><h2>")
              .append(esc(c.t("Average time per phase"))).append("</h2>").append(duel(c, (List<Map<String, Object>>) result.get("phases"))).append("</section></div>");
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("By URL, largest change first"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Method"))).append("</th><th>URL</th>");
            for (String h : new String[] {"Requests", "Failed", "Average"}) for (String sd : new String[] {"A", "B"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append(" ").append(sd).append("</th>");
            sb.append("<th class=\"num\">").append(esc(c.t("Change"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> u : (List<Map<String, Object>>) result.get("urls")) {
                Double d = Analysis.dn(u.get("delta"));
                sb.append("<tr><td>").append(esc(u.get("method"))).append("</td><td>").append(esc(u.get("url")));
                if (u.get("only_in") != null) sb.append(" <span class=\"hint\">").append(esc(c.t("only in {side}", "side", u.get("only_in")))).append("</span>");
                else if (Boolean.TRUE.equals(u.get("few"))) sb.append(" <span class=\"hint\">").append(esc(c.t("few samples"))).append("</span>");
                sb.append("</td>");
                for (String k : new String[] {"requests_a", "requests_b", "failed_a", "failed_b"}) sb.append("<td class=\"num\">").append(u.get(k) == null ? 0 : u.get(k)).append("</td>");
                sb.append("<td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("avg_a")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("avg_b")))).append("</td><td class=\"num ")
                  .append(d != null && d > 0 ? "up" : d != null && d < 0 ? "down" : "").append("\">").append(d == null ? "–" : (d > 0 ? "+" : "") + String.format(Locale.ROOT, "%.1f ms", d * 1000)).append("</td></tr>");
            }
            sb.append("</tbody></table></div></section>");
            Pages.Ctx ca = c.withId((String) metaA.get("id")), cb = c.withId((String) metaB.get("id"));
            List<Map<String, Object>> sa = (List<Map<String, Object>>) result.get("slowest_a"), sbb = (List<Map<String, Object>>) result.get("slowest_b");
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Slowest in A"))).append("</h2>").append(waterfall(ca, sa.subList(0, Math.min(5, sa.size())))).append("</section>");
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Slowest in B"))).append("</h2>").append(waterfall(cb, sbb.subList(0, Math.min(5, sbb.size())))).append("</section>");
        }
        if (points != null) {
            if (Boolean.TRUE.equals(points.get("reversed"))) sb.append("<p class=\"warn\">").append(esc(c.t("B takes longer than A, so the captures may be swapped. A must be the point nearer the client."))).append("</p>");
            String conf = (String) points.get("confidence");
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("What the path between the points added"))).append("</h2><dl class=\"metrics\"><div><dt>").append(esc(c.t("Added, median"))).append("</dt><dd>").append(Fmt.seconds(Analysis.dn(points.get("added"))))
              .append("</dd></div><div><dt>").append(esc(c.t("Added, 95th percentile"))).append("</dt><dd>").append(Fmt.seconds(Analysis.dn(points.get("added_p95")))).append("</dd></div><div><dt>").append(esc(c.t("Service seen at B"))).append("</dt><dd>")
              .append(Fmt.seconds(Analysis.dn(points.get("service")))).append("</dd></div><div><dt>").append(esc(c.t("Requests matched"))).append("</dt><dd>").append(esc(c.t("{n}%", "n", String.format(Locale.ROOT, "%.0f", Analysis.d(points.get("match_rate")) * 100))))
              .append("</dd></div><div class=\"trust-").append(conf).append("\"><dt>").append(esc(c.t("Match confidence"))).append("</dt><dd>").append(esc(c.t(Character.toUpperCase(conf.charAt(0)) + conf.substring(1)))).append("</dd></div></dl><p class=\"hint\">")
              .append(esc(c.t("The added time covers NetScaler and the network between the two points. Captures cannot separate those two. It does not depend on the capture clocks."))).append("</p><p>")
              .append(esc(c.t("{exact} matched by request ID, {likely} by URL and time. {a} in A and {b} in B have no match.", "exact", points.get("exact"), "likely", points.get("likely"), "a", points.get("unmatched_a"), "b", points.get("unmatched_b")))).append("</p>");
            if (((Number) points.get("exact")).intValue() == 0) sb.append("<p class=\"warn\">").append(esc(c.t("No shared request IDs, so requests are matched by URL and time. On busy URLs some pairs can be wrong. {n} matches had more than one candidate.", "n", points.get("unclear")))).append("</p>");
            sb.append("</section>");
            List<Map<String, Object>> urls = (List<Map<String, Object>>) points.get("urls");
            if (!urls.isEmpty()) {
                sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("By URL, largest added time first"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Method"))).append("</th><th>URL</th>");
                for (String h : new String[] {"Requests", "Total at A", "Added, median", "Added, 95th percentile", "Service seen at B"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
                sb.append("</tr></thead><tbody>");
                for (Map<String, Object> u : urls)
                    sb.append("<tr><td>").append(esc(u.get("method"))).append("</td><td>").append(esc(u.get("url"))).append("</td><td class=\"num\">").append(u.get("requests")).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("total"))))
                      .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("added")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("added_p95")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("service")))).append("</td></tr>");
                sb.append("</tbody></table></div></section>");
            }
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Same requests at two points"))).append("</h2><p class=\"hint\">")
              .append(esc(c.t("The split into two directions is an estimate. It takes the fastest trip each way as equal to remove the clock difference of {ms} ms.", "ms", String.format(Locale.ROOT, "%.1f", Analysis.d(points.get("clock_skew")) * 1000)))).append("</p>");
            List<Map<String, Object>> rows = (List<Map<String, Object>>) points.get("rows");
            if (!rows.isEmpty()) {
                sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Match"))).append("</th><th>").append(esc(c.t("Request"))).append("</th>");
                for (String h : new String[] {"Status", "Total at A", "Total at B", "Added between points", "Delay toward B", "Delay back"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
                sb.append("</tr></thead><tbody>");
                for (Map<String, Object> r : rows) {
                    String uri = String.valueOf(r.get("uri"));
                    sb.append("<tr><td>").append(esc(c.t("exact".equals(r.get("match")) ? "Exact" : "Likely"))).append("</td><td><a href=\"").append(c.path()).append("/a/").append(metaA.get("id")).append("/txn/").append(r.get("id_a")).append("\">")
                      .append(esc(r.get("method") + " " + (uri.length() > 60 ? uri.substring(0, 59) + "…" : uri))).append("</a></td><td class=\"num\">").append(r.get("status") == null ? "–" : r.get("status")).append("</td><td class=\"num\">")
                      .append(Fmt.seconds(Analysis.dn(r.get("total_a")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(r.get("total_b")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(r.get("added"))))
                      .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(r.get("forward")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(r.get("back")))).append("</td></tr>");
                }
                sb.append("</tbody></table></div>");
            }
            sb.append("</section>");
        }
        return sb.toString();
    }

    static String statsTab(Ctx c, String id, List<Map<String, Object>> load, boolean kept, String flt, List<Map<String, Object>> seqs) {
        StringBuilder sb = new StringBuilder();
        if (kept) {
            sb.append("<div id=\"stats-overview\" data-load=\"").append(c.path()).append("/a/").append(id).append("/stats/overview\"><p class=\"empty\">").append(esc(c.t("Reading the packets again. A large capture can take a few minutes the first time."))).append("</p></div>");
            sb.append("<div id=\"stats-services\" data-load=\"").append(c.path()).append("/a/").append(id).append("/stats/services\"></div>");
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("IO graph"))).append("</h2><form class=\"inline\" method=\"get\" action=\"").append(c.path()).append("/a/").append(id).append("\"><input type=\"hidden\" name=\"tab\" value=\"stats\"><label class=\"wide\">")
              .append(esc(c.t("Wireshark display filter"))).append(" <input name=\"filter\" spellcheck=\"false\" value=\"").append(esc(flt)).append("\" placeholder=\"tcp.analysis.retransmission\"></label><button>").append(esc(c.t("Draw"))).append("</button></form>")
              .append("<div class=\"chart tall\" data-chart=\"io\" data-src=\"").append(c.path()).append("/api/a/").append(id).append("/io?filter=").append(java.net.URLEncoder.encode(flt, java.nio.charset.StandardCharsets.UTF_8)).append("\" data-name=\"io-graph\"></div></section>");
        } else sb.append("<p class=\"empty\">").append(esc(c.t("The original capture was not kept, so packets cannot be read again."))).append("</p>");
        sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("HTTP load distribution"))).append("</h2>");
        if (load.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No HTTP requests in this capture."))).append("</p>");
        else {
            sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Server"))).append("</th><th>").append(esc(c.t("Host"))).append("</th><th class=\"num\">").append(esc(c.t("Requests"))).append("</th><th class=\"num\">")
              .append(esc(c.t("Responses"))).append("</th><th class=\"num\">").append(esc(c.t("Share"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> s : load)
                sb.append("<tr><td>").append(esc(s.get("server"))).append("</td><td>").append(esc(s.get("host") == null ? "–" : s.get("host"))).append("</td><td class=\"num\">").append(s.get("requests")).append("</td><td class=\"num\">").append(s.get("responses"))
                  .append("</td><td class=\"num\">").append(String.format(Locale.ROOT, "%.1f", Analysis.d(s.get("share")) * 100)).append("%</td></tr>");
            sb.append("</tbody></table></div>");
        }
        sb.append("</section>").append(sequencesPanel(c, seqs));
        if (kept) {
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Flow graph"))).append("</h2><p class=\"muted\">").append(esc(c.t("Packets between hosts on a time axis, as in Wireshark's Flow Graph."))).append("</p><form method=\"get\" action=\"")
              .append(c.path()).append("/a/").append(id).append("/flow\" class=\"inline\"><label class=\"wide\">").append(esc(c.t("Wireshark display filter"))).append(" <input name=\"filter\" spellcheck=\"false\" placeholder=\"dns or icmp\"></label><button>")
              .append(esc(c.t("Show flow graph"))).append("</button></form></section><section class=\"panel\"><h2>").append(esc(c.t("Export objects"))).append("</h2><p class=\"muted\">")
              .append(esc(c.t("Files carried over HTTP, SMB, TFTP, FTP, e-mail or DICOM, as Wireshark's Export Objects finds them."))).append("</p><a class=\"button\" href=\"").append(c.path()).append("/a/").append(id).append("/objects\">")
              .append(esc(c.t("Find files in this capture"))).append("</a></section>");
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String statsOverview(Ctx c, List<Map<String, Object>> hierarchy, Map<String, Object> o) {
        StringBuilder sb = new StringBuilder("<section class=\"panel flush\"><h2>" + esc(c.t("Protocol hierarchy")) + "</h2><div class=\"table-wrap\"><table><thead><tr><th>" + esc(c.t("Protocol")) + "</th><th class=\"num\">" + esc(c.t("Packets"))
                + "</th><th class=\"num\">%</th><th class=\"num\">" + esc(c.t("Bytes")) + "</th><th class=\"num\">%</th></tr></thead><tbody>");
        for (Map<String, Object> p : hierarchy)
            sb.append("<tr><td style=\"padding-left: ").append(12 + ((Number) p.get("depth")).intValue() * 16).append("px\">").append(esc(p.get("protocol"))).append("</td><td class=\"num\">").append(p.get("packets")).append("</td><td class=\"num\">")
              .append(String.format(Locale.ROOT, "%.1f", Analysis.d(p.get("share")) * 100)).append("</td><td class=\"num\">").append(Fmt.size((Number) p.get("bytes"))).append("</td><td class=\"num\">").append(String.format(Locale.ROOT, "%.1f", Analysis.d(p.get("byte_share")) * 100)).append("</td></tr>");
        sb.append("</tbody></table></div></section>");
        double total = Analysis.d(o.get("packets"));
        sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Packet lengths"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Bytes per packet"))).append("</th><th class=\"num\">").append(esc(c.t("Packets")))
          .append("</th><th class=\"num\">%</th><th class=\"num\">").append(esc(c.t("Bytes"))).append("</th></tr></thead><tbody>");
        for (Map<String, Object> s : (List<Map<String, Object>>) o.get("sizes"))
            sb.append("<tr><td>").append(s.get("bin")).append("</td><td class=\"num\">").append(s.get("packets")).append("</td><td class=\"num\">").append(String.format(Locale.ROOT, "%.1f", total > 0 ? Analysis.d(s.get("packets")) / total * 100 : 0))
              .append("</td><td class=\"num\">").append(Fmt.size((Number) s.get("bytes"))).append("</td></tr>");
        sb.append("</tbody></table></div></section>");
        List<Map<String, Object>> udp = (List<Map<String, Object>>) o.get("udp");
        sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("UDP conversations"))).append("</h2>");
        if (udp.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No UDP traffic in this capture."))).append("</p>");
        else {
            sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Address A"))).append("</th><th>").append(esc(c.t("Address B"))).append("</th><th class=\"num\">").append(esc(c.t("Packets"))).append("</th><th class=\"num\">")
              .append(esc(c.t("Bytes"))).append("</th><th class=\"num\">A → B</th><th class=\"num\">B → A</th><th class=\"num\">").append(esc(c.t("Duration"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> u : udp)
                sb.append("<tr><td>").append(esc(u.get("a"))).append("</td><td>").append(esc(u.get("b"))).append("</td><td class=\"num\">").append(u.get("frames")).append("</td><td class=\"num\">").append(Fmt.size((Number) u.get("bytes"))).append("</td><td class=\"num\">")
                  .append(Fmt.size((Number) u.get("a_to_b"))).append("</td><td class=\"num\">").append(Fmt.size((Number) u.get("b_to_a"))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("duration")))).append("</td></tr>");
            sb.append("</tbody></table></div>");
        }
        sb.append("</section><section class=\"panel flush\"><h2>").append(esc(c.t("IP endpoints"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Address"))).append("</th>").append(Boolean.TRUE.equals(o.get("geoip")) ? "<th>" + esc(c.t("Country")) + "</th><th>" + esc(c.t("AS number")) + "</th>" : "").append("<th class=\"num\">").append(esc(c.t("Packets")))
          .append("</th><th class=\"num\">").append(esc(c.t("Bytes"))).append("</th><th class=\"num\">").append(esc(c.t("Sent"))).append("</th><th class=\"num\">").append(esc(c.t("Received"))).append("</th></tr></thead><tbody>");
        for (Map<String, Object> e : (List<Map<String, Object>>) o.get("ips"))
            sb.append("<tr><td>").append(esc(e.get("address"))).append("</td>").append(Boolean.TRUE.equals(o.get("geoip")) ? "<td>" + esc(e.get("country") == null ? "–" : e.get("country")) + "</td><td>" + esc(e.get("asn") == null ? "–" : e.get("asn")) + "</td>" : "").append("<td class=\"num\">").append(e.get("frames")).append("</td><td class=\"num\">").append(Fmt.size((Number) e.get("bytes"))).append("</td><td class=\"num\">")
              .append(Fmt.size((Number) e.get("sent"))).append("</td><td class=\"num\">").append(Fmt.size((Number) e.get("received"))).append("</td></tr>");
        return sb.append("</tbody></table></div></section>").toString();
    }

    // ---- follow, flow graph, objects

    @SuppressWarnings("unchecked")
    public static String followPage(Ctx c, Map<String, Object> meta, Map<String, Object> conn, String mode, Map<String, Object> follow, List<Map<String, Object>> exchanges, boolean hasRequests) {
        String id = (String) meta.get("id");
        boolean http = mode.equals("http");
        String title = c.t(http ? "Follow HTTP stream" : "Follow TCP stream");
        StringBuilder sb = new StringBuilder(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Connections"), c.path() + "/a/" + id + "?tab=connections"},
                {c.t("Connection {n}", "n", conn.get("stream")), c.path() + "/a/" + id + "/conn/" + conn.get("stream")}, {title, null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(title)).append("</h1><p class=\"muted\">")
          .append(esc(http ? c.t("Each request and its response in order, with headers and the start of each body. Known secret headers and fields are masked.")
                  : c.t("What each side sent, in order. The client's bytes are on the left, the server's on the right. Known secret headers and fields are masked."))).append("</p></div><div class=\"actions\"><p class=\"switch\">")
          .append("<a href=\"?mode=ascii\"").append(mode.equals("ascii") ? " aria-current=\"true\"" : "").append(">").append(esc(c.t("Text"))).append("</a><a href=\"?mode=hex\"").append(mode.equals("hex") ? " aria-current=\"true\"" : "").append(">Hex</a>");
        if (hasRequests) sb.append("<a href=\"?mode=http\"").append(http ? " aria-current=\"true\"" : "").append(">HTTP</a>");
        sb.append("</p></div></div></header><section class=\"panel follow\">");
        if (http) {
            if (exchanges.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No HTTP requests on this connection. Without a key, HTTPS shows only as TLS."))).append("</p>");
            int n = 0;
            for (Map<String, Object> x : exchanges) {
                n++;
                sb.append("<p class=\"hint\">#").append(n).append(" · ").append(Fmt.clock(Analysis.d(x.get("start")))).append(x.get("h2_stream") != null ? " · HTTP/2 " + esc(c.t("stream")) + " " + x.get("h2_stream") : "").append(" · ")
                  .append(Fmt.seconds(Analysis.dn(x.get("total")))).append(" · <a href=\"").append(c.path()).append("/a/").append(id).append("/txn/").append(x.get("id")).append("\">").append(esc(c.t("Request details"))).append("</a></p>")
                  .append("<pre class=\"side-0\">").append(esc(x.get("request"))).append("</pre>");
                if (x.get("response") != null) sb.append("<pre class=\"side-1\">").append(esc(x.get("response"))).append("</pre>");
                else sb.append("<p class=\"hint\">").append(esc(c.t("No response was seen."))).append("</p>");
            }
            sb.append("<p class=\"hint\">").append(esc(c.t("Bodies show their first 2,000 characters, as the analysis keeps them."))).append("</p>");
        } else {
            List<Map<String, Object>> chunks = (List<Map<String, Object>>) follow.get("chunks");
            if (chunks.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("This connection carried no data."))).append("</p>");
            for (Map<String, Object> k : chunks) sb.append("<pre class=\"side-").append(k.get("side")).append("\">").append(esc(k.get("text"))).append("</pre>");
            if (!chunks.isEmpty() && Boolean.TRUE.equals(chunks.get(chunks.size() - 1).get("cut"))) sb.append("<p class=\"hint\">").append(esc(c.t("Only the first 2 MB are shown. Download the connection as PCAP to see all of it."))).append("</p>");
        }
        return sb.append("</section>").toString();
    }

    @SuppressWarnings("unchecked")
    static String flowSvg(Ctx c, Map<String, Object> f) {
        List<String> hosts = (List<String>) f.get("hosts");
        List<Map<String, Object>> rows = (List<Map<String, Object>>) f.get("rows");
        int w = 170, left = 120, row = 26, width = left + w * hosts.size();
        int height = 40 + row * rows.size();
        StringBuilder sb = new StringBuilder("<div class=\"flow-wrap\"><svg class=\"flow\" viewBox=\"0 0 " + (width + 40) + " " + height + "\" width=\"" + (width + 40) + "\" role=\"img\" aria-label=\"" + esc(c.t("Flow graph")) + "\">");
        for (int i = 0; i < hosts.size(); i++) {
            double x = left + w * i + w / 2.0;
            sb.append("<text x=\"").append(x).append("\" y=\"16\" text-anchor=\"middle\" class=\"host\">").append(esc(hosts.get(i))).append("</text><line x1=\"").append(x).append("\" y1=\"24\" x2=\"").append(x).append("\" y2=\"")
              .append(32 + row * rows.size()).append("\" class=\"life\"/>");
        }
        int k = 0;
        for (Map<String, Object> r : rows) {
            int y = 40 + row * k++;
            double x1 = left + w * hosts.indexOf((String) r.get("src")) + w / 2.0, x2 = left + w * hosts.indexOf((String) r.get("dst")) + w / 2.0;
            String label = r.get("protocol") + " " + r.get("info");
            sb.append("<text x=\"4\" y=\"").append(y + 4).append("\" class=\"time\">").append(String.format(Locale.ROOT, "%.6f", Analysis.d(r.get("t")))).append("</text><line x1=\"").append(x1).append("\" y1=\"").append(y).append("\" x2=\"").append(x2)
              .append("\" y2=\"").append(y).append("\" class=\"msg\" marker-end=\"url(#arrow)\"/><text x=\"").append((x1 + x2) / 2).append("\" y=\"").append(y - 4).append("\" text-anchor=\"middle\" class=\"info\"><title>")
              .append(r.get("frame")).append(": ").append(esc(label)).append("</title>").append(esc(label.length() > 44 ? label.substring(0, 43) + "…" : label)).append("</text>");
        }
        sb.append("<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"10\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\"><path d=\"M0,0 L10,5 L0,10 z\" class=\"head\"/></marker></defs></svg></div>");
        if (Boolean.TRUE.equals(f.get("cut"))) sb.append("<p class=\"hint\">").append(esc(c.t("Only the first {n} packets are shown. Narrow the filter to see others.", "n", rows.size()))).append("</p>");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String flowPage(Ctx c, Map<String, Object> meta, Map<String, Object> f, String flt, Integer stream) {
        String id = (String) meta.get("id");
        StringBuilder sb = new StringBuilder(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Statistics"), c.path() + "/a/" + id + "?tab=stats"}, {c.t("Flow graph"), null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(c.t("Flow graph"))).append("</h1><p class=\"muted\">")
          .append(esc(stream != null ? c.t("Connection {n}", "n", stream) : f.get("filter") != null ? f.get("filter") : c.t("All packets"))).append("</p></div></div></header><section class=\"panel\"><form method=\"get\" class=\"inline\"><label class=\"wide\">")
          .append(esc(c.t("Wireshark display filter"))).append(" <input name=\"filter\" value=\"").append(esc(flt)).append("\" spellcheck=\"false\" placeholder=\"dns or icmp\"></label><button>").append(esc(c.t("Show flow graph"))).append("</button></form>");
        if (((List<?>) f.get("rows")).isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No packets match."))).append("</p>"); else sb.append(flowSvg(c, f));
        return sb.append("</section>").toString();
    }

    public static String objectsPage(Ctx c, Map<String, Object> meta, List<Map<String, Object>> objects) {
        String id = (String) meta.get("id");
        StringBuilder sb = new StringBuilder(crumbs(c, new String[][] {{c.t("Captures"), c.path() + "/"}, {(String) meta.get("filename"), c.path() + "/a/" + id}, {c.t("Statistics"), c.path() + "/a/" + id + "?tab=stats"}, {c.t("Export objects"), null}}));
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(c.t("Export objects"))).append("</h1><p class=\"muted\">")
          .append(esc(c.t("Files found in the capture. They are raw content from the traffic and are not masked, so treat them as sensitive."))).append("</p></div></div></header><section class=\"panel flush\">");
        if (objects.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No files were found in this capture."))).append("</p>");
        else {
            sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Protocol"))).append("</th><th>").append(esc(c.t("Name"))).append("</th><th class=\"num\">").append(esc(c.t("Size"))).append("</th><th></th></tr></thead><tbody>");
            for (Map<String, Object> o : objects)
                sb.append("<tr><td>").append(esc(o.get("protocol"))).append("</td><td>").append(esc(o.get("name"))).append("</td><td class=\"num\">").append(Fmt.size((Number) o.get("size"))).append("</td><td>")
                  .append(Boolean.TRUE.equals(o.get("kept")) ? "<a href=\"" + c.path() + "/export/" + id + "/object/" + o.get("file") + "\">" + esc(c.t("Download")) + "</a>" : "<span class=\"hint\">" + esc(c.t("Not kept: over the 200 MB limit")) + "</span>").append("</td></tr>");
            sb.append("</tbody></table></div>");
        }
        return sb.append("</section>").toString();
    }

    @SuppressWarnings("unchecked")
    public static String sequencesPanel(Ctx c, List<Map<String, Object>> seqs) {
        if (seqs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("<section class=\"panel flush\"><h2>" + esc(c.t("HTTP request sequences")) + "</h2><p class=\"muted pad\">" + esc(c.t("Which page each request came from, by its Referer header."))
                + "</p><div class=\"table-wrap\"><table><thead><tr><th>" + esc(c.t("Referer")) + "</th><th>" + esc(c.t("Requested URL")) + "</th><th class=\"num\">" + esc(c.t("Requests")) + "</th></tr></thead><tbody>");
        for (Map<String, Object> s : seqs) {
            List<Map<String, Object>> targets = (List<Map<String, Object>>) s.get("targets");
            boolean first = true;
            for (Map<String, Object> t : targets) {
                sb.append("<tr>");
                if (first) sb.append("<td rowspan=\"").append(targets.size()).append("\">").append(esc(s.get("referer") == null ? c.t("No Referer") : s.get("referer"))).append("</td>");
                first = false;
                sb.append("<td>").append(esc(t.get("url"))).append("</td><td class=\"num\">").append(t.get("requests")).append("</td></tr>");
            }
        }
        return sb.append("</tbody></table></div></section>").toString();
    }

    @SuppressWarnings("unchecked")
    public static String servicesFragment(Ctx c, List<Map<String, Object>> services, List<Map<String, Object>> quic, Map<String, Object> voip) {
        StringBuilder sb = new StringBuilder();
        if (!services.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Service response times"))).append("</h2><p class=\"muted pad\">")
              .append(esc(c.t("Time from each request to its answer, as Wireshark's Service Response Time shows it, for LDAP, Kerberos, SMB2, Kafka, SMTP, DCERPC, MQTT, AMQP and FTP."))).append("</p><div class=\"table-wrap\"><table><thead><tr><th>")
              .append(esc(c.t("Protocol"))).append("</th><th>").append(esc(c.t("Operation"))).append("</th>");
            for (String h : new String[] {"Requests", "Answered", "Errors", "Average", "95th pct", "Slowest"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
            sb.append("</tr></thead><tbody>");
            for (Map<String, Object> s : services) {
                sb.append("<tr class=\"group\"><td><b>").append(esc(s.get("protocol"))).append("</b></td><td>").append(esc(c.t("All"))).append("</td>").append(statCells(s)).append("</tr>");
                for (Map<String, Object> o : (List<Map<String, Object>>) s.get("operations")) sb.append("<tr><td></td><td>").append(esc(o.get("op"))).append("</td>").append(statCells(o)).append("</tr>");
            }
            sb.append("</tbody></table></div></section>");
            boolean anyErr = services.stream().anyMatch(s -> !((List<?>) s.get("error_kinds")).isEmpty());
            if (anyErr) {
                sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Service errors"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Protocol"))).append("</th><th>")
                  .append(esc(c.t("Operation"))).append("</th><th>").append(esc(c.t("Answer"))).append("</th><th class=\"num\">").append(esc(c.t("Count"))).append("</th></tr></thead><tbody>");
                for (Map<String, Object> s : services) for (Map<String, Object> e : (List<Map<String, Object>>) s.get("error_kinds"))
                    sb.append("<tr><td>").append(esc(s.get("protocol"))).append("</td><td>").append(esc(e.get("op"))).append("</td><td>").append(esc(e.get("error"))).append("</td><td class=\"num\">").append(e.get("count")).append("</td></tr>");
                sb.append("</tbody></table></div></section>");
            }
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Servers"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Protocol"))).append("</th><th>").append(esc(c.t("Server")))
              .append("</th><th class=\"num\">").append(esc(c.t("Requests"))).append("</th><th class=\"num\">").append(esc(c.t("Errors"))).append("</th><th class=\"num\">").append(esc(c.t("Average"))).append("</th><th class=\"num\">").append(esc(c.t("Slowest"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> s : services) for (Map<String, Object> v : (List<Map<String, Object>>) s.get("servers"))
                sb.append("<tr><td>").append(esc(s.get("protocol"))).append("</td><td>").append(esc(v.get("server"))).append("</td><td class=\"num\">").append(v.get("requests")).append("</td><td class=\"num\">").append(v.get("errors"))
                  .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(v.get("avg")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(v.get("max")))).append("</td></tr>");
            sb.append("</tbody></table></div></section><section class=\"panel flush\"><h2>").append(esc(c.t("Slowest answers"))).append("</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Protocol"))).append("</th><th>")
              .append(esc(c.t("Operation"))).append("</th><th class=\"num\">").append(esc(c.t("Frame"))).append("</th><th>").append(esc(c.t("Time"))).append("</th><th>").append(esc(c.t("Client"))).append("</th><th>").append(esc(c.t("Server")))
              .append("</th><th class=\"num\">").append(esc(c.t("Response time"))).append("</th><th>").append(esc(c.t("Answer"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> s : services) {
                List<Map<String, Object>> sl = (List<Map<String, Object>>) s.get("slowest");
                for (Map<String, Object> r : sl.subList(0, Math.min(5, sl.size())))
                    sb.append("<tr><td>").append(esc(s.get("protocol"))).append("</td><td>").append(esc(r.get("op"))).append("</td><td class=\"num\">").append(r.get("frame")).append("</td><td>").append(Fmt.clock(Analysis.d(r.get("start"))))
                      .append("</td><td>").append(esc(r.get("client"))).append("</td><td>").append(esc(r.get("server"))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(r.get("time")))).append("</td><td>").append(esc(r.get("error") == null ? "–" : r.get("error"))).append("</td></tr>");
            }
            sb.append("</tbody></table></div></section>");
        }
        sb.append("<section class=\"panel flush\"><h2>QUIC</h2>");
        if (quic.isEmpty()) sb.append("<p class=\"empty\">").append(esc(c.t("No QUIC traffic in this capture."))).append("</p>");
        else {
            sb.append("<div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Client"))).append("</th><th>").append(esc(c.t("Server"))).append("</th><th>").append(esc(c.t("Server name"))).append("</th><th>").append(esc(c.t("Version")))
              .append("</th><th class=\"num\">").append(esc(c.t("Handshake"))).append("</th><th class=\"num\">").append(esc(c.t("Duration"))).append("</th><th class=\"num\">").append(esc(c.t("Packets"))).append("</th><th class=\"num\">")
              .append(esc(c.t("Bytes"))).append("</th><th class=\"num\">").append(esc(c.t("HTTP/3 requests"))).append("</th></tr></thead><tbody>");
            for (Map<String, Object> q : quic)
                sb.append("<tr><td>").append(esc(q.get("client"))).append("</td><td>").append(esc(q.get("server"))).append("</td><td>").append(esc(q.get("sni") == null ? "–" : q.get("sni"))).append("</td><td>").append(esc(q.get("version") == null ? "–" : q.get("version")))
                  .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(q.get("handshake")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(q.get("duration")))).append("</td><td class=\"num\">").append(q.get("packets"))
                  .append("</td><td class=\"num\">").append(Fmt.size((Number) q.get("bytes"))).append("</td><td class=\"num\">").append(Boolean.TRUE.equals(q.get("h3")) || ((Number) q.get("requests")).intValue() > 0 ? q.get("requests") : "–").append("</td></tr>");
            sb.append("</tbody></table></div><p class=\"hint pad\">").append(esc(c.t("HTTP/3 requests are counted only when a TLS key log was given with the capture, because QUIC encrypts them."))).append("</p>");
        }
        sb.append("</section>");
        List<Map<String, Object>> calls = (List<Map<String, Object>>) voip.get("calls"), streams = (List<Map<String, Object>>) voip.get("streams");
        if (!calls.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("SIP calls"))).append("</h2><div class=\"table-wrap\"><table><thead><tr>");
            for (String h : new String[] {"Time", "From", "To", "Caller", "Callee", "State"}) sb.append("<th>").append(esc(c.t(h))).append("</th>");
            for (String h : new String[] {"Answer", "Ringing after", "Answered after", "Talk time", "Messages"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
            sb.append("</tr></thead><tbody>");
            Map<String, String> labels = Map.of("completed", "Completed", "in_call", "In call when the capture ended", "rejected", "Rejected", "cancelled", "Cancelled", "unanswered", "Not answered", "other", "Other");
            for (Map<String, Object> k : calls)
                sb.append("<tr><td>").append(Fmt.clock(Analysis.d(k.get("start")))).append("</td><td>").append(esc(dash(k.get("from_user")))).append("</td><td>").append(esc(dash(k.get("to_user")))).append("</td><td>").append(esc(dash(k.get("caller"))))
                  .append("</td><td>").append(esc(dash(k.get("callee")))).append("</td><td>").append(esc(c.t(labels.getOrDefault((String) k.get("state"), "Other")))).append("</td><td class=\"num\">").append(esc(dash(k.get("status"))))
                  .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(k.get("ringing")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(k.get("setup")))).append("</td><td class=\"num\">")
                  .append(Fmt.seconds(Analysis.dn(k.get("duration")))).append("</td><td class=\"num\">").append(k.get("messages")).append("</td></tr>");
            sb.append("</tbody></table></div></section>");
        }
        if (!streams.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("RTP streams"))).append("</h2><p class=\"muted pad\">").append(esc(c.t("Jitter follows RFC 3550 with the payload type's clock. Dynamic payload types are read with an 8 kHz clock."))).append("</p><div class=\"table-wrap\"><table><thead><tr><th>")
              .append(esc(c.t("Source"))).append("</th><th>").append(esc(c.t("Destination"))).append("</th><th>SSRC</th>");
            for (String h : new String[] {"Payload", "Packets", "Lost", "Out of order", "Largest gap", "Mean jitter", "Highest jitter", "Duration"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
            sb.append("</tr></thead><tbody>");
            for (Map<String, Object> st : streams) {
                boolean bad = Analysis.d(st.get("loss")) > 0.01 || Analysis.d(st.get("max_jitter")) > 0.03;
                sb.append("<tr").append(bad ? " class=\"bad\"" : "").append("><td>").append(esc(st.get("src"))).append("</td><td>").append(esc(st.get("dst"))).append("</td><td>").append(esc(st.get("ssrc"))).append("</td><td class=\"num\">").append(esc(dash(st.get("payload"))))
                  .append("</td><td class=\"num\">").append(st.get("packets")).append("</td><td class=\"num\">").append(st.get("lost")).append(" (").append(String.format(Locale.ROOT, "%.1f", Analysis.d(st.get("loss")) * 100)).append("%)</td><td class=\"num\">")
                  .append(st.get("out_of_order")).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(st.get("max_delta")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(st.get("mean_jitter")))).append("</td><td class=\"num\">")
                  .append(Fmt.seconds(Analysis.dn(st.get("max_jitter")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(st.get("duration")))).append("</td></tr>");
            }
            sb.append("</tbody></table></div><p class=\"hint pad\">").append(esc(c.t("Voice quality usually suffers above 1% loss or 30 ms jitter. Those rows are marked."))).append("</p></section>");
        }
        return sb.toString();
    }

    private static Object dash(Object o) { return o == null ? "–" : o; }

    private static String statCells(Map<String, Object> s) {
        return "<td class=\"num\">" + s.get("requests") + "</td><td class=\"num\">" + s.get("answered") + "</td><td class=\"num\">" + s.get("errors") + "</td><td class=\"num\">" + Fmt.seconds(Analysis.dn(s.get("avg")))
                + "</td><td class=\"num\">" + Fmt.seconds(Analysis.dn(s.get("p95"))) + "</td><td class=\"num\">" + Fmt.seconds(Analysis.dn(s.get("max"))) + "</td>";
    }

    public static String passwordPage(Ctx c, String error) {
        StringBuilder sb = new StringBuilder("<header class=\"page-head\"><div><h1>" + esc(c.t("Change the password")) + "</h1><p class=\"muted\">" + esc(c.t("This is the password everyone with the login shares.")) + "</p></div></header>");
        if (error != null) sb.append("<p class=\"error\" role=\"alert\">").append(esc(error)).append("</p>");
        sb.append("<section class=\"panel\"><form method=\"post\" action=\"").append(c.path()).append("/password\"><input type=\"hidden\" name=\"csrf_token\" value=\"").append(c.csrf()).append("\"><div class=\"fields\"><label>")
          .append(esc(c.t("Current password"))).append(" <input type=\"password\" name=\"current\" required autocomplete=\"current-password\"></label><label>").append(esc(c.t("New password")))
          .append(" <input type=\"password\" name=\"new\" required minlength=\"").append(Passwords.MIN_LENGTH).append("\" autocomplete=\"new-password\"></label><label>").append(esc(c.t("New password again")))
          .append(" <input type=\"password\" name=\"again\" required autocomplete=\"new-password\"></label></div><button class=\"primary\">").append(esc(c.t("Change the password"))).append("</button></form></section>");
        return sb.toString();
    }

    /** A self-contained report of one analysis: one HTML file with its style inside, for mail or a ticket. */
    @SuppressWarnings("unchecked")
    public static String reportPage(Ctx c, Map<String, Object> meta, Map<String, Object> r, String css) {
        Map<String, Object> http = (Map<String, Object>) r.get("http"), tcp = (Map<String, Object>) r.get("tcp");
        long requests = ((Number) http.get("requests")).longValue();
        StringBuilder sb = new StringBuilder("<!doctype html><html lang=\"" + c.lang() + "\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + esc(meta.get("filename")) + "</title><style>" + css
                + "\nbody.app{display:block}.page{max-width:1100px;margin:0 auto;padding:1rem}</style></head><body class=\"app\"><main class=\"page\">");
        sb.append("<header class=\"hero\"><div class=\"hero-head\"><div><h1>").append(esc(meta.get("filename"))).append("</h1><p class=\"muted\">")
          .append(esc(c.t("{file}, {size}, {packets} packets. Captured {when}.", "file", meta.get("filename"), "size", Fmt.size((Number) meta.get("size")), "packets", meta.get("packets"), "when", Fmt.when(Analysis.dn(meta.get("capture_start"))))))
          .append("</p></div></div>");
        if (requests > 0) sb.append(score(c, http)).append(metrics(c, http));
        sb.append("</header>").append(quality(c, (Map<String, Object>) r.get("quality")));
        List<Map<String, Object>> budget = (List<Map<String, Object>>) r.get("budget");
        double total = budget.stream().mapToDouble(p -> Analysis.d(p.get("seconds"))).sum();
        if (total > 0) {
            Map<String, Object> phases = new LinkedHashMap<>();
            budget.forEach(p -> phases.put((String) p.get("name"), p.get("seconds")));
            sb.append("<section class=\"panel\"><h2>").append(esc(c.t("Where the time went"))).append("</h2><div class=\"budget\">").append(strip(c, phases)).append("</div>").append(breakdown(c, budget)).append("</section>");
        }
        List<Map<String, Object>> slow = (List<Map<String, Object>>) r.get("slow");
        if (!slow.isEmpty()) sb.append("<section class=\"panel flush\"><h2>").append(esc(c.t("Slowest requests"))).append("</h2>").append(waterfall(c.withId(null), slow)).append("</section>");
        sb.append(issuesTab(c, "", (List<Map<String, Object>>) r.get("issues")).replaceAll("<a href=\"[^\"]*\">([^<]*)</a>", "<b>$1</b>"));
        List<Map<String, Object>> urls = (List<Map<String, Object>>) r.get("urls");
        if (!urls.isEmpty()) {
            sb.append("<section class=\"panel flush\"><h2>URLs</h2><div class=\"table-wrap\"><table><thead><tr><th>").append(esc(c.t("Method"))).append("</th><th>URL</th>");
            for (String h : new String[] {"Requests", "Failed", "Average", "95th percentile", "Slowest"}) sb.append("<th class=\"num\">").append(esc(c.t(h))).append("</th>");
            sb.append("</tr></thead><tbody>");
            for (Map<String, Object> u : urls.subList(0, Math.min(100, urls.size())))
                sb.append("<tr><td>").append(esc(u.get("method"))).append("</td><td>").append(esc(u.get("url"))).append("</td><td class=\"num\">").append(u.get("requests")).append("</td><td class=\"num\">").append(u.get("failed"))
                  .append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("avg_total")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("p95_total")))).append("</td><td class=\"num\">").append(Fmt.seconds(Analysis.dn(u.get("max_total")))).append("</td></tr>");
            sb.append("</tbody></table></div></section>");
        }
        sb.append("<section class=\"panel\"><h2>").append(esc(c.t("TCP"))).append("</h2><dl class=\"facts\">");
        fact(sb, c.t("Connections"), tcp.get("connections")); fact(sb, c.t("Handshakes seen"), tcp.get("handshakes")); fact(sb, c.t("Resets"), tcp.get("resets")); fact(sb, c.t("Retransmissions"), tcp.get("retransmissions"));
        fact(sb, c.t("Average connect"), Fmt.seconds(Analysis.dn(tcp.get("avg_connect")))); fact(sb, c.t("Average round trip"), Fmt.seconds(Analysis.dn(tcp.get("avg_rtt_server"))));
        sb.append("</dl></section><p class=\"hint\">pcap-analyzer ").append(VERSION).append("</p></main></body></html>");
        return sb.toString();
    }
}
