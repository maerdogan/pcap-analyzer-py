package io.pcapanalyzer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Tables of one analysis as CSV, JSON or Excel files, and the requests as a HAR file. */
public final class Exports {
    public static final List<String> TABLES = List.of("requests", "urls", "connections", "hosts", "issues");
    public static final Map<String, String> FORMATS = Map.of("csv", "text/csv; charset=utf-8", "json", "application/json",
            "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    private static final String[] REQUEST_COLUMNS = {"id", "stream", "method", "uri", "url_template", "host", "http_version", "status", "answered", "req_frame", "resp_frame",
            "connect_time", "request_send", "wait", "service", "ttfb", "transfer", "total", "req_bytes", "resp_bytes", "cause", "client", "server"};

    private Exports() {}

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> table(String name, Map<String, Object> result, String lang) {
        List<Map<String, Object>> out = new ArrayList<>();
        switch (name) {
            case "requests" -> {
                for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) {
                    Map<String, Object> r = new LinkedHashMap<>();
                    for (String c : REQUEST_COLUMNS) r.put(c, x.get(c));
                    out.add(r);
                }
            }
            case "urls" -> {
                for (Map<String, Object> u : (List<Map<String, Object>>) result.get("urls")) {
                    Map<String, Object> r = new LinkedHashMap<>(u);
                    StringBuilder st = new StringBuilder();
                    for (Map<String, Object> s : (List<Map<String, Object>>) u.get("statuses")) st.append(st.length() > 0 ? ", " : "").append(s.get("status") == null ? Knowledge.ui("none", lang) : s.get("status")).append(" x").append(s.get("requests"));
                    r.put("statuses", st.toString());
                    out.add(r);
                }
            }
            case "connections" -> out.addAll((List<Map<String, Object>>) result.get("connections"));
            case "hosts" -> {
                for (Map<String, Object> h : (List<Map<String, Object>>) result.get("hosts")) {
                    Map<String, Object> r = new LinkedHashMap<>(h);
                    r.put("addresses", String.join(", ", (List<String>) h.get("addresses")));
                    out.add(r);
                }
            }
            case "issues" -> {
                for (Map<String, Object> i : (List<Map<String, Object>>) result.get("issues")) {
                    String[] info = Knowledge.issue((String) i.get("key"), lang);
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("key", i.get("key")); r.put("title", info[0]); r.put("why", info[1]); r.put("count", i.get("count")); r.put("severity", i.get("severity"));
                    out.add(r);
                }
            }
            default -> throw new IllegalArgumentException(name);
        }
        return out;
    }

    /** URLs come from the capture, so stop spreadsheets from running them as formulas. */
    static String safe(String v) {
        return !v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0 ? "'" + v : v;
    }

    private static List<String> columns(List<Map<String, Object>> rows) { return rows.isEmpty() ? List.of() : new ArrayList<>(rows.get(0).keySet()); }

    public static byte[] render(List<Map<String, Object>> rows, String fmt, String lang) throws IOException {
        List<String> cols = columns(rows);
        switch (fmt) {
            case "json": return Json.write(rows).getBytes(StandardCharsets.UTF_8);
            case "csv": {
                StringBuilder sb = new StringBuilder("﻿");
                sb.append(String.join(",", cols.stream().map(c -> csv(Knowledge.column(c, lang))).toList())).append("\r\n");
                for (Map<String, Object> r : rows) {
                    List<String> cells = new ArrayList<>();
                    for (String c : cols) cells.add(csv(r.get(c) == null ? "" : safe(String.valueOf(r.get(c)))));
                    sb.append(String.join(",", cells)).append("\r\n");
                }
                return sb.toString().getBytes(StandardCharsets.UTF_8);
            }
            case "xlsx": return xlsx(rows, cols, lang);
            default: throw new IllegalArgumentException(fmt);
        }
    }

    private static String csv(String v) {
        return v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r") ? "\"" + v.replace("\"", "\"\"") + "\"" : v;
    }

    private static String xml(String v) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '&') sb.append("&amp;"); else if (c == '<') sb.append("&lt;"); else if (c == '>') sb.append("&gt;");
            else if (c >= 0x20 || c == '\n' || c == '\t') sb.append(c);
        }
        return sb.toString();
    }

    private static String cell(int col, int row, Object v) {
        StringBuilder ref = new StringBuilder();
        for (int n = col; n >= 0; n = n / 26 - 1) ref.insert(0, (char) ('A' + n % 26));
        ref.append(row);
        if (v == null) return "";
        if (v instanceof Number n && !(n instanceof Double d && (d.isNaN() || d.isInfinite()))) return "<c r=\"" + ref + "\"><v>" + n + "</v></c>";
        if (v instanceof Boolean b) return "<c r=\"" + ref + "\" t=\"b\"><v>" + (b ? 1 : 0) + "</v></c>";
        return "<c r=\"" + ref + "\" t=\"inlineStr\"><is><t xml:space=\"preserve\">" + xml(safe(String.valueOf(v))) + "</t></is></c>";
    }

    private static byte[] xlsx(List<Map<String, Object>> rows, List<String> cols, String lang) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bytes)) {
            put(z, "[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>");
            put(z, "_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");
            put(z, "xl/workbook.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Sheet\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>");
            put(z, "xl/_rels/workbook.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>");
            StringBuilder sheet = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>");
            sheet.append("<row r=\"1\">");
            for (int i = 0; i < cols.size(); i++) sheet.append(cell(i, 1, Knowledge.column(cols.get(i), lang)));
            sheet.append("</row>");
            int n = 2;
            for (Map<String, Object> r : rows) {
                sheet.append("<row r=\"").append(n).append("\">");
                for (int i = 0; i < cols.size(); i++) sheet.append(cell(i, n, r.get(cols.get(i))));
                sheet.append("</row>");
                n++;
            }
            put(z, "xl/worksheets/sheet1.xml", sheet.append("</sheetData></worksheet>").toString());
        }
        return bytes.toByteArray();
    }

    private static void put(ZipOutputStream z, String name, String content) throws IOException {
        z.putNextEntry(new ZipEntry(name));
        z.write(content.getBytes(StandardCharsets.UTF_8));
        z.closeEntry();
    }

    private static List<Object> pairs(String block) {
        List<Object> out = new ArrayList<>();
        if (block == null) return out;
        for (String line : block.split("\\R")) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", line.substring(0, colon)); m.put("value", line.substring(colon + 1).strip());
            out.add(m);
        }
        return out;
    }

    private static double ms(Object v) { return v instanceof Number n ? Math.round(n.doubleValue() * 1_000_000) / 1000.0 : -1; }

    /** Requests as a HAR 1.2 file. Headers are the masked ones, so secrets stay out of it. */
    @SuppressWarnings("unchecked")
    public static String har(Map<String, Object> result, Map<String, Object> details) {
        List<Object> entries = new ArrayList<>();
        for (Map<String, Object> t : (List<Map<String, Object>>) result.get("transactions")) {
            boolean tls = String.valueOf(t.get("kind")).startsWith("HTTPS");
            String server = String.valueOf(t.get("server"));
            String host = t.get("host") != null ? t.get("host").toString() : server.substring(0, server.lastIndexOf(':'));
            String version = t.get("http_version") == null ? "HTTP/1.1" : t.get("http_version").toString();
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("startedDateTime", Instant.ofEpochMilli((long) (Analysis.d(t.get("req_start")) * 1000)).toString());
            e.put("time", t.get("total") == null ? 0 : ms(t.get("total")));
            Map<String, Object> rq = new LinkedHashMap<>(), rs = new LinkedHashMap<>(), content = new LinkedHashMap<>();
            rq.put("method", t.get("method")); rq.put("url", (tls ? "https://" : "http://") + host + (t.get("uri") == null ? "" : t.get("uri"))); rq.put("httpVersion", version);
            Map<String, Object> det = (Map<String, Object>) details.getOrDefault(String.valueOf(((Number) t.get("id")).intValue()), new HashMap<>());
            rq.put("cookies", List.of()); rq.put("headers", pairs((String) det.get("req_headers"))); rq.put("queryString", List.of()); rq.put("headersSize", -1); rq.put("bodySize", t.get("req_bytes") == null ? 0 : t.get("req_bytes"));
            content.put("size", t.get("resp_bytes") == null ? 0 : t.get("resp_bytes")); content.put("mimeType", t.get("content_type") == null ? "" : t.get("content_type"));
            rs.put("status", t.get("status") == null ? 0 : t.get("status")); rs.put("statusText", t.get("phrase") == null ? "" : t.get("phrase")); rs.put("httpVersion", version);
            rs.put("cookies", List.of()); rs.put("headers", pairs((String) det.get("resp_headers"))); rs.put("content", content); rs.put("redirectURL", ""); rs.put("headersSize", -1); rs.put("bodySize", t.get("resp_bytes") == null ? 0 : t.get("resp_bytes"));
            e.put("request", rq); e.put("response", rs); e.put("cache", new LinkedHashMap<>());
            e.put("serverIPAddress", server.substring(0, server.lastIndexOf(':'))); e.put("connection", String.valueOf(t.get("stream")));
            Map<String, Object> tm = new LinkedHashMap<>();
            tm.put("blocked", -1); tm.put("dns", -1); tm.put("connect", ms(t.get("connect_time"))); tm.put("ssl", -1); tm.put("send", ms(t.get("request_send")));
            tm.put("wait", t.get("wait") == null ? 0 : ms(t.get("wait"))); tm.put("receive", t.get("transfer") == null ? 0 : ms(t.get("transfer")));
            e.put("timings", tm);
            entries.add(e);
        }
        Map<String, Object> creator = new LinkedHashMap<>(), log = new LinkedHashMap<>(), root = new LinkedHashMap<>();
        creator.put("name", "pcap-analyzer"); creator.put("version", Pages.VERSION);
        log.put("version", "1.2"); log.put("creator", creator); log.put("entries", entries);
        root.put("log", log);
        return Json.write(root);
    }
}
