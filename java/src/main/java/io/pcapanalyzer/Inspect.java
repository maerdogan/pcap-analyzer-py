package io.pcapanalyzer;

import java.util.*;

/** Focused view on one source, destination, port and connection type, computed from a stored analysis. */
public final class Inspect {
    public record Query(String src, Integer srcPort, String dst, Integer port, String kind, String url, Long minSize, String sizeOf, Double start, Double end) {}

    private Inspect() {}

    static String str(Map<String, String[]> p, String k) {
        String[] v = p.get(k);
        return v == null || v[0].isBlank() ? null : v[0].strip();
    }

    static Integer num(Map<String, String[]> p, String k) {
        try { String v = str(p, k); return v == null ? null : Integer.valueOf(v); } catch (NumberFormatException e) { return null; }
    }

    static Double dbl(Map<String, String[]> p, String k) {
        try { String v = str(p, k); return v == null ? null : Double.valueOf(v); } catch (NumberFormatException e) { return null; }
    }

    public static Query query(Map<String, String[]> p) {
        String sizeOf = Optional.ofNullable(str(p, "size_of")).orElse("total");
        if (!List.of("total", "request", "response", "packet").contains(sizeOf)) sizeOf = "total";
        Integer minSize = num(p, "min_size");
        return new Query(str(p, "src"), num(p, "src_port"), str(p, "dst"), num(p, "port"), str(p, "kind"), str(p, "url"),
                minSize == null ? null : minSize.longValue(), sizeOf, dbl(p, "start"), dbl(p, "end"));
    }

    static boolean connMatches(Query q, Map<String, Object> c) {
        if (q.src() != null && !q.src().equals(c.get("client_ip"))) return false;
        if (q.srcPort() != null && q.srcPort() != Analysis.d(c.get("client_port"))) return false;
        if (q.dst() != null && !q.dst().equals(c.get("server_ip"))) return false;
        if (q.port() != null && q.port() != Analysis.d(c.get("server_port"))) return false;
        if (q.kind() != null && !q.kind().equals(c.get("kind"))) return false;
        if (q.start() != null && Analysis.d(c.get("end_time")) < q.start()) return false;
        if (q.end() != null && Analysis.d(c.get("start_time")) > q.end()) return false;
        return true;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> run(Query q, Map<String, Object> result) {
        List<Map<String, Object>> conns = new ArrayList<>(), all = (List<Map<String, Object>>) result.get("connections");
        Map<Integer, Map<String, Object>> connOf = new HashMap<>();
        for (Map<String, Object> c : all) if (connMatches(q, c)) { conns.add(c); connOf.put(((Number) c.get("stream")).intValue(), c); }
        List<Map<String, Object>> txns = new ArrayList<>();
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) {
            if (!connOf.containsKey(((Number) x.get("stream")).intValue())) continue;
            if (q.url() != null && !String.valueOf(x.get("uri")).toLowerCase().contains(q.url().toLowerCase())) continue;
            if (q.start() != null && Analysis.d(x.get("req_start")) < q.start()) continue;
            if (q.end() != null && Analysis.d(x.get("req_start")) > q.end()) continue;
            if (q.minSize() != null) {
                double rq = Analysis.d(x.get("req_bytes")), rs = Analysis.d(x.get("resp_bytes"));
                double size = switch (q.sizeOf()) { case "request" -> rq; case "response" -> rs; case "packet" -> Math.max(rq, rs); default -> rq + rs; };
                if (size <= q.minSize()) continue;
            }
            txns.add(x);
        }
        long ok = 0, http = 0, tcpOnly = 0;
        double connect = 0, rtt = 0;
        int nc = 0, nr = 0;
        for (Map<String, Object> c : conns) {
            if (Boolean.TRUE.equals(c.get("handshake_seen")) && !"RST".equals(c.get("close_type"))) ok++;
            if ("TCP".equals(c.get("kind")) || "TLS".equals(c.get("kind"))) tcpOnly++; else http++;
            if (c.get("connect_time") != null) { connect += Analysis.d(c.get("connect_time")); nc++; }
            if (c.get("rtt_server") != null) { rtt += Analysis.d(c.get("rtt_server")); nr++; }
        }
        Map<String, Object> cs = new LinkedHashMap<>();
        cs.put("connections", conns.size()); cs.put("ok", ok); cs.put("http", http); cs.put("tcp_only", tcpOnly);
        cs.put("avg_connect", nc == 0 ? null : connect / nc); cs.put("avg_rtt", nr == 0 ? null : rtt / nr);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requests", Analysis.http(txns));
        out.put("connections", cs);
        out.put("urls", Analysis.urls(txns));
        out.put("slowest", Analysis.slowest(txns, connOf));
        return out;
    }
}
