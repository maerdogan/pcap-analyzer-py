package io.pcapanalyzer;

import java.util.*;

/** Focused view on one source, destination, port and connection type, computed from a stored analysis. */
public final class Inspect {
    public record Query(String src, Integer srcPort, String dst, Integer port, String kind, String url, Long minSize, String sizeOf, Double start, Double end) {}

    /** Filter of the slowest requests list: text in the method, URL, host or status, a status class, and a duration range in milliseconds. */
    public record Slow(String text, String status, Double minMs, Double maxMs) {
        boolean empty() { return text == null && status == null && minMs == null && maxMs == null; }
    }

    static final List<String> STATUS_CLASSES = List.of("2xx", "3xx", "4xx", "5xx", "none");

    private Inspect() {}

    public static Slow slow(Map<String, String[]> p) {
        String st = str(p, "slow_status");
        if (st != null && !STATUS_CLASSES.contains(st)) st = null;
        Double min = dbl(p, "slow_min_ms"), max = dbl(p, "slow_max_ms");
        return new Slow(str(p, "slow_q"), st, min != null && min >= 0 ? min : null, max != null && max >= 0 ? max : null);
    }

    static boolean slowMatches(Slow s, Map<String, Object> x) {
        if (s == null || s.empty()) return true;
        if (s.text() != null) {
            String hay = (x.get("method") + " " + x.get("uri") + " " + x.get("host") + " " + x.get("status")).toLowerCase();
            if (!hay.contains(s.text().toLowerCase())) return false;
        }
        Integer code = Analysis.statusOf(x);
        if (s.status() != null) {
            String cls = code == null || code == 0 ? "none" : (code / 100) + "xx";
            if (!s.status().equals(cls)) return false;
        }
        Double total = Analysis.dn(x.get("total"));
        if (s.minMs() != null && (total == null || total * 1000 < s.minMs())) return false;
        if (s.maxMs() != null && (total == null || total * 1000 > s.maxMs())) return false;
        return true;
    }

    static final double[] BUCKETS_S = {1, 5, 10, 30, 60, 300, 900, 1800, 3600, 21600, 86400};
    static final int MAX_POINTS = 120;

    /** Bucket width that keeps a time series of the span under MAX_POINTS points. */
    static double bucket(double span) {
        for (double b : BUCKETS_S) if (span / b <= MAX_POINTS) return b;
        return BUCKETS_S[BUCKETS_S.length - 1];
    }

    /** One URL over time: per bucket the requests, failures, average and 95th percentile total, and the average of each phase. Empty buckets are left out. */
    static List<Map<String, Object>> series(List<Map<String, Object>> g, double from, double width) {
        TreeMap<Long, List<Map<String, Object>>> by = new TreeMap<>();
        for (Map<String, Object> t : g) by.computeIfAbsent((long) Math.floor((Analysis.d(t.get("req_start")) - from) / width), k -> new ArrayList<>()).add(t);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<Long, List<Map<String, Object>>> e : by.entrySet()) {
            List<Double> totals = new ArrayList<>();
            Map<String, Double> ph = new LinkedHashMap<>();
            int failed = 0;
            for (Map<String, Object> t : e.getValue()) {
                Double tot = Analysis.dn(t.get("total"));
                if (tot != null) totals.add(tot);
                if (Analysis.unansweredOr5xx(t)) failed++;
                if (t.get("phases") instanceof Map<?, ?> m) for (String name : Analysis.PHASES) if (m.get(name) instanceof Number n) ph.merge(name, n.doubleValue(), Double::sum);
            }
            Collections.sort(totals);
            int n = e.getValue().size();
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("t", from + e.getKey() * width); p.put("n", n); p.put("failed", failed);
            p.put("avg", totals.isEmpty() ? null : totals.stream().mapToDouble(Double::doubleValue).sum() / totals.size());
            p.put("p95", totals.isEmpty() ? null : totals.get(Math.min(totals.size() - 1, (int) Math.ceil(0.95 * totals.size()) - 1)));
            Map<String, Double> avgPh = new LinkedHashMap<>();
            ph.forEach((k, v) -> { if (v > 0) avgPh.put(k, v / n); });
            p.put("phases", avgPh);
            out.add(p);
        }
        return out;
    }

    /** Where the time of each URL's requests went, on average: the phases of the requests, and the round trips on both sides of the capture point. */
    static Map<String, Object> breakdown(List<Map<String, Object>> g, Map<Integer, Map<String, Object>> connOf) {
        Map<String, double[]> sum = new LinkedHashMap<>();
        java.util.function.BiConsumer<String, Object> add = (k, v) -> { if (v instanceof Number n) { double[] a = sum.computeIfAbsent(k, z -> new double[2]); a[0] += n.doubleValue(); a[1]++; } };
        Set<Integer> seenConn = new HashSet<>();
        for (Map<String, Object> x : g) {
            Map<String, Object> cn = connOf.get(Analysis.streamOf(x));
            if (cn != null && seenConn.add(Analysis.streamOf(cn))) { add.accept("rtt_client", cn.get("rtt_client")); add.accept("rtt_server", cn.get("rtt_server")); }
            if (x.get("phases") instanceof Map<?, ?> ph) for (String name : Analysis.PHASES) add.accept(name, ph.get(name));
            add.accept("upstream_time", x.get("upstream_time")); add.accept("gateway_time", x.get("gateway_time"));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        // phases are averaged over all requests of the URL, so they add up to the average total
        for (Map.Entry<String, double[]> e : sum.entrySet()) {
            boolean phase = Arrays.asList(Analysis.PHASES).contains(e.getKey());
            out.put(e.getKey(), e.getValue()[0] / (phase ? g.size() : e.getValue()[1]));
        }
        return out;
    }

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

    /** The result with only the connections and requests the query selects. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> filtered(Query q, Map<String, Object> result) {
        Set<Integer> keep = new HashSet<>();
        List<Map<String, Object>> conns = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) result.get("connections")) if (connMatches(q, c)) { conns.add(c); keep.add(Analysis.streamOf(c)); }
        List<Map<String, Object>> txns = new ArrayList<>();
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) {
            if (!keep.contains(Analysis.streamOf(x))) continue;
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
        Map<String, Object> out = new LinkedHashMap<>(result);
        out.put("connections", conns); out.put("transactions", txns);
        return out;
    }

    public static Map<String, Object> run(Query q, Map<String, Object> result) { return run(q, result, null); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> run(Query q, Map<String, Object> result, Slow slow) {
        Map<String, Object> f = filtered(q, result);
        List<Map<String, Object>> conns = (List<Map<String, Object>>) f.get("connections"), txns = (List<Map<String, Object>>) f.get("transactions");
        Map<Integer, Map<String, Object>> connOf = new HashMap<>();
        for (Map<String, Object> c : conns) connOf.put(Analysis.streamOf(c), c);
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
        List<Map<String, Object>> urls = Analysis.urls(txns);
        Map<String, List<Map<String, Object>>> groups = new HashMap<>();
        for (Map<String, Object> t : txns) groups.computeIfAbsent(t.get("method") + " " + t.get("url_template"), k -> new ArrayList<>()).add(t);
        double from = txns.stream().mapToDouble(t -> Analysis.d(t.get("req_start"))).min().orElse(0), to = txns.stream().mapToDouble(t -> Analysis.d(t.get("req_start"))).max().orElse(0);
        double width = bucket(to - from);
        for (Map<String, Object> u : urls) {
            List<Map<String, Object>> g = groups.getOrDefault(u.get("method") + " " + u.get("url"), List.of());
            u.put("breakdown", breakdown(g, connOf));
            u.put("series", series(g, from, width));
        }
        out.put("bucket_s", width);
        out.put("urls", urls);
        List<Map<String, Object>> slowTxns = new ArrayList<>();
        for (Map<String, Object> t : txns) if (slowMatches(slow, t)) slowTxns.add(t);
        boolean ranged = slow != null && (slow.minMs() != null || slow.maxMs() != null);
        out.put("slowest", Analysis.slowest(slowTxns, connOf, ranged ? slowTxns.size() : Analysis.SLOWEST)); // a duration range lists every match
        out.put("slow_matched", slowTxns.size());
        return out;
    }
}
