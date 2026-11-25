package io.pcapanalyzer;

import java.nio.file.Path;
import java.util.*;

/** Analyzes one capture and prepares every view the pages and charts need. */
public final class Analysis {
    static final double DEFAULT_SLOW_S = 0.2;
    /** Requests under this are normal, whatever their largest phase is. Set from the saved limit before each analysis. */
    static volatile double SLOW_S = DEFAULT_SLOW_S;
    static final int SLOWEST = 10;
    static final int MAX_STORED = 50_000;
    /** Raised when the stored result changes shape, so older analyses show a message instead of failing. */
    public static final int RESULT_VERSION = 2;
    static final double[] BUCKETS_S = {0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600};
    static final int CHART_POINTS = 150;
    static final double LOST_SHARE_HIGH = 0.01, MOST = 0.5;
    static final String[] PHASES = {"connect_time", "tls_time", "request_clean", "network", "queue_time", "service", "transfer_clean",
            "retrans_time", "zero_window_time", "h2_flow_time", "delayed_ack_time"};
    static final Set<String> PHASES_SET = Set.of(PHASES);
    static final Map<String, String> CAUSE_OF_PHASE = Map.ofEntries(Map.entry("connect_time", "connect"), Map.entry("tls_time", "tls"), Map.entry("request_clean", "upload"),
            Map.entry("network", "network"), Map.entry("queue_time", "queueing"), Map.entry("service", "service"), Map.entry("transfer_clean", "transfer"),
            Map.entry("retrans_time", "loss"), Map.entry("zero_window_time", "slow_client"), Map.entry("h2_flow_time", "h2_flow_stall"), Map.entry("delayed_ack_time", "delayed_ack"));

    private Analysis() {}

    /** Detail of each issue: requests and connections behind it, filled by issues(). */
    private static final ThreadLocal<Map<String, Object>> DETAIL = ThreadLocal.withInitial(LinkedHashMap::new);


    static Integer statusOf(Map<String, Object> x) { return x.get("status") instanceof Number n ? n.intValue() : null; }
    /** No answer, or a 5xx: what counts as failed for retries and for a URL over time. */
    static boolean unansweredOr5xx(Map<String, Object> x) { Integer st = statusOf(x); return st == null || st == 0 || st >= 500; }

    static Integer streamOf(Map<String, Object> x) { return ((Number) x.get("stream")).intValue(); }

    static double d(Object o) { return o instanceof Number n ? n.doubleValue() : 0.0; }
    static Double dn(Object o) { return o instanceof Number n ? n.doubleValue() : null; }

    static boolean failed(Map<String, Object> x) {
        Integer st = statusOf(x);
        return st == null || st >= 400;
    }

    static boolean error(Map<String, Object> x) {
        Integer st = statusOf(x);
        return st == null || st >= 500;
    }

    /** A request whose request ID was seen before on an attempt that failed and ended before it began: a retry by the gateway or the client.
     *  Two legs of one proxy carry the same ID too, but they overlap in time, so they are not counted. */
    static void markRetries(List<Map<String, Object>> txns) {
        Map<Object, List<Map<String, Object>>> byId = new HashMap<>();
        for (Map<String, Object> t : txns) if (t.get("request_id") != null) byId.computeIfAbsent(t.get("request_id"), k -> new ArrayList<>()).add(t);
        for (List<Map<String, Object>> g : byId.values()) {
            if (g.size() < 2) continue;
            g.sort(Comparator.comparingDouble(t -> d(t.get("req_start"))));
            int attempt = 1;
            Map<String, Object> first = g.get(0), prev = first;
            for (Map<String, Object> t : g.subList(1, g.size())) {
                boolean failed = unansweredOr5xx(prev);
                double prevEnd = prev.get("resp_end") != null ? d(prev.get("resp_end")) : d(prev.get("req_end"));
                if (!failed || prevEnd > d(t.get("req_start"))) continue;
                t.put("attempt", ++attempt); t.put("retry_of", prev.get("id"));
                prev = t;
            }
        }
    }

    /** In a NetScaler trace each connection names its own PCB and the linked PCB of the other leg: client to VIP, and SNIP to server.
     *  Sets ns_peer to the stream of the other leg. Either side naming the other is enough. */
    static void linkNetScalerLegs(List<Map<String, Object>> conns) {
        Map<Object, Map<String, Object>> byPcb = new HashMap<>();
        for (Map<String, Object> c : conns) if (c.get("ns_pcb") != null) byPcb.putIfAbsent(c.get("ns_pcb"), c);
        for (Map<String, Object> c : conns) {
            Map<String, Object> peer = c.get("ns_linked_pcb") == null ? null : byPcb.get(c.get("ns_linked_pcb"));
            if (peer == null || peer == c) continue;
            c.putIfAbsent("ns_peer", peer.get("stream"));
            peer.putIfAbsent("ns_peer", c.get("stream"));
        }
    }

    public static Map<String, Object> run(TShark tshark, Path capture, String filter, long timeoutSeconds) throws TShark.TsharkException {
        return run(tshark, capture, null, filter, timeoutSeconds);
    }

    public static Map<String, Object> run(TShark tshark, Path capture, Path keylog, String filter, long timeoutSeconds) throws TShark.TsharkException {
        return run(tshark, capture, keylog, null, List.of(), filter, timeoutSeconds);
    }

    public static Map<String, Object> run(TShark tshark, Path capture, Path keylog, Path rsaKey, List<String> decodeAs, String filter, long timeoutSeconds) throws TShark.TsharkException {
        Builder b = new Builder();
        tshark.read(capture, keylog, rsaKey, decodeAs, filter, timeoutSeconds, b::add);
        List<Builder.Finished> fin = b.finish();
        List<Map<String, Object>> conns = new ArrayList<>(), txns = new ArrayList<>();
        Map<Integer, Map<String, Object>> connOf = new HashMap<>();
        for (Builder.Finished f : fin) {
            conns.add(f.conn());
            connOf.put((Integer) f.conn().get("stream"), f.conn());
            txns.addAll(f.txns());
        }
        linkNetScalerLegs(conns);
        txns.sort(Comparator.comparing((Map<String, Object> x) -> streamOf(x)).thenComparingDouble(x -> d(x.get("req_start"))));
        int nextId = 1;
        Map<String, Object> details = new LinkedHashMap<>();
        for (Map<String, Object> x : txns) {
            Map<String, Object> cn = connOf.get(streamOf(x));
            Map<String, Object> det = new LinkedHashMap<>();
            for (String k : new String[] {"_req_headers", "_resp_headers", "_req_body", "_resp_body"}) {
                Object v = x.remove(k);
                if (v != null) det.put(k.substring(1), v);
            }
            if (!det.isEmpty()) details.put(String.valueOf(nextId), det);
            x.put("id", nextId++);
            x.put("client", cn.get("client")); x.put("server", cn.get("server")); x.put("kind", cn.get("kind"));
            phases(x, cn);
        }

        markRetries(txns);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("version", RESULT_VERSION);
        result.put("_details", details);
        result.put("summary", summary(b, conns, txns));
        result.put("http", http(txns));
        result.put("tcp", tcp(conns));
        result.put("kinds", counts(conns, "kind", "kind"));
        result.put("capture_points", counts(conns, "capture_point", "capture_point"));
        result.put("budget", budget(txns));
        result.put("slow", slowest(txns, connOf));
        result.put("quality", quality(b, conns));
        result.put("warnings", warnings(b, conns, txns));
        result.put("timeline", timeline(b, conns, txns));
        result.put("statuses", statuses(txns));
        result.put("histogram", histogram(txns));
        result.put("urls", urls(txns));
        result.put("connections", connectionRows(conns, txns));
        result.put("transactions", txns.size() > MAX_STORED ? new ArrayList<>(txns.subList(0, MAX_STORED)) : txns);
        result.put("tls", tls(conns));
        result.put("hosts", hosts(conns, txns));
        result.put("backends", backends(conns, txns));
        DETAIL.get().clear();
        @SuppressWarnings("unchecked") List<Map<String, Object>> backs = (List<Map<String, Object>>) result.get("backends");
        result.put("issues", issues(b, conns, txns, connOf, backs));
        result.put("issue_detail", new LinkedHashMap<>(DETAIL.get()));
        return result;
    }

    // ---- per request

    /** The time of a request split into phases, and the cause of the time, as causes.classify does. */
    static void phases(Map<String, Object> x, Map<String, Object> conn) {
        Map<String, Double> p = new LinkedHashMap<>();
        for (String name : PHASES) p.put(name, d(x.get(name)));
        x.put("phases", p);
        Integer st = statusOf(x);
        boolean answered = Boolean.TRUE.equals(x.get("answered"));
        boolean gateway = st != null && (st == 502 || st == 503 || st == 504);
        List<String> flags = new ArrayList<>();
        if (gateway) flags.add("gateway_error");
        if (Boolean.TRUE.equals(x.get("truncated"))) flags.add("truncated");
        Integer mss = conn.get("mss") instanceof Number n ? n.intValue() : null;
        if (mss != null && mss < 1200) flags.add("small_mss");
        if (x.get("content_encoding") != null) flags.add("compressed");
        if (x.get("transfer_encoding") != null) flags.add("chunked");
        if (x.get("connect_time") != null) flags.add("new_connection");
        String cause;
        double share = 1.0;
        if (!answered) cause = "RST".equals(conn.get("close_type")) ? "connection_reset" : "no_response";
        else if (st != null && st == 101) cause = "websocket";
        else if (Boolean.TRUE.equals(x.get("truncated"))) cause = "truncated";
        else if (gateway) cause = "gateway";
        else {
            Map<String, Double> q = new LinkedHashMap<>(p);
            double total = q.values().stream().mapToDouble(Double::doubleValue).sum();
            if (q.get("network") > 0 && q.get("connect_time") <= 3 * q.get("network")) {
                q.put("network", q.get("network") + q.get("connect_time"));
                q.put("connect_time", 0.0);
            }
            String top = PHASES[0];
            for (String name : PHASES) if (q.get(name) > q.get(top)) top = name;
            share = total > 0 ? q.get(top) / total : 0;
            cause = q.get(top) < SLOW_S ? "normal" : CAUSE_OF_PHASE.get(top);
        }
        x.put("cause", cause);
        x.put("cause_share", share);
        x.put("flags", String.join(",", flags));
        double longest = answered ? d(x.get("total")) : Math.max(d(conn.get("end_time")) - d(x.get("req_end")), 0);
        x.put("longest", longest);
    }

    static Map<String, Object> facts(Map<String, Object> x, Map<String, Object> conn) {
        Map<String, Object> f = new HashMap<>(x);
        f.putAll(x.get("phases") instanceof Map<?, ?> m ? castPhases(m) : Map.of());
        boolean answered = Boolean.TRUE.equals(x.get("answered"));
        f.put("elapsed", answered ? x.get("wait") : Math.max(d(conn.get("end_time")) - d(x.get("req_end")), 0));
        f.put("pct", String.format(Locale.ROOT, "%.0f", d(x.get("cause_share")) * 100));
        f.put("still_open", conn.get("close_type") == null);
        for (String k : new String[] {"capture_point", "closed_by", "close_type", "rtt_client"}) f.put(k, conn.get(k));
        f.values().removeIf(Objects::isNull);
        return f;
    }

    private static Map<String, Object> castPhases(Map<?, ?> m) {
        Map<String, Object> o = new HashMap<>();
        m.forEach((k, v) -> o.put((String) k, v));
        return o;
    }

    // ---- overview

    static Map<String, Object> summary(Builder b, List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("packets", b.total); s.put("tcp_packets", b.tcp); s.put("bytes", b.bytes);
        s.put("start", b.tFirst); s.put("end", b.tLast);
        s.put("connections", conns.size()); s.put("requests", txns.size());
        s.put("health_checks", txns.stream().filter(t -> Boolean.TRUE.equals(t.get("health_check"))).count());
        s.put("retries", txns.stream().filter(t -> t.get("retry_of") != null).count());
        return s;
    }

    static Double percentile(List<Double> sorted, double q) {
        if (sorted.isEmpty()) return null;
        double pos = q * (sorted.size() - 1);
        int lo = (int) Math.floor(pos), hi = (int) Math.ceil(pos);
        return sorted.get(lo) + (sorted.get(hi) - sorted.get(lo)) * (pos - lo);
    }

    static Map<String, Object> http(List<Map<String, Object>> txns) {
        List<Double> totals = new ArrayList<>();
        int failed = 0;
        for (Map<String, Object> x : txns) {
            if (failed(x)) failed++;
            Double t = dn(x.get("total"));
            if (t != null) totals.add(t);
        }
        Collections.sort(totals);
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("requests", txns.size()); h.put("ok", txns.size() - failed); h.put("failed", failed);
        h.put("avg_total", totals.isEmpty() ? null : totals.stream().mapToDouble(Double::doubleValue).average().orElse(0));
        h.put("p50_total", percentile(totals, 0.5)); h.put("p95_total", percentile(totals, 0.95));
        h.put("max_total", totals.isEmpty() ? null : totals.get(totals.size() - 1));
        return h;
    }

    static Map<String, Object> tcp(List<Map<String, Object>> conns) {
        long hs = 0, resets = 0, retr = 0;
        double connect = 0, rtt = 0;
        int nc = 0, nr = 0;
        for (Map<String, Object> c : conns) {
            if (Boolean.TRUE.equals(c.get("handshake_seen"))) hs++;
            if ("RST".equals(c.get("close_type"))) resets++;
            retr += (Long) c.get("retransmissions");
            if (c.get("connect_time") != null) { connect += d(c.get("connect_time")); nc++; }
            if (c.get("rtt_server") != null) { rtt += d(c.get("rtt_server")); nr++; }
        }
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("connections", conns.size()); t.put("handshakes", hs); t.put("resets", resets); t.put("retransmissions", retr);
        t.put("avg_connect", nc == 0 ? null : connect / nc); t.put("avg_rtt_server", nr == 0 ? null : rtt / nr);
        return t;
    }

    static List<Map<String, Object>> counts(List<Map<String, Object>> conns, String key, String name) {
        Map<String, Integer> n = new TreeMap<>();
        for (Map<String, Object> c : conns) if (c.get(key) != null) n.merge(String.valueOf(c.get(key)), 1, Integer::sum);
        List<Map<String, Object>> out = new ArrayList<>();
        n.entrySet().stream().sorted((a, z) -> z.getValue() - a.getValue()).forEach(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put(name, e.getKey()); m.put("connections", e.getValue());
            out.add(m);
        });
        return out;
    }

    static List<Map<String, Object>> budget(List<Map<String, Object>> txns) {
        Map<String, Double> sum = new LinkedHashMap<>();
        for (String name : PHASES) sum.put(name, 0.0);
        for (Map<String, Object> x : txns) {
            if (!Boolean.TRUE.equals(x.get("answered"))) continue;
            @SuppressWarnings("unchecked") Map<String, Double> p = (Map<String, Double>) x.get("phases");
            p.forEach((k, v) -> sum.merge(k, v, Double::sum));
        }
        List<Map<String, Object>> out = new ArrayList<>();
        sum.forEach((k, v) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("name", k); m.put("seconds", v); out.add(m); });
        return out;
    }

    static List<Map<String, Object>> slowest(List<Map<String, Object>> txns, Map<Integer, Map<String, Object>> connOf) {
        return slowest(txns, connOf, SLOWEST);
    }

    /** Notes about the capture itself that change how its numbers read. */
    static List<String> warnings(Builder b, List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        List<String> w = new ArrayList<>();
        if (b.copies > 0) w.add("copies_removed");
        if (b.natViews > 0) w.add("nat_views_removed");
        if (b.truncatedPackets > 0) w.add("frames_truncated");
        if (conns.stream().anyMatch(c -> Boolean.TRUE.equals(c.get("offload")))) w.add("offload_suspected");
        Map<Object, Set<Object>> byId = new HashMap<>();
        for (Map<String, Object> x : txns) if (x.get("request_id") != null) byId.computeIfAbsent(x.get("request_id"), k -> new HashSet<>()).add(x.get("stream"));
        if (byId.values().stream().anyMatch(v -> v.size() > 1)) w.add("same_request_on_two_connections");
        return w;
    }

    static Map<String, Object> quality(Builder b, List<Map<String, Object>> conns) {
        long oneWay = conns.stream().filter(c -> Boolean.TRUE.equals(c.get("one_way"))).count();
        long before = conns.stream().filter(c -> !Boolean.TRUE.equals(c.get("syn_seen"))).count();
        long openEnd = conns.stream().filter(c -> c.get("close_type") == null).count();
        long encrypted = conns.stream().filter(c -> Boolean.TRUE.equals(c.get("tls_seen")) && ((Number) c.get("requests")).intValue() == 0).count();
        double n = Math.max(conns.size(), 1);
        List<Map<String, Object>> found = new ArrayList<>();
        String level = "high";
        if (encrypted > 0) level = add(found, level, "encrypted", encrypted, encrypted == conns.size() ? "low" : "medium");
        if (b.copies > 0) level = add(found, level, "copies", b.copies, "info");
        long unseen = b.events.stream().filter(e -> "ack_lost_segment".equals(e.get("event"))).count();
        if (unseen > 0) level = add(found, level, "unseen", unseen, (double) unseen / Math.max(b.tcp, 1) > LOST_SHARE_HIGH ? "low" : "medium");
        if (b.truncatedPackets > 0) level = add(found, level, "snapped", b.truncatedPackets, "medium");
        if (oneWay > 0) level = add(found, level, "one_way", oneWay, oneWay / n > MOST ? "low" : "medium");
        if (before > 0) level = add(found, level, "started_before", before, before / n > MOST ? "medium" : "info");
        if (openEnd > 0) level = add(found, level, "open_at_end", openEnd, "info");
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("level", level); q.put("findings", found);
        return q;
    }

    private static String add(List<Map<String, Object>> found, String level, String key, long n, String sev) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("key", key); f.put("n", n); f.put("level", sev);
        found.add(f);
        if (sev.equals("low")) return "low";
        if (sev.equals("medium") && !level.equals("low")) return "medium";
        return level;
    }

    // ---- charts and grids

    static Map<String, Object> timeline(Builder b, List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (txns.isEmpty()) { out.put("start", null); out.put("width", null); out.put("rows", new ArrayList<>()); return out; }
        double lo = Double.MAX_VALUE, hi = -Double.MAX_VALUE;
        for (Map<String, Object> x : txns) {
            lo = Math.min(lo, d(x.get("req_start")));
            hi = Math.max(hi, x.get("resp_end") != null ? d(x.get("resp_end")) : d(x.get("req_end")));
        }
        double length = Math.max(hi - lo, 0.001);
        double width = BUCKETS_S[BUCKETS_S.length - 1];
        for (double w : BUCKETS_S) if (length / w <= CHART_POINTS) { width = w; break; }
        int count = (int) (length / width) + 1;
        int[] req = new int[count], err = new int[count], lost = new int[count];
        List<List<Double>> totals = new ArrayList<>();
        for (int i = 0; i < count; i++) totals.add(new ArrayList<>());
        for (Map<String, Object> x : txns) {
            int slot = Math.min(count - 1, (int) ((d(x.get("req_start")) - lo) / width));
            req[slot]++;
            if (error(x)) err[slot]++;
            if (x.get("total") != null) totals.get(slot).add(d(x.get("total")));
        }
        for (Map<String, Object> e : b.events) {
            String ev = (String) e.get("event");
            if (!ev.equals("retransmission") && !ev.equals("fast_retransmission")) continue;
            int slot = (int) ((d(e.get("time")) - lo) / width);
            if (slot >= 0 && slot < count) lost[slot]++;
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            double start = lo + i * width;
            long open = 0;
            for (Map<String, Object> c : conns) if (d(c.get("start_time")) < start + width && d(c.get("end_time")) >= start) open++;
            List<Double> t = totals.get(i);
            Collections.sort(t);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("start", start); r.put("requests", req[i]); r.put("errors", err[i]); r.put("p95_total", percentile(t, 0.95));
            r.put("retransmissions", lost[i]); r.put("open_connections", open);
            rows.add(r);
        }
        out.put("start", lo); out.put("width", width); out.put("rows", rows);
        return out;
    }

    static List<Map<String, Object>> statuses(List<Map<String, Object>> txns) {
        Map<String, Integer> n = new TreeMap<>();
        for (Map<String, Object> x : txns) {
            Integer st = statusOf(x);
            n.merge(st == null ? "none" : (st / 100) + "xx", 1, Integer::sum);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        n.forEach((k, v) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("class", k); m.put("requests", v); out.add(m); });
        return out;
    }

    static List<Map<String, Object>> histogram(List<Map<String, Object>> txns) {
        double[] edges = {0, .001, .005, .01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60};
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < edges.length; i++) {
            double lo = edges[i];
            Double hi = i + 1 < edges.length ? edges[i + 1] : null;
            int n = 0;
            for (Map<String, Object> x : txns) {
                Double t = dn(x.get("total"));
                if (t != null && t >= lo && (hi == null || t < hi)) n++;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("label", hi != null ? num(lo) + "-" + num(hi) + " s" : ">" + num(lo) + " s");
            m.put("requests", n);
            out.add(m);
        }
        return out;
    }

    private static String num(double v) { return v == Math.rint(v) ? String.valueOf((long) v) : String.valueOf(v); }

    static List<Map<String, Object>> urls(List<Map<String, Object>> txns) {
        Map<String, List<Map<String, Object>>> by = new LinkedHashMap<>();
        for (Map<String, Object> x : txns) by.computeIfAbsent(x.get("method") + " " + x.get("url_template"), k -> new ArrayList<>()).add(x);
        List<Map<String, Object>> out = new ArrayList<>();
        for (List<Map<String, Object>> g : by.values()) {
            List<Double> totals = new ArrayList<>();
            double service = 0;
            int ns = 0, failed = 0;
            Map<String, Integer> st = new TreeMap<>();
            for (Map<String, Object> x : g) {
                if (failed(x)) failed++;
                Double t = dn(x.get("total"));
                if (t != null) totals.add(t);
                if (x.get("service") != null) { service += d(x.get("service")); ns++; }
                st.merge(x.get("status") == null ? "" : String.valueOf(x.get("status")), 1, Integer::sum);
            }
            Collections.sort(totals);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("method", g.get(0).get("method")); m.put("url", g.get(0).get("url_template"));
            m.put("requests", g.size()); m.put("failed", failed);
            m.put("avg_total", totals.isEmpty() ? null : totals.stream().mapToDouble(Double::doubleValue).average().orElse(0));
            m.put("p95_total", percentile(totals, 0.95)); m.put("max_total", totals.isEmpty() ? null : totals.get(totals.size() - 1));
            m.put("avg_service", ns == 0 ? null : service / ns);
            List<Map<String, Object>> codes = new ArrayList<>();
            st.forEach((k, v) -> { Map<String, Object> c = new LinkedHashMap<>(); c.put("status", k.isEmpty() ? null : Integer.valueOf(k)); c.put("requests", v); codes.add(c); });
            m.put("statuses", codes);
            out.add(m);
        }
        out.sort(Comparator.comparingDouble((Map<String, Object> m) -> -d(m.get("p95_total"))));
        return out;
    }

    static List<Map<String, Object>> connectionRows(List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        Map<Integer, List<Double>> totals = new HashMap<>();
        for (Map<String, Object> x : txns) if (x.get("total") != null) totals.computeIfAbsent(streamOf(x), k -> new ArrayList<>()).add(d(x.get("total")));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : conns) {
            Map<String, Object> m = new LinkedHashMap<>(c);
            List<Double> t = totals.getOrDefault(c.get("stream"), List.of());
            m.put("avg_total", t.isEmpty() ? null : t.stream().mapToDouble(Double::doubleValue).average().orElse(0));
            m.put("max_total", t.isEmpty() ? null : Collections.max(t));
            out.add(m);
        }
        return out;
    }

    // ---- hosts, servers and issues

    static String hostName(Map<String, Object> conn, List<Map<String, Object>> txns) {
        for (Map<String, Object> x : txns) {
            if (x.get("host") != null) {
                String h = x.get("host").toString();
                int colon = h.lastIndexOf(':');
                return colon > 0 && h.indexOf(':') == colon ? h.substring(0, colon) : h;
            }
        }
        return conn.get("sni") != null ? (String) conn.get("sni") : (String) conn.get("server_ip");
    }

    static List<Map<String, Object>> hosts(List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        Map<Integer, List<Map<String, Object>>> by = new HashMap<>();
        for (Map<String, Object> x : txns) by.computeIfAbsent(streamOf(x), k -> new ArrayList<>()).add(x);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        Map<String, TreeSet<String>> addr = new HashMap<>();
        for (Map<String, Object> c : conns) {
            String h = hostName(c, by.getOrDefault(c.get("stream"), List.of()));
            Map<String, Object> m = out.computeIfAbsent(h, k -> { Map<String, Object> n = new LinkedHashMap<>(); n.put("host", k); n.put("connections", 0L); n.put("requests", 0L); n.put("bytes", 0L); return n; });
            m.put("connections", (Long) m.get("connections") + 1);
            m.put("requests", (Long) m.get("requests") + by.getOrDefault(c.get("stream"), List.of()).size());
            m.put("bytes", (Long) m.get("bytes") + (Long) c.get("bytes"));
            addr.computeIfAbsent(h, k -> new TreeSet<>()).add((String) c.get("server_ip"));
        }
        out.forEach((h, m) -> m.put("addresses", new ArrayList<>(addr.get(h))));
        List<Map<String, Object>> rows = new ArrayList<>(out.values());
        rows.sort((a, z) -> Long.compare((Long) z.get("bytes"), (Long) a.get("bytes")));
        return rows;
    }

    static List<Map<String, Object>> backends(List<Map<String, Object>> conns, List<Map<String, Object>> txns) {
        Map<Integer, Map<String, Object>> connOf = new HashMap<>();
        for (Map<String, Object> c : conns) connOf.put((Integer) c.get("stream"), c);
        Map<String, List<Map<String, Object>>> by = new LinkedHashMap<>();
        for (Map<String, Object> x : txns) {
            Map<String, Object> c = connOf.get(streamOf(x));
            by.computeIfAbsent(c.get("server_ip") + "\u0000" + c.get("server_port"), k -> new ArrayList<>()).add(x);
        }
        List<Map<String, Object>> got = new ArrayList<>();
        for (var e : by.entrySet()) {
            List<Map<String, Object>> g = e.getValue();
            Map<String, Object> c0 = connOf.get((Integer) g.get(0).get("stream"));
            Set<Object> streams = new HashSet<>(), resetStreams = new HashSet<>();
            List<Double> totals = new ArrayList<>(), services = new ArrayList<>();
            int failed = 0;
            for (Map<String, Object> x : g) {
                streams.add(x.get("stream"));
                if ("RST".equals(connOf.get(x.get("stream")).get("close_type"))) resetStreams.add(x.get("stream"));
                if (error(x)) failed++;
                if (x.get("total") != null) totals.add(d(x.get("total")));
                if (x.get("service") != null) services.add(d(x.get("service")));
            }
            long retr = 0;
            for (Object s : streams) retr += (Long) connOf.get(s).get("retransmissions");
            Collections.sort(totals); Collections.sort(services);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("server_ip", c0.get("server_ip")); m.put("server_port", c0.get("server_port"));
            m.put("connections", streams.size()); m.put("requests", g.size()); m.put("failed", failed);
            m.put("p50_total", percentile(totals, 0.5)); m.put("p95_total", percentile(totals, 0.95)); m.put("p50_service", percentile(services, 0.5));
            m.put("resets", resetStreams.size()); m.put("retransmissions", retr);
            m.put("error_share", (double) failed / g.size()); m.put("flag", null);
            got.add(m);
        }
        got.sort(Comparator.comparingDouble((Map<String, Object> m) -> -d(m.get("p50_total"))));
        for (Map<String, Object> r : got) {
            List<Map<String, Object>> peers = new ArrayList<>();
            for (Map<String, Object> x : got) if (Objects.equals(x.get("server_port"), r.get("server_port")) && (Integer) x.get("requests") >= 5) peers.add(x);
            if (!peers.contains(r) || peers.size() < 2) continue;
            Double usual = median(peers, "p50_total", r), usualErr = median(peers, "error_share", r);
            if (usualErr != null && d(r.get("error_share")) - usualErr > 0.2) r.put("flag", "errors");
            else if (usual != null && r.get("p50_total") != null && d(r.get("p50_total")) > 2.0 * usual && d(r.get("p50_total")) - usual >= SLOW_S) r.put("flag", "slow");
        }
        return got;
    }

    private static Double median(List<Map<String, Object>> rows, String key, Map<String, Object> except) {
        List<Double> v = new ArrayList<>();
        for (Map<String, Object> r : rows) if (r != except && r.get(key) != null) v.add(d(r.get(key)));
        Collections.sort(v);
        return percentile(v, 0.5);
    }

    private record Rule(String key, int severity, boolean onRequests, java.util.function.Predicate<Map<String, Object>> test) {}

    static List<Map<String, Object>> issues(Builder b, List<Map<String, Object>> conns, List<Map<String, Object>> txns, Map<Integer, Map<String, Object>> connOf,
                                            List<Map<String, Object>> backs) {
        List<Rule> rules = List.of(
                new Rule("no_response", 1, true, x -> !Boolean.TRUE.equals(x.get("answered"))),
                new Rule("resets", 1, false, c -> "RST".equals(c.get("close_type"))),
                new Rule("no_handshake", 1, false, c -> !Boolean.TRUE.equals(c.get("handshake_seen")) && (Integer) c.get("transactions") == 0 && (Integer) c.get("packets") <= 3),
                new Rule("gateway", 1, true, x -> statusOf(x) != null && (statusOf(x) == 502 || statusOf(x) == 503 || statusOf(x) == 504)),
                new Rule("server_errors", 1, true, x -> statusOf(x) != null && statusOf(x) >= 500 && statusOf(x) != 502 && statusOf(x) != 503 && statusOf(x) != 504),
                new Rule("grpc_errors", 1, true, x -> x.get("grpc_status") instanceof Number n && n.intValue() > 0),
                new Rule("tls_no_answer", 1, false, c -> Boolean.TRUE.equals(c.get("tls_no_answer"))),
                new Rule("tls_alerts", 2, false, c -> c.get("tls_alert") != null),
                new Rule("truncated", 1, true, x -> Boolean.TRUE.equals(x.get("truncated"))),
                new Rule("loss", 2, true, x -> "loss".equals(x.get("cause"))),
                new Rule("slow_client", 2, true, x -> d(x.get("zero_window_time")) > 0),
                new Rule("retried", 2, true, x -> x.get("retry_of") != null),
                new Rule("delayed_ack", 3, true, x -> d(x.get("delayed_ack_time")) > 0),
                new Rule("queueing", 3, true, x -> d(x.get("queue_time")) > 0),
                new Rule("small_mss", 3, false, c -> c.get("mss") instanceof Number n && n.intValue() < 1200),
                new Rule("slow_service", 2, true, x -> "service".equals(x.get("cause"))),
                new Rule("retrans", 2, false, c -> (Long) c.get("retransmissions") > 0),
                new Rule("network", 3, true, x -> "network".equals(x.get("cause"))));
        List<Map<String, Object>> found = new ArrayList<>();
        for (Rule r : rules) {
            List<Map<String, Object>> hit = new ArrayList<>();
            for (Map<String, Object> o : r.onRequests() ? txns : conns) if (r.test().test(o)) hit.add(o);
            if (hit.isEmpty()) continue;
            found.add(issue(r.key(), r.severity(), hit.size(), true));
            Map<String, Object> detail = new LinkedHashMap<>();
            if (r.onRequests()) {
                detail.put("transactions", slowest(hit, connOf, 200));
                detail.put("connections", new ArrayList<>());
            } else {
                detail.put("transactions", new ArrayList<>());
                detail.put("connections", new ArrayList<>(hit.subList(0, Math.min(200, hit.size()))));
            }
            DETAIL.get().put(r.key(), detail);
        }
        long slow = backs.stream().filter(bk -> bk.get("flag") != null).count();
        if (slow > 0) found.add(issue("slow_backend", 2, slow, false));
        long slowDns = b.dnsTimes.stream().filter(dd -> dd[0] > 0.1).count();
        if (slowDns > 0) found.add(issue("slow_dns", 3, slowDns, false));
        if (b.fragNeeded > 0) found.add(issue("frag_needed", 2, b.fragNeeded, false));
        if (b.fragments > 0) found.add(issue("ip_fragments", 3, b.fragments, false));
        long drops = b.events.stream().filter(e -> "ack_lost_segment".equals(e.get("event"))).count();
        if (drops > 0) found.add(issue("capture_drops", 1, drops, false));
        String[][] packetRules = {{"malformed", "2", "malformed"}, {"icmp_unreachable", "2", "icmp_unreachable"}, {"dns_errors", "2", "dns_error"}, {"tcp_flags_invalid", "2", "tcp_flags_invalid"},
                {"port_reused", "2", "port_reused"}, {"ecn_congestion", "3", "ecn_congestion"}, {"sack_blocks", "3", "sack_blocks"},
                {"h2_flow_stall", "2", "h2_flow_stall"}, {"h2_reset", "2", "h2_reset"}, {"h2_goaway", "2", "h2_goaway"}, {"tls_no_client_cert", "2", "tls_no_client_cert"}};
        for (String[] pr : packetRules) {
            List<Object[]> hit = new ArrayList<>();
            for (Object[] pi : b.packetIssues) if (pr[2].equals(pi[2])) hit.add(pi);
            if (hit.isEmpty()) continue;
            found.add(issue(pr[0], Integer.parseInt(pr[1]), hit.size(), true));
            Map<String, Integer> det = new LinkedHashMap<>(), pairs = new LinkedHashMap<>();
            for (Object[] pi : hit) { det.merge(String.valueOf(pi[3]), 1, Integer::sum); pairs.merge(pi[4] + "\u0000" + pi[5], 1, Integer::sum); }
            Map<String, Object> detail = new LinkedHashMap<>();
            List<Map<String, Object>> dl = new ArrayList<>(), pl = new ArrayList<>(), packets = new ArrayList<>();
            det.entrySet().stream().sorted((x, y) -> y.getValue() - x.getValue()).limit(50).forEach(e -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("detail", e.getKey().equals("null") ? null : e.getKey()); m.put("n", e.getValue()); dl.add(m); });
            pairs.entrySet().stream().sorted((x, y) -> y.getValue() - x.getValue()).limit(20).forEach(e -> { String[] k = e.getKey().split("\u0000", -1); Map<String, Object> m = new LinkedHashMap<>(); m.put("src", k[0].equals("null") ? null : k[0]); m.put("dst", k[1].equals("null") ? null : k[1]); m.put("n", e.getValue()); pl.add(m); });
            hit.stream().sorted(Comparator.comparingInt(pi -> (Integer) pi[0])).limit(200).forEach(pi -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("frame", pi[0]); m.put("time", pi[1]); m.put("src", pi[4]); m.put("dst", pi[5]); m.put("detail", pi[3]); packets.add(m); });
            detail.put("transactions", new ArrayList<>()); detail.put("connections", new ArrayList<>()); detail.put("details", dl); detail.put("pairs", pl); detail.put("packets", packets);
            DETAIL.get().put(pr[0], detail);
        }
        found.sort(Comparator.comparingInt((Map<String, Object> f) -> (Integer) f.get("severity")).thenComparingLong(f -> -((Number) f.get("count")).longValue()));
        return found;
    }

    private static Map<String, Object> issue(String key, int severity, long count, boolean drill) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", key); m.put("severity", severity); m.put("count", count); m.put("drill", drill);
        return m;
    }

    static List<Map<String, Object>> slowest(List<Map<String, Object>> txns, Map<Integer, Map<String, Object>> connOf, int limit) {
        List<Map<String, Object>> sorted = new ArrayList<>(txns);
        sorted.sort(Comparator.comparingDouble((Map<String, Object> x) -> -d(x.get("longest"))));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> x : sorted.subList(0, Math.min(limit, sorted.size()))) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", x.get("id")); m.put("method", x.get("method")); m.put("uri", x.get("uri")); m.put("status", x.get("status"));
            m.put("cause", x.get("cause")); m.put("longest", x.get("longest")); m.put("phases", x.get("phases"));
            m.put("facts", facts(x, connOf.get(streamOf(x))));
            out.add(m);
        }
        return out;
    }

    /** What the handshakes show. None of this needs a key, so it also works on traffic that stays encrypted. */
    static Map<String, Object> tls(List<Map<String, Object>> conns) {
        record Key(String version, String cipher, String alpn) {}
        Map<Key, double[]> groups = new LinkedHashMap<>(); // count, resumed, handshake sum, handshake n
        List<Map<String, Object>> problems = new ArrayList<>();
        Map<String, Map<String, Object>> certs = new TreeMap<>();
        long[] mtls = new long[2];
        for (Map<String, Object> c : conns) {
            boolean seen = c.get("tls_version") != null || Boolean.TRUE.equals(c.get("tls_no_answer")) || c.get("tls_alert") != null;
            if (!seen) continue;
            Key k = new Key(str(c.get("tls_version"), "-"), str(c.get("tls_cipher"), "-"), str(c.get("tls_alpn"), "-"));
            double[] g = groups.computeIfAbsent(k, x -> new double[4]);
            g[0]++;
            if (Boolean.TRUE.equals(c.get("tls_resumed"))) g[1]++;
            if (c.get("tls_time") != null) { g[2] += d(c.get("tls_time")); g[3]++; }
            if ((Boolean.TRUE.equals(c.get("tls_no_answer")) || c.get("tls_alert") != null) && problems.size() < 200) {
                Map<String, Object> p = new LinkedHashMap<>();
                for (String f : new String[] {"stream", "client", "server", "sni", "tls_alert", "tls_no_answer"}) p.put(f, c.get(f));
                problems.add(p);
            }
            if (Boolean.TRUE.equals(c.get("tls_client_cert_requested"))) {
                mtls[0]++;
                if (c.get("tls_client_certs") != null && ((Number) c.get("tls_client_certs")).intValue() > 0) mtls[1]++;
            }
            if (c.get("tls_cert_expires") != null) {
                String name = c.get("sni") != null ? (String) c.get("sni") : (String) c.get("server_ip");
                Map<String, Object> m = certs.computeIfAbsent(c.get("tls_cert_expires") + "\u0000" + name, x -> {
                    Map<String, Object> n = new LinkedHashMap<>(); n.put("name", name); n.put("expires", c.get("tls_cert_expires")); n.put("chain", c.get("tls_chain")); n.put("connections", 0); return n; });
                m.put("connections", (Integer) m.get("connections") + 1);
            }
        }
        List<Map<String, Object>> versions = new ArrayList<>();
        groups.forEach((k, g) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("version", k.version()); m.put("cipher", k.cipher()); m.put("alpn", k.alpn()); m.put("connections", (long) g[0]); m.put("resumed", (long) g[1]);
            m.put("avg_handshake", g[3] == 0 ? null : g[2] / g[3]);
            versions.add(m);
        });
        versions.sort((a, z) -> Long.compare((Long) z.get("connections"), (Long) a.get("connections")));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("versions", versions); out.put("problems", problems); out.put("certificates", new ArrayList<>(certs.values())); out.put("client_cert_requested", mtls[0]); out.put("client_cert_sent", mtls[1]);
        return out;
    }

    private static String str(Object o, String dflt) { return o == null ? dflt : o.toString(); }
}
