package io.pcapanalyzer;

import java.util.*;
import java.util.stream.Collectors;

/** Compares two analyses, and matches the same requests seen at two points. */
public final class Compare {
    static final int MIN_SAMPLE = 5;
    static final double MATCH_WINDOW_S = 5.0, NEGLIGIBLE_S = 0.001;
    static final String[] PHASE_AVG = {"network", "queue_time", "service", "transfer_clean", "retrans_time", "zero_window_time", "delayed_ack_time"};

    private Compare() {}

    static Double delta(Double a, Double b) { return a != null && b != null ? b - a : null; }
    static Double pct(Double a, Double b) { return a != null && a != 0 && b != null ? (b - a) / a * 100 : null; }
    static Double dn(Object o) { return Analysis.dn(o); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> row(String key, String label, Object a, Object b, boolean time) {
        Map<String, Object> m = new LinkedHashMap<>();
        Double x = dn(a), y = dn(b);
        m.put("key", key); m.put("label", label); m.put("a", x); m.put("b", y); m.put("delta", delta(x, y)); m.put("percent", pct(x, y)); m.put("is_time", time);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Double> averageStats(List<Map<String, Object>> txns) {
        double wait = 0, service = 0, transfer = 0;
        int n = 0, ns = 0;
        for (Map<String, Object> x : txns) {
            if (x.get("wait") != null) { wait += Analysis.d(x.get("wait")); n++; }
            if (x.get("service") != null) { service += Analysis.d(x.get("service")); ns++; }
            if (x.get("transfer") != null) transfer += Analysis.d(x.get("transfer"));
        }
        Map<String, Double> m = new HashMap<>();
        m.put("avg_wait", n == 0 ? null : wait / n); m.put("avg_service", ns == 0 ? null : service / ns); m.put("avg_transfer", n == 0 ? null : transfer / n);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Double> phaseAverages(Map<String, Object> inspected, List<Map<String, Object>> txns) {
        Map<String, Double> sum = new HashMap<>();
        int n = 0;
        for (Map<String, Object> x : txns) {
            Map<String, Object> ph = (Map<String, Object>) x.get("phases");
            if (ph == null) continue;
            n++;
            for (String p : PHASE_AVG) sum.merge(p, Analysis.d(ph.get(p)), Double::sum);
        }
        Map<String, Double> out = new HashMap<>();
        for (String p : PHASE_AVG) out.put(p, n == 0 ? null : sum.getOrDefault(p, 0.0) / n);
        return out;
    }

    /** The transactions of an analysis that the filter lets through. */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> filtered(Map<String, Object> result, Inspect.Query q) {
        Set<Integer> streams = new HashSet<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) result.get("connections")) if (Inspect.connMatches(q, c)) streams.add(((Number) c.get("stream")).intValue());
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) {
            if (!streams.contains(((Number) x.get("stream")).intValue())) continue;
            if (q.url() != null && !String.valueOf(x.get("uri")).toLowerCase().contains(q.url().toLowerCase())) continue;
            out.add(x);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> captures(Pages.Ctx c, Map<String, Object> ra, Map<String, Object> rb, Inspect.Query fa, Inspect.Query fb) {
        Map<String, Object> a = Inspect.run(fa, ra), b = Inspect.run(fb, rb);
        Map<String, Object> qa = (Map<String, Object>) a.get("requests"), qb = (Map<String, Object>) b.get("requests");
        Map<String, Double> sa = averageStats(filtered(ra, fa)), sb = averageStats(filtered(rb, fb));
        List<Map<String, Object>> summary = new ArrayList<>();
        String[][] keys = {{"requests", "Requests"}, {"failed", "Failed"}, {"avg_total", "Average"}, {"p50_total", "Median"}, {"p95_total", "95th percentile"}, {"max_total", "Slowest"}};
        for (String[] k : keys) summary.add(row(k[0], c.t(k[1]), qa.get(k[0]), qb.get(k[0]), !k[0].equals("requests") && !k[0].equals("failed")));
        summary.add(row("avg_wait", c.t("Average server wait"), sa.get("avg_wait"), sb.get("avg_wait"), true));
        summary.add(row("avg_service", c.t("Average service"), sa.get("avg_service"), sb.get("avg_service"), true));
        summary.add(row("avg_transfer", c.t("Average transfer"), sa.get("avg_transfer"), sb.get("avg_transfer"), true));
        Map<String, Object> ca = (Map<String, Object>) a.get("connections"), cb = (Map<String, Object>) b.get("connections");
        summary.add(row("connections", c.t("TCP connections"), ca.get("connections"), cb.get("connections"), false));
        summary.add(row("avg_connect", c.t("Average connect"), ca.get("avg_connect"), cb.get("avg_connect"), true));
        summary.add(row("avg_rtt", c.t("Average round trip"), ca.get("avg_rtt"), cb.get("avg_rtt"), true));
        Map<String, Map<String, Object>> ua = new HashMap<>(), ub = new HashMap<>();
        for (Map<String, Object> u : (List<Map<String, Object>>) a.get("urls")) ua.put(u.get("method") + " " + u.get("url"), u);
        for (Map<String, Object> u : (List<Map<String, Object>>) b.get("urls")) ub.put(u.get("method") + " " + u.get("url"), u);
        List<Map<String, Object>> urls = new ArrayList<>();
        for (String k : new TreeSet<>(union(ua.keySet(), ub.keySet()))) {
            Map<String, Object> x = ua.get(k), y = ub.get(k);
            Map<String, Object> r = new LinkedHashMap<>();
            Map<String, Object> any = x != null ? x : y;
            r.put("method", any.get("method")); r.put("url", any.get("url"));
            r.put("requests_a", x == null ? null : x.get("requests")); r.put("requests_b", y == null ? null : y.get("requests"));
            r.put("failed_a", x == null ? null : x.get("failed")); r.put("failed_b", y == null ? null : y.get("failed"));
            r.put("avg_a", x == null ? null : x.get("avg_total")); r.put("avg_b", y == null ? null : y.get("avg_total"));
            r.put("only_in", y == null ? "A" : x == null ? "B" : null);
            r.put("delta", delta(dn(r.get("avg_a")), dn(r.get("avg_b"))));
            r.put("few", Math.min(x == null ? 0 : ((Number) x.get("requests")).intValue(), y == null ? 0 : ((Number) y.get("requests")).intValue()) < MIN_SAMPLE);
            urls.add(r);
        }
        urls.sort(Comparator.comparingDouble((Map<String, Object> r) -> r.get("delta") == null ? -1 : -Math.abs(Analysis.d(r.get("delta")))));
        Map<String, Double> pa = phaseAverages(a, filtered(ra, fa)), pb = phaseAverages(b, filtered(rb, fb));
        List<Map<String, Object>> phases = new ArrayList<>();
        for (String p : PHASE_AVG) { Map<String, Object> m = row(p, Knowledge.phaseLabel(p, c.lang()), pa.get(p), pb.get(p), true); phases.add(m); }
        List<String> notes = new ArrayList<>();
        String cpa = mainPoint(ra), cpb = mainPoint(rb);
        if (cpa != null && cpb != null && !cpa.equals(cpb))
            notes.add(c.t("The captures were taken at different points ({a} and {b}), so network time differs by nature.", "a", point(c, cpa), "b", point(c, cpb)));
        if (((Number) qa.get("requests")).intValue() < MIN_SAMPLE || ((Number) qb.get("requests")).intValue() < MIN_SAMPLE) notes.add(c.t("One side has fewer than {n} requests, so averages can mislead.", "n", MIN_SAMPLE));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("summary", summary); out.put("urls", urls); out.put("phases", phases); out.put("slowest_a", a.get("slowest")); out.put("slowest_b", b.get("slowest")); out.put("notes", notes);
        return out;
    }

    private static Set<String> union(Set<String> a, Set<String> b) { Set<String> u = new HashSet<>(a); u.addAll(b); return u; }

    private static String point(Pages.Ctx c, String name) { String s = name.replace('_', ' '); return c.t(Character.toUpperCase(s.charAt(0)) + s.substring(1)); }

    @SuppressWarnings("unchecked")
    private static String mainPoint(Map<String, Object> result) {
        Map<String, Integer> n = new HashMap<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) result.get("connections")) {
            String p = (String) c.get("capture_point");
            if (p != null && !p.equals("unknown")) n.merge(p, 1, Integer::sum);
        }
        return n.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
    }

    // ---- two points

    static double median(List<Double> v) {
        List<Double> s = new ArrayList<>(v);
        Collections.sort(s);
        return s.get(s.size() / 2) * (s.size() % 2 == 1 ? 1 : 0) + (s.size() % 2 == 0 ? (s.get(s.size() / 2 - 1) + s.get(s.size() / 2)) / 2 : 0);
    }

    private static Map<String, Double> spread(List<Double> values) {
        List<Double> v = values.stream().filter(Objects::nonNull).sorted().collect(Collectors.toList());
        Map<String, Double> m = new HashMap<>();
        m.put("median", v.isEmpty() ? null : median(v)); m.put("p95", Analysis.percentile(v, 0.95));
        return m;
    }

    private static double startGap(List<Map<String, Object>[]> pairs) {
        if (pairs.isEmpty()) return 0;
        return median(pairs.stream().map(p -> Analysis.d(p[0].get("req_start")) - Analysis.d(p[1].get("req_start"))).collect(Collectors.toList()));
    }

    /** Pair requests with the same method, URL and status, closest start first. Returns the pairs; unclear[0] counts those with more than one candidate. */
    private static List<Map<String, Object>[]> likely(List<Map<String, Object>> aRows, List<Map<String, Object>> bRows, Set<Object> taken, Set<Object> used0, double gap, int[] unclear) {
        Set<Object> used = new HashSet<>(used0);
        List<Map<String, Object>[]> pairs = new ArrayList<>();
        Map<String, List<Map<String, Object>>> groups = new HashMap<>();
        for (Map<String, Object> b : bRows) groups.computeIfAbsent(b.get("method") + "\u0000" + b.get("uri") + "\u0000" + b.get("status"), k -> new ArrayList<>()).add(b);
        unclear[0] = 0;
        for (Map<String, Object> a : aRows) {
            String key = a.get("method") + "\u0000" + a.get("uri") + "\u0000" + a.get("status");
            if (taken.contains(a.get("id")) || !groups.containsKey(key)) continue;
            double want = Analysis.d(a.get("req_start")) - gap;
            List<Map<String, Object>> options = new ArrayList<>();
            for (Map<String, Object> b : groups.get(key))
                if (!used.contains(b.get("id")) && Math.abs(Analysis.d(b.get("req_start")) + gap - Analysis.d(a.get("req_start"))) <= MATCH_WINDOW_S && Math.abs(Analysis.d(b.get("req_start")) - want) <= 2 * MATCH_WINDOW_S) options.add(b);
            if (options.isEmpty()) continue;
            options.sort(Comparator.comparingDouble(b -> Math.abs(Analysis.d(b.get("req_start")) + gap - Analysis.d(a.get("req_start")))));
            @SuppressWarnings("unchecked") Map<String, Object>[] pair = new Map[] {a, options.get(0)};
            pairs.add(pair);
            used.add(options.get(0).get("id"));
            if (options.size() > 1) unclear[0]++;
        }
        return pairs;
    }

    private static double clockSkew(List<Map<String, Object>[]> pairs) {
        double fwd = Double.MAX_VALUE, back = Double.MAX_VALUE;
        boolean haveBack = false;
        for (Map<String, Object>[] p : pairs) {
            fwd = Math.min(fwd, Analysis.d(p[1].get("req_start")) - Analysis.d(p[0].get("req_start")));
            if (p[0].get("resp_start") != null && p[1].get("resp_start") != null) { back = Math.min(back, Analysis.d(p[0].get("resp_start")) - Analysis.d(p[1].get("resp_start"))); haveBack = true; }
        }
        return !pairs.isEmpty() && haveBack ? (fwd - back) / 2 : 0.0;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> twoPoint(Map<String, Object> ra, Map<String, Object> rb) {
        List<Map<String, Object>> aRows = new ArrayList<>((List<Map<String, Object>>) ra.get("transactions")), bRows = new ArrayList<>((List<Map<String, Object>>) rb.get("transactions"));
        Comparator<Map<String, Object>> byStart = Comparator.comparingDouble(x -> Analysis.d(x.get("req_start")));
        aRows.sort(byStart); bRows.sort(byStart);
        Map<Object, Map<String, Object>> byId = new HashMap<>();
        for (Map<String, Object> b : bRows) if (b.get("request_id") != null) byId.putIfAbsent(b.get("request_id"), b);
        List<Map<String, Object>[]> exact = new ArrayList<>();
        Set<Object> used = new HashSet<>(), taken = new HashSet<>();
        for (Map<String, Object> a : aRows) {
            Map<String, Object> b = a.get("request_id") == null ? null : byId.get(a.get("request_id"));
            if (b != null && !used.contains(b.get("id"))) { exact.add(new Map[] {a, b}); used.add(b.get("id")); taken.add(a.get("id")); }
        }
        int[] unclear = new int[1];
        List<Map<String, Object>[]> likely = likely(aRows, bRows, taken, used, startGap(exact), unclear);
        if (!likely.isEmpty() && exact.isEmpty()) likely = likely(aRows, bRows, taken, used, startGap(likely), unclear);
        double skew = clockSkew(exact.isEmpty() ? likely : exact);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (int kind = 0; kind < 2; kind++) {
            for (Map<String, Object>[] p : kind == 0 ? exact : likely) {
                Map<String, Object> a = p[0], b = p[1];
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("match", kind == 0 ? "exact" : "likely"); r.put("method", a.get("method")); r.put("uri", a.get("uri")); r.put("url", a.get("url_template")); r.put("status", a.get("status"));
                r.put("id_a", a.get("id")); r.put("id_b", b.get("id")); r.put("total_a", a.get("total")); r.put("total_b", b.get("total")); r.put("service_b", b.get("service"));
                r.put("added", delta(dn(b.get("total")), dn(a.get("total"))));
                r.put("forward", Analysis.d(b.get("req_start")) - Analysis.d(a.get("req_start")) - skew);
                r.put("back", a.get("resp_start") != null && b.get("resp_start") != null ? Analysis.d(a.get("resp_start")) - Analysis.d(b.get("resp_start")) + skew : null);
                rows.add(r);
            }
        }
        rows.sort(Comparator.comparingDouble((Map<String, Object> r) -> r.get("added") == null ? 1 : -Analysis.d(r.get("added"))));
        int matched = exact.size() + likely.size();
        double rate = aRows.isEmpty() ? 0 : (double) matched / aRows.size();
        String confidence = rate < 0.5 || (matched > 0 && exact.isEmpty() && (double) unclear[0] / matched > 0.3) ? "low" : rate >= 0.8 && exact.size() >= 0.9 * matched ? "high" : "medium";
        Map<String, Double> added = spread(rows.stream().map(r -> dn(r.get("added"))).collect(Collectors.toList()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rows", rows); out.put("urls", byUrl(rows)); out.put("clock_skew", skew); out.put("exact", exact.size()); out.put("likely", likely.size()); out.put("unclear", unclear[0]);
        out.put("match_rate", rate); out.put("confidence", confidence); out.put("added", added.get("median")); out.put("added_p95", added.get("p95"));
        out.put("service", spread(rows.stream().map(r -> dn(r.get("service_b"))).collect(Collectors.toList())).get("median"));
        out.put("reversed", added.get("median") != null && added.get("median") < -NEGLIGIBLE_S);
        out.put("unmatched_a", aRows.size() - rows.size()); out.put("unmatched_b", bRows.size() - rows.size());
        return out;
    }

    private static List<Map<String, Object>> byUrl(List<Map<String, Object>> rows) {
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        for (Map<String, Object> r : rows) groups.computeIfAbsent(r.get("method") + "\u0000" + r.get("url"), k -> new ArrayList<>()).add(r);
        List<Map<String, Object>> out = new ArrayList<>();
        for (List<Map<String, Object>> g : groups.values()) {
            Map<String, Double> added = spread(g.stream().map(r -> dn(r.get("added"))).collect(Collectors.toList()));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("method", g.get(0).get("method")); m.put("url", g.get(0).get("url")); m.put("requests", g.size());
            m.put("added", added.get("median")); m.put("added_p95", added.get("p95"));
            m.put("service", spread(g.stream().map(r -> dn(r.get("service_b"))).collect(Collectors.toList())).get("median"));
            m.put("total", spread(g.stream().map(r -> dn(r.get("total_a"))).collect(Collectors.toList())).get("median"));
            out.add(m);
        }
        out.sort(Comparator.comparingDouble((Map<String, Object> m) -> m.get("added_p95") == null ? 1 : -Analysis.d(m.get("added_p95"))));
        return out;
    }
}
