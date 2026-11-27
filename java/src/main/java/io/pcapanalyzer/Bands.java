package io.pcapanalyzer;

import java.util.*;

/**
 * For each service (method and URL template) two groups of requests are cut out of the sorted response times and compared:
 * the group around the percentile that the mean of p50 and p90 falls on (typical-slow, that percentile +-2), and the fast group, p12.5 to p15.
 * The tails are left out on purpose: a handful of the slowest requests out of thousands says little about the service.
 */
final class Bands {
    static final int MIN_REQUESTS = 20, EXAMPLES = 5, MAX_SERVICES = 8;
    static final double SPREAD = 2, FAST_FROM = 12.5, FAST_TO = 15;

    private Bands() {}

    /** The comparison of every service with enough requests, the busiest first. */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> of(Map<String, Object> result) {
        Map<String, List<Map<String, Object>>> by = new LinkedHashMap<>();
        if (result.get("transactions") instanceof List<?> l)
            for (Object o : l)
                if (o instanceof Map<?, ?> m && Boolean.TRUE.equals(m.get("answered")) && Analysis.d(m.get("total")) > 0)
                    by.computeIfAbsent(m.get("method") + " " + m.get("url_template"), k -> new ArrayList<>()).add((Map<String, Object>) m);
        List<Map.Entry<String, List<Map<String, Object>>>> order = new ArrayList<>(by.entrySet());
        order.sort((a, b) -> b.getValue().size() - a.getValue().size());
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> e : order.subList(0, Math.min(MAX_SERVICES, order.size()))) out.add(service(e.getKey(), e.getValue()));
        return out;
    }

    static double quantile(double[] sorted, double p) {
        if (sorted.length == 0) return 0;
        double pos = p / 100 * (sorted.length - 1);
        int lo = (int) Math.floor(pos), hi = (int) Math.ceil(pos);
        return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
    }

    private static double r(double v) { return Math.round(v * 10000) / 10000.0; }

    static Map<String, Object> service(String name, List<Map<String, Object>> xs) {
        List<Map<String, Object>> sorted = new ArrayList<>(xs);
        sorted.sort(Comparator.comparingDouble(x -> Analysis.d(x.get("total"))));
        int n = sorted.size();
        double[] t = sorted.stream().mapToDouble(x -> Analysis.d(x.get("total"))).toArray();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("service", name);
        out.put("requests", n);
        out.put("p50_s", r(quantile(t, 50))); out.put("p90_s", r(quantile(t, 90)));
        if (n < MIN_REQUESTS) { out.put("note", "Too few requests for the two groups."); return out; }
        double target = (quantile(t, 50) + quantile(t, 90)) / 2;
        long atOrBelow = Arrays.stream(t).filter(v -> v <= target).count();
        double pt = 100.0 * atOrBelow / n;
        out.put("middle_s", r(target)); out.put("middle_percentile", Math.round(pt * 10) / 10.0);
        List<Map<String, Object>> a = new ArrayList<>(), b = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            double rank = 100.0 * (i + 1) / n;
            if (Math.abs(rank - pt) <= SPREAD) a.add(sorted.get(i));
            if (rank >= FAST_FROM && rank <= FAST_TO) b.add(sorted.get(i));
        }
        Map<String, Object> ga = group(a, "p" + Math.round((pt - SPREAD) * 10) / 10.0 + "-p" + Math.round((pt + SPREAD) * 10) / 10.0), gb = group(b, "p12.5-p15");
        out.put("typical_slow", ga);
        out.put("fast", gb);
        if (!a.isEmpty() && !b.isEmpty()) {
            Map<String, Object> diff = new LinkedHashMap<>();
            Map<String, Double> pa = (Map<String, Double>) ga.get("phase_median_s"), pb = (Map<String, Double>) gb.get("phase_median_s");
            double gap = Analysis.d(ga.get("total_median_s")) - Analysis.d(gb.get("total_median_s"));
            for (String ph : pa.keySet()) {
                double d = pa.get(ph) - pb.getOrDefault(ph, 0.0);
                if (Math.abs(d) >= 0.0005) diff.put(ph, Map.of("added_s", r(d), "share_of_gap_pct", gap > 0 ? Math.round(d / gap * 100) : 0));
            }
            out.put("phase_differences", diff);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> group(List<Map<String, Object>> g, String range) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("range", range);
        o.put("requests", g.size());
        if (g.isEmpty()) return o;
        o.put("total_median_s", r(median(g.stream().mapToDouble(x -> Analysis.d(x.get("total"))).toArray())));
        Map<String, Double> phases = new LinkedHashMap<>();
        for (String ph : Analysis.PHASES) {
            double m = median(g.stream().mapToDouble(x -> x.get("phases") instanceof Map<?, ?> p ? Analysis.d(p.get(ph)) : 0).toArray());
            if (m > 0) phases.put(ph, r(m));
        }
        o.put("phase_median_s", phases);
        o.put("request_bytes_median", Math.round(median(g.stream().mapToDouble(x -> Analysis.d(x.get("req_bytes"))).toArray())));
        o.put("response_bytes_median", Math.round(median(g.stream().mapToDouble(x -> Analysis.d(x.get("resp_bytes"))).toArray())));
        o.put("new_connection", g.stream().filter(x -> x.get("connect_time") != null).count());
        Map<String, Integer> clients = new HashMap<>(), causes = new HashMap<>();
        for (Map<String, Object> x : g) { clients.merge(String.valueOf(x.get("client")), 1, Integer::sum); causes.merge(String.valueOf(x.get("cause")), 1, Integer::sum); }
        o.put("clients", top(clients, 3));
        o.put("causes", top(causes, 3));
        List<Object> ex = new ArrayList<>();
        for (int i = 0; i < Math.min(EXAMPLES, g.size()); i++) {
            Map<String, Object> x = g.get(EXAMPLES >= g.size() ? i : (int) ((long) i * (g.size() - 1) / (EXAMPLES - 1)));
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("start", x.get("req_start")); e.put("client", x.get("client")); e.put("total_s", r(Analysis.d(x.get("total")))); e.put("status", x.get("status"));
            if (x.get("phases") instanceof Map<?, ?> p) { Map<String, Object> pp = new LinkedHashMap<>(); for (String ph : Analysis.PHASES) if (Analysis.d(p.get(ph)) >= 0.0005) pp.put(ph, r(Analysis.d(p.get(ph)))); e.put("phases_s", pp); }
            ex.add(e);
        }
        o.put("examples", ex);
        return o;
    }

    private static Map<String, Integer> top(Map<String, Integer> m, int k) {
        Map<String, Integer> out = new LinkedHashMap<>();
        m.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(k).forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    private static double median(double[] v) {
        double[] s = v.clone();
        Arrays.sort(s);
        return quantile(s, 50);
    }
}
