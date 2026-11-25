package io.pcapanalyzer;

import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Wireshark-style views of one capture, read again from the kept file: hierarchy, lengths, endpoints, conversations and the IO graph. */
public final class Stats {
    static final int MAX_PACKETS = 2_000_000;
    static final long[] EDGES = {0, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120};
    private static final Pattern PHS = Pattern.compile("^(\\s*)(\\S+)\\s+frames:(\\d+)\\s+bytes:(\\d+)");

    private Stats() {}

    static List<Map<String, Object>> hierarchy(TShark ts, Path capture) throws TShark.TsharkException {
        List<Map<String, Object>> out = new ArrayList<>();
        long total = 0, totalBytes = 0;
        for (String line : ts.statsText(capture, "io,phs", 120).split("\n")) {
            Matcher m = PHS.matcher(line);
            if (!m.find()) continue;
            Map<String, Object> r = new LinkedHashMap<>();
            long frames = Long.parseLong(m.group(3)), bytes = Long.parseLong(m.group(4));
            if (out.isEmpty()) { total = frames; totalBytes = bytes; }
            r.put("protocol", m.group(2)); r.put("depth", m.group(1).length() / 2); r.put("packets", frames); r.put("bytes", bytes);
            r.put("share", total == 0 ? 0.0 : (double) frames / total); r.put("byte_share", totalBytes == 0 ? 0.0 : (double) bytes / totalBytes);
            out.add(r);
        }
        return out;
    }

    private static class Ep { long frames, bytes, sent, received; }
    private static class Conv { long frames, bytes, aToB, bToA; double first = Double.MAX_VALUE, last; }

    /** One pass over the packets gives lengths, IP endpoints and UDP conversations. */
    public static Map<String, Object> overview(TShark ts, Path capture) throws TShark.TsharkException {
        List<String> fields = List.of("frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport");
        List<String[]> rows = ts.query(capture, null, fields, MAX_PACKETS, 300);
        long[] binPackets = new long[EDGES.length], binBytes = new long[EDGES.length];
        Map<String, Ep> ips = new HashMap<>();
        Map<String, Conv> udp = new HashMap<>();
        for (String[] r : rows) {
            if (r.length < 8 || r[1].isEmpty()) continue;
            long len = Long.parseLong(r[1]);
            int bin = 0;
            for (int i = 0; i < EDGES.length; i++) if (len >= EDGES[i]) bin = i;
            binPackets[bin]++; binBytes[bin] += len;
            String src = r[2].isEmpty() ? r[4] : r[2], dst = r[3].isEmpty() ? r[5] : r[3];
            if (!src.isEmpty()) { Ep e = ips.computeIfAbsent(src, k -> new Ep()); e.frames++; e.bytes += len; e.sent += len; }
            if (!dst.isEmpty()) { Ep e = ips.computeIfAbsent(dst, k -> new Ep()); e.frames++; e.bytes += len; e.received += len; }
            if (!r[6].isEmpty() && !src.isEmpty() && !dst.isEmpty()) {
                String a = src + ":" + r[6], b = dst + ":" + r[7];
                boolean swap = a.compareTo(b) > 0;
                String key = swap ? b + "\u0000" + a : a + "\u0000" + b;
                Conv c = udp.computeIfAbsent(key, k -> new Conv());
                double t = r[0].isEmpty() ? 0 : Double.parseDouble(r[0]);
                c.frames++; c.bytes += len; c.first = Math.min(c.first, t); c.last = Math.max(c.last, t);
                if (swap) c.bToA += len; else c.aToB += len;
            }
        }
        List<Map<String, Object>> sizes = new ArrayList<>();
        for (int i = 0; i < EDGES.length; i++) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bin", i + 1 < EDGES.length ? EDGES[i] + "-" + (EDGES[i + 1] - 1) : EDGES[i] + "+");
            m.put("packets", binPackets[i]); m.put("bytes", binBytes[i]);
            sizes.add(m);
        }
        List<Map<String, Object>> ipRows = new ArrayList<>();
        ips.entrySet().stream().sorted((x, y) -> Long.compare(y.getValue().bytes, x.getValue().bytes)).limit(200).forEach(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", e.getKey()); if (GeoIp.available()) { m.put("country", GeoIp.country(e.getKey())); m.put("asn", GeoIp.asn(e.getKey())); } m.put("frames", e.getValue().frames); m.put("bytes", e.getValue().bytes); m.put("sent", e.getValue().sent); m.put("received", e.getValue().received);
            ipRows.add(m);
        });
        List<Map<String, Object>> udpRows = new ArrayList<>();
        udp.entrySet().stream().sorted((x, y) -> Long.compare(y.getValue().bytes, x.getValue().bytes)).limit(200).forEach(e -> {
            String[] ab = e.getKey().split("\u0000");
            Conv c = e.getValue();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("a", ab[0]); m.put("b", ab[1]); m.put("frames", c.frames); m.put("bytes", c.bytes); m.put("a_to_b", c.aToB); m.put("b_to_a", c.bToA); m.put("duration", c.last - c.first);
            udpRows.add(m);
        });
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("packets", (long) rows.size()); out.put("geoip", GeoIp.available()); out.put("sizes", sizes); out.put("ips", ipRows); out.put("udp", udpRows);
        return out;
    }

    /** Packets and bits per second over time, for the packets that match a display filter. */
    public static Map<String, Object> io(TShark ts, Path capture, String filter) throws TShark.TsharkException {
        List<String[]> rows = ts.query(capture, filter, List.of("frame.time_epoch", "frame.len"), MAX_PACKETS, 300);
        double t0 = Double.MAX_VALUE, t1 = 0;
        for (String[] r : rows) if (r.length >= 2 && !r[0].isEmpty()) { double t = Double.parseDouble(r[0]); t0 = Math.min(t0, t); t1 = Math.max(t1, t); }
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> list = new ArrayList<>();
        if (rows.isEmpty()) { out.put("step", 1.0); out.put("rows", list); return out; }
        double[] steps = {0.001, 0.01, 0.1, 1, 10, 60, 600};
        double step = steps[steps.length - 1];
        for (double s : steps) if ((t1 - t0) / s <= 200) { step = s; break; }
        int n = (int) ((t1 - t0) / step) + 1;
        long[] packets = new long[n], bytes = new long[n];
        for (String[] r : rows) {
            if (r.length < 2 || r[0].isEmpty()) continue;
            int slot = Math.min(n - 1, (int) ((Double.parseDouble(r[0]) - t0) / step));
            packets[slot]++; bytes[slot] += r[1].isEmpty() ? 0 : Long.parseLong(r[1]);
        }
        for (int i = 0; i < n; i++) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", i * step); m.put("packets", packets[i]); m.put("bps", bytes[i] * 8 / step);
            list.add(m);
        }
        out.put("step", step); out.put("rows", list);
        return out;
    }

    /** Requests and responses per server, with each server's share. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> httpLoad(Map<String, Object> result) {
        Map<String, long[]> by = new LinkedHashMap<>();
        Map<String, String> host = new HashMap<>();
        long total = 0;
        for (Map<String, Object> x : (List<Map<String, Object>>) result.get("transactions")) {
            String server = String.valueOf(x.get("server"));
            long[] c = by.computeIfAbsent(server, k -> new long[2]);
            c[0]++; total++;
            if (Boolean.TRUE.equals(x.get("answered"))) c[1]++;
            if (x.get("host") != null) host.putIfAbsent(server, x.get("host").toString());
        }
        List<Map<String, Object>> out = new ArrayList<>();
        final long all = total;
        by.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0])).forEach(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("server", e.getKey()); m.put("host", host.get(e.getKey())); m.put("requests", e.getValue()[0]); m.put("responses", e.getValue()[1]); m.put("share", all == 0 ? 0.0 : (double) e.getValue()[0] / all);
            out.add(m);
        });
        return out;
    }
}
