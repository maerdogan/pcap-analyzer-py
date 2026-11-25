package io.pcapanalyzer;

import java.nio.file.Path;
import java.util.*;

/**
 * Bir TCP baglantisinin paketleri, Wireshark paket listesindeki gibi: zaman, yon, bayraklar, sira ve onay numaralari,
 * uzunluk, pencere, protokol, bilgi ve TCP isaretleri. Python surumundeki stats.packets ve stats.request_packets ile ayni isi yapar.
 */
public final class Packets {
    /** Bir listede gosterilen en fazla paket sayisi. */
    public static final int ROWS = 5000;

    /** TCP bayraklari, insanlarin okudugu sirada (SYN, ACK, ...). */
    static final Object[][] FLAGS = {{0x02, "SYN"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x01, "FIN"}, {0x04, "RST"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"}};
    /** Her bayragin anlami; metinler bilgi dosyasindaki cevirilerle eslesir. */
    static final Map<String, String> MEANINGS = Map.of(
            "SYN", "opens a connection", "ACK", "acknowledges data received", "PSH", "hands the data to the application at once",
            "FIN", "ends sending, a normal close", "RST", "breaks the connection off at once", "URG", "marks urgent data",
            "ECE", "reports congestion on the path", "CWR", "the sender slowed down after congestion");

    static final List<String> FIELDS = List.of("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport", "tcp.flags", "tcp.seq", "tcp.ack", "tcp.len",
            "tcp.window_size", "_ws.col.protocol", "_ws.col.info", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
            "tcp.analysis.out_of_order", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
            "tcp.analysis.zero_window", "tcp.analysis.window_full", "tcp.analysis.keep_alive");
    /** TCP isaret alanlari (FIELDS icinde 12. siradan baslar) ve ekranda gorunen adlari. */
    static final String[] MARKS = {"retransmission", "fast retransmission", "out of order", "duplicate ACK", "previous segment not captured",
            "ACKed unseen segment", "zero window", "window full", "keep-alive"};
    private static final int FIRST_MARK = 12;

    private Packets() {}

    /** Bayrak degerindeki (ornek 0x0012) bayraklarin adlari. */
    static List<String> flagNames(String value) {
        int bits = 0;
        if (value != null && !value.isBlank()) {
            String v = value.strip();
            try { bits = v.startsWith("0x") || v.startsWith("0X") ? Integer.parseInt(v.substring(2), 16) : Integer.parseInt(v); }
            catch (NumberFormatException ignored) { bits = 0; }
        }
        List<String> out = new ArrayList<>();
        for (Object[] f : FLAGS) if ((bits & (Integer) f[0]) != 0) out.add((String) f[1]);
        return out;
    }

    private static String last(String v) {
        if (v == null || v.isEmpty()) return "";
        int i = v.lastIndexOf(',');
        return i < 0 ? v : v.substring(i + 1);
    }

    private static Long num(String v) {
        if (v == null || v.isBlank()) return null;
        try { return Long.parseLong(v.strip()); } catch (NumberFormatException e) { return null; }
    }

    private static Double dbl(String v) {
        if (v == null || v.isBlank()) return null;
        try { return Double.parseDouble(v.strip()); } catch (NumberFormatException e) { return null; }
    }

    private static List<Map<String, Object>> legend(List<Map<String, Object>> rows) {
        Set<String> seen = new HashSet<>();
        for (Map<String, Object> r : rows) for (Object f : (List<?>) r.get("flags")) seen.add((String) f);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object[] f : FLAGS) {
            String name = (String) f[1];
            if (!seen.contains(name)) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("flag", name); m.put("meaning", MEANINGS.get(name));
            out.add(m);
        }
        return out;
    }

    /** Bir TCP baglantisinin tum paketleri, yakalama sirasinda, en fazla ROWS tane. Zamanlar ilk paketten itibaren saniyedir. */
    public static Map<String, Object> connection(TShark ts, Path capture, int stream) throws TShark.TsharkException {
        List<Map<String, Object>> rows = new ArrayList<>();
        String client = null;
        for (String[] p : ts.query(capture, "tcp.stream == " + stream, FIELDS, ROWS + 1, 120)) {
            if (p.length < FIELDS.size()) continue;
            Double t = dbl(p[1]);
            if (t == null) continue;
            String ip = last(p[2]).isEmpty() ? last(p[3]) : last(p[2]);
            String side = ip + ":" + p[4];
            if (client == null) client = side;
            Map<String, Object> r = new LinkedHashMap<>();
            Long frame = num(p[0]);
            r.put("frame", frame == null ? 0L : frame);
            r.put("t", t);
            r.put("from_client", side.equals(client));
            r.put("flags", flagNames(p[5]));
            r.put("seq", num(p[6]));
            r.put("ack", num(p[7]));
            Long len = num(p[8]);
            r.put("len", len == null ? 0L : len);
            r.put("win", num(p[9]));
            r.put("protocol", p[10]);
            String info = Optional.ofNullable(Privacy.maskUri(p[11])).orElse("");
            r.put("info", info.length() > 300 ? info.substring(0, 300) : info);
            List<String> marks = new ArrayList<>();
            for (int i = 0; i < MARKS.length; i++) if (!p[FIRST_MARK + i].isEmpty()) marks.add(MARKS[i]);
            r.put("marks", marks);
            rows.add(r);
        }
        boolean cut = rows.size() > ROWS;
        if (cut) rows = new ArrayList<>(rows.subList(0, ROWS));
        double start = rows.isEmpty() ? 0 : (Double) rows.get(0).get("t");
        for (Map<String, Object> r : rows) r.put("t", (Double) r.get("t") - start);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rows", rows); out.put("cut", cut); out.put("limit", ROWS); out.put("legend", legend(rows)); out.put("start", start);
        return out;
    }

    /**
     * Bir HTTP isteginin paketleri: istek baglantiyi actiysa el sikismadan, yoksa kendi ilk paketinden baslar;
     * yanitin son paketine ve istemcinin onu onaylamasina kadar gider.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> request(TShark ts, Path capture, Map<String, Object> t) throws TShark.TsharkException {
        Map<String, Object> whole = connection(ts, capture, ((Number) t.get("stream")).intValue());
        List<Map<String, Object>> rows = (List<Map<String, Object>>) whole.get("rows");
        Map<String, Object> out = new LinkedHashMap<>(whole);
        if (rows.isEmpty()) { out.put("rows", List.of()); out.put("legend", List.of()); return out; }
        double start = (Double) whole.get("start");
        Object endValue = t.get("resp_end") != null ? t.get("resp_end") : t.get("req_end") != null ? t.get("req_end") : t.get("req_start");
        double end = endValue == null ? Double.MAX_VALUE : ((Number) endValue).doubleValue();
        int first;
        if (Boolean.TRUE.equals(t.get("new_conn"))) first = 0;
        else {
            long reqFrame = t.get("req_frame") == null ? 0 : ((Number) t.get("req_frame")).longValue();
            first = rows.size();
            for (int i = 0; i < rows.size(); i++) if (((Number) rows.get(i).get("frame")).longValue() >= reqFrame) { first = i; break; }
        }
        int lastRow = first;
        for (int i = first; i < rows.size(); i++) {
            if (start + (Double) rows.get(i).get("t") <= end + 1e-6) lastRow = i;
            else break;
        }
        // Istemcinin yalin onayi (veri tasimayan ACK) alisverisi kapatir
        if (lastRow + 1 < rows.size()) {
            Map<String, Object> next = rows.get(lastRow + 1);
            if (Boolean.TRUE.equals(next.get("from_client")) && List.of("ACK").equals(next.get("flags")) && ((Number) next.get("len")).longValue() == 0) lastRow++;
        }
        List<Map<String, Object>> picked = new ArrayList<>();
        if (first < rows.size()) for (Map<String, Object> r : rows.subList(first, lastRow + 1)) picked.add(new LinkedHashMap<>(r));
        double t0 = picked.isEmpty() ? 0 : (Double) picked.get(0).get("t");
        for (Map<String, Object> r : picked) r.put("t", (Double) r.get("t") - t0);
        out.put("rows", picked);
        out.put("cut", Boolean.TRUE.equals(whole.get("cut")) && lastRow + 1 >= rows.size());
        out.put("legend", legend(picked));
        out.put("start", start + t0);
        return out;
    }
}
