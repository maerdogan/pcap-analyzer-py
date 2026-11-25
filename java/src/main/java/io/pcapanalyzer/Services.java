package io.pcapanalyzer;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/** Service response times of protocols other than HTTP, SIP calls with their RTP streams, and QUIC connections, read again from the kept capture. */
public final class Services {
    static final int SLOWEST = 20, TOP = 200;
    static final List<String> ADDRESS = List.of("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.stream", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport");
    static final Map<String, List<String>> PROTOCOL_FIELDS = new LinkedHashMap<>();
    static {
        PROTOCOL_FIELDS.put("LDAP", List.of("ldap.protocolOp", "ldap.messageID", "ldap.resultCode", "ldap.bindResponse_resultCode"));
        PROTOCOL_FIELDS.put("Kerberos", List.of("kerberos.msg_type", "kerberos.error_code"));
        PROTOCOL_FIELDS.put("SMB2", List.of("smb2.cmd", "smb2.time", "smb2.nt_status", "smb2.flags.response"));
        PROTOCOL_FIELDS.put("Kafka", List.of("kafka.api_key", "kafka.correlation_id", "kafka.request_frame", "kafka.error"));
        PROTOCOL_FIELDS.put("SMTP", List.of("smtp.req.command", "smtp.response.code"));
        PROTOCOL_FIELDS.put("DCERPC", List.of("dcerpc.pkt_type", "dcerpc.opnum", "dcerpc.cn_call_id", "dcerpc.cn_status"));
        PROTOCOL_FIELDS.put("MQTT", List.of("mqtt.msgtype", "mqtt.msgid", "mqtt.conack.val"));
        PROTOCOL_FIELDS.put("AMQP", List.of("amqp.channel", "amqp.method.class", "amqp.method.method", "amqp.method.arguments.reply_code"));
        PROTOCOL_FIELDS.put("FTP", List.of("ftp.request.command", "ftp.response.code"));
    }
    static final String DISPLAY = "ldap or kerberos or smb2 or kafka or smtp or dcerpc or mqtt or amqp or ftp";
    static final Map<Integer, String> LDAP_OPS = Map.of(0, "bind", 3, "search", 6, "modify", 8, "add", 10, "delete", 12, "modify DN", 14, "compare", 23, "extended");
    static final Map<Integer, Integer> LDAP_DONE = Map.of(1, 0, 5, 3, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 24, 23);
    static final Set<Integer> LDAP_NOT_ERRORS = Set.of(0, 5, 6, 10, 14);
    static final Map<Integer, String> KERBEROS = Map.of(10, "AS-REQ", 12, "TGS-REQ");
    static final Set<Integer> KERBEROS_ANSWERS = Set.of(11, 13, 30);
    static final Map<Integer, String> SMB2 = Map.ofEntries(Map.entry(0, "NEGOTIATE"), Map.entry(1, "SESSION_SETUP"), Map.entry(2, "LOGOFF"), Map.entry(3, "TREE_CONNECT"), Map.entry(4, "TREE_DISCONNECT"),
            Map.entry(5, "CREATE"), Map.entry(6, "CLOSE"), Map.entry(7, "FLUSH"), Map.entry(8, "READ"), Map.entry(9, "WRITE"), Map.entry(10, "LOCK"), Map.entry(11, "IOCTL"), Map.entry(12, "CANCEL"),
            Map.entry(13, "ECHO"), Map.entry(14, "QUERY_DIRECTORY"), Map.entry(15, "CHANGE_NOTIFY"), Map.entry(16, "QUERY_INFO"), Map.entry(17, "SET_INFO"), Map.entry(18, "OPLOCK_BREAK"));
    static final Set<Long> SMB2_NOT_ERRORS = Set.of(0L, 0x103L, 0xC0000016L, 0x80000005L, 0x80000006L);
    static final Map<Integer, String> KAFKA = Map.ofEntries(Map.entry(0, "Produce"), Map.entry(1, "Fetch"), Map.entry(2, "ListOffsets"), Map.entry(3, "Metadata"), Map.entry(8, "OffsetCommit"),
            Map.entry(9, "OffsetFetch"), Map.entry(10, "FindCoordinator"), Map.entry(11, "JoinGroup"), Map.entry(12, "Heartbeat"), Map.entry(13, "LeaveGroup"), Map.entry(14, "SyncGroup"),
            Map.entry(15, "DescribeGroups"), Map.entry(16, "ListGroups"), Map.entry(17, "SaslHandshake"), Map.entry(18, "ApiVersions"), Map.entry(19, "CreateTopics"), Map.entry(22, "InitProducerId"), Map.entry(36, "SaslAuthenticate"));
    static final Map<Integer, Object[]> MQTT = Map.of(1, new Object[] {"CONNECT", 2}, 3, new Object[] {"PUBLISH", 4}, 6, new Object[] {"PUBREL", 7}, 8, new Object[] {"SUBSCRIBE", 9},
            10, new Object[] {"UNSUBSCRIBE", 11}, 12, new Object[] {"PINGREQ", 13});
    static final Map<Integer, String> AMQP = Map.of(10, "connection", 20, "channel", 40, "exchange", 50, "queue", 60, "basic", 85, "confirm", 90, "tx");

    private Services() {}

    // ---- helpers

    static Integer toInt(String v) {
        if (v == null || v.isEmpty()) return null;
        try { return v.startsWith("0x") ? (int) Long.parseLong(v.substring(2), 16) : Integer.valueOf(v); } catch (NumberFormatException e) { return null; }
    }

    static Long toLong(String v) {
        if (v == null || v.isEmpty()) return null;
        try { return v.startsWith("0x") ? Long.parseLong(v.substring(2), 16) : Long.valueOf(v); } catch (NumberFormatException e) { return null; }
    }

    static List<String> many(String v) { return v == null || v.isEmpty() ? new ArrayList<>() : new ArrayList<>(Arrays.asList(v.split(String.valueOf(TShark.AGG), -1))); }
    static String first(String v) { List<String> l = many(v); return l.isEmpty() || l.get(0).isEmpty() ? null : l.get(0); }
    static String last(String v) { List<String> l = many(v); return l.isEmpty() ? null : l.get(l.size() - 1); }
    static String get(Map<String, String> p, String k) { return p.getOrDefault(k, ""); }

    static String[] ends(Map<String, String> p) {
        String src = Optional.ofNullable(last(get(p, "ip.src"))).filter(x -> !x.isEmpty()).orElse(last(get(p, "ipv6.src")));
        String dst = Optional.ofNullable(last(get(p, "ip.dst"))).filter(x -> !x.isEmpty()).orElse(last(get(p, "ipv6.dst")));
        String sp, dp;
        if (!get(p, "tcp.srcport").isEmpty()) { sp = get(p, "tcp.srcport"); dp = get(p, "tcp.dstport"); } else { sp = last(get(p, "udp.srcport")); dp = last(get(p, "udp.dstport")); }
        return new String[] {src + ":" + sp, dst + ":" + dp};
    }

    static List<Map<String, String>> rows(List<String[]> raw, List<String> fields) {
        List<Map<String, String>> out = new ArrayList<>();
        for (String[] r : raw) {
            Map<String, String> m = new HashMap<>();
            for (int i = 0; i < fields.size(); i++) m.put(fields.get(i), i < r.length ? r[i] : "");
            out.add(m);
        }
        return out;
    }

    static String at(List<String> l, int i) { return i < l.size() ? l.get(i) : ""; }

    // ---- exchanges

    static final class Ex {
        final Map<Object, ArrayDeque<Object[]>> pending = new HashMap<>();
        final List<Map<String, Object>> done = new ArrayList<>();

        void ask(Object key, int frame, double t, String op, String client, String server) {
            pending.computeIfAbsent(key, k -> new ArrayDeque<>()).add(new Object[] {frame, t, op, client, server});
        }

        void answer(Object key, double t, String error, String op) {
            ArrayDeque<Object[]> q = pending.get(key);
            if (q == null || q.isEmpty()) return;
            Object[] w = q.poll();
            done.add(row((Integer) w[0], (Double) w[1], Math.max(t - (Double) w[1], 0.0), op != null ? op : (String) w[2], (String) w[3], (String) w[4], error));
        }

        void answer(Object key, double t, String error) { answer(key, t, error, null); }

        List<Map<String, Object>> unanswered() {
            List<Map<String, Object>> out = new ArrayList<>();
            for (ArrayDeque<Object[]> q : pending.values()) for (Object[] w : q) out.add(row((Integer) w[0], (Double) w[1], null, (String) w[2], (String) w[3], (String) w[4], null));
            return out;
        }
    }

    static Map<String, Object> row(int frame, double start, Double time, String op, String client, String server, String error) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("frame", frame); m.put("start", start); m.put("time", time); m.put("op", op); m.put("client", client); m.put("server", server); m.put("error", error);
        return m;
    }

    static List<Object> key(Object... parts) { return Arrays.asList(parts); }

    static void collect(Map<String, Ex> x, Map<String, String> p) {
        Double t = Builder.toDouble(get(p, "frame.time_epoch"));
        if (t == null) return;
        int frame = Integer.parseInt(get(p, "frame.number"));
        String[] ab = ends(p);
        String a = ab[0], b = ab[1];
        List<String> conn = new ArrayList<>(List.of(a, b));
        Collections.sort(conn);
        for (String name : PROTOCOL_FIELDS.keySet()) {
            Ex e = x.computeIfAbsent(name, k -> new Ex());
            switch (name) {
                case "LDAP" -> {
                    List<String> codes = many(get(p, "ldap.resultCode"));
                    if (codes.isEmpty()) codes = many(get(p, "ldap.bindResponse_resultCode"));
                    List<String> ops = many(get(p, "ldap.protocolOp")), ids = many(get(p, "ldap.messageID"));
                    for (int i = 0; i < Math.min(ops.size(), ids.size()); i++) {
                        Integer op = toInt(ops.get(i)), mid = toInt(ids.get(i));
                        if (op != null && LDAP_OPS.containsKey(op)) e.ask(key(conn, mid), frame, t, LDAP_OPS.get(op), a, b);
                        else if (op != null && LDAP_DONE.containsKey(op)) { Integer code = toInt(at(codes, i)); e.answer(key(conn, mid), t, code == null || LDAP_NOT_ERRORS.contains(code) ? null : "resultCode " + code); }
                    }
                }
                case "Kerberos" -> {
                    Integer kind = toInt(first(get(p, "kerberos.msg_type")));
                    if (kind != null && KERBEROS.containsKey(kind)) e.ask(conn, frame, t, KERBEROS.get(kind), a, b);
                    else if (kind != null && KERBEROS_ANSWERS.contains(kind)) e.answer(conn, t, kind == 30 ? "KRB-ERROR " + toInt(first(get(p, "kerberos.error_code"))) : null);
                }
                case "SMB2" -> {
                    List<String> cmds = many(get(p, "smb2.cmd")), times = many(get(p, "smb2.time")), status = many(get(p, "smb2.nt_status")), resp = many(get(p, "smb2.flags.response"));
                    for (int i = 0; i < cmds.size(); i++) {
                        Double took = Builder.toDouble(at(times, i));
                        String r = at(resp, i);
                        if (!(r.equals("1") || r.equals("True")) || took == null) continue;
                        Long st = toLong(at(status, i));
                        Integer cmd = toInt(cmds.get(i));
                        e.done.add(row(frame, t - took, took, SMB2.getOrDefault(cmd, cmds.get(i)), b, a, st == null || SMB2_NOT_ERRORS.contains(st) ? null : String.format("0x%08x", st)));
                    }
                }
                case "Kafka" -> {
                    Integer cid = toInt(first(get(p, "kafka.correlation_id")));
                    if (cid == null) break;
                    Integer api = toInt(first(get(p, "kafka.api_key")));
                    if (!get(p, "kafka.request_frame").isEmpty()) {
                        Integer err = many(get(p, "kafka.error")).stream().map(Services::toInt).filter(v -> v != null && v != 0).findFirst().orElse(null);
                        e.answer(key(conn, cid), t, err != null ? "error " + err : null);
                    } else e.ask(key(conn, cid), frame, t, KAFKA.getOrDefault(api, "API " + api), a, b);
                }
                case "SMTP" -> {
                    for (String cmd : many(get(p, "smtp.req.command"))) e.ask(conn, frame, t, cmd.toUpperCase(), a, b);
                    List<Integer> codes = many(get(p, "smtp.response.code")).stream().map(Services::toInt).filter(v -> v != null && v != 0).collect(Collectors.toList());
                    if (!codes.isEmpty()) e.answer(conn, t, codes.get(codes.size() - 1) >= 400 ? String.valueOf(codes.get(codes.size() - 1)) : null);
                }
                case "DCERPC" -> {
                    List<String> kinds = many(get(p, "dcerpc.pkt_type")), calls = many(get(p, "dcerpc.cn_call_id")), ops = many(get(p, "dcerpc.opnum"));
                    for (int i = 0; i < Math.min(kinds.size(), calls.size()); i++) {
                        Integer kind = toInt(kinds.get(i)), call = toInt(calls.get(i));
                        if (kind != null && kind == 0) e.ask(key(conn, call), frame, t, !at(ops, i).isEmpty() ? "opnum " + at(ops, i) : "call", a, b);
                        else if (kind != null && (kind == 2 || kind == 3)) {
                            Long st = toLong(first(get(p, "dcerpc.cn_status")));
                            e.answer(key(conn, call), t, kind == 3 ? (st != null && st != 0 ? String.format("fault 0x%08x", st) : "fault") : null);
                        }
                    }
                }
                case "MQTT" -> {
                    List<String> kinds = many(get(p, "mqtt.msgtype")), ids = many(get(p, "mqtt.msgid"));
                    Set<Integer> answers = new HashSet<>();
                    for (Object[] v : MQTT.values()) answers.add((Integer) v[1]);
                    for (int i = 0; i < kinds.size(); i++) {
                        Integer kind = toInt(kinds.get(i)), mid = toInt(at(ids, i));
                        if (kind == null) continue;
                        if (MQTT.containsKey(kind) && (kind != 3 || mid != null)) e.ask(key(conn, MQTT.get(kind)[1], kind != 1 && kind != 12 ? mid : null), frame, t, (String) MQTT.get(kind)[0], a, b);
                        else if (kind == 5) e.answer(key(conn, 4, mid), t, null, "PUBLISH");
                        else if (answers.contains(kind)) {
                            Integer code = toInt(first(get(p, "mqtt.conack.val")));
                            e.answer(key(conn, kind, kind != 2 && kind != 13 ? mid : null), t, kind == 2 && code != null && code != 0 ? "CONNACK " + code : null);
                        }
                    }
                }
                case "AMQP" -> {
                    List<String> chs = many(get(p, "amqp.channel")), cls = many(get(p, "amqp.method.class")), methods = many(get(p, "amqp.method.method"));
                    for (int i = 0; i < Math.min(chs.size(), Math.min(cls.size(), methods.size())); i++) {
                        Integer c = toInt(cls.get(i)), m = toInt(methods.get(i));
                        if (c == null || m == null) continue;
                        String nm = AMQP.getOrDefault(c, String.valueOf(c)) + "." + m;
                        List<Object> prev = key(conn, chs.get(i), c, m - 1);
                        if (e.pending.containsKey(prev) && !e.pending.get(prev).isEmpty()) e.answer(prev, t, null);
                        else {
                            e.ask(key(conn, chs.get(i), c, m), frame, t, nm, a, b);
                            Integer code = toInt(first(get(p, "amqp.method.arguments.reply_code")));
                            if (code != null && code != 0 && code != 200) e.done.add(row(frame, t, 0.0, nm, b, a, "reply " + code));
                        }
                    }
                }
                case "FTP" -> {
                    for (String cmd : many(get(p, "ftp.request.command"))) e.ask(conn, frame, t, cmd.toUpperCase(), a, b);
                    List<Integer> codes = many(get(p, "ftp.response.code")).stream().map(Services::toInt).filter(v -> v != null && v != 0).collect(Collectors.toList());
                    if (!codes.isEmpty() && codes.get(codes.size() - 1) >= 200) e.answer(conn, t, codes.get(codes.size() - 1) >= 400 ? String.valueOf(codes.get(codes.size() - 1)) : null);
                }
                default -> { }
            }
        }
    }

    static Map<String, Object> stat(List<Map<String, Object>> rows) {
        List<Double> times = rows.stream().map(r -> (Double) r.get("time")).filter(Objects::nonNull).sorted().collect(Collectors.toList());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requests", rows.size()); m.put("answered", times.size()); m.put("errors", rows.stream().filter(r -> r.get("error") != null).count());
        m.put("avg", times.isEmpty() ? null : times.stream().mapToDouble(Double::doubleValue).average().orElse(0)); m.put("p95", Analysis.percentile(times, 0.95)); m.put("max", times.isEmpty() ? null : times.get(times.size() - 1));
        return m;
    }

    static List<Map<String, Object>> grouped(List<Map<String, Object>> rows, String field, String label) {
        Map<String, List<Map<String, Object>>> g = new LinkedHashMap<>();
        for (Map<String, Object> r : rows) g.computeIfAbsent(String.valueOf(r.get(field)), k -> new ArrayList<>()).add(r);
        List<Map<String, Object>> out = new ArrayList<>();
        g.forEach((k, v) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put(label, k); m.putAll(stat(v)); out.add(m); });
        out.sort((a, b) -> ((Number) b.get("requests")).intValue() - ((Number) a.get("requests")).intValue());
        return out.subList(0, Math.min(TOP, out.size()));
    }

    public static List<Map<String, Object>> responseTimes(TShark ts, Path capture) throws TShark.TsharkException {
        List<String> fields = new ArrayList<>(ADDRESS);
        PROTOCOL_FIELDS.values().forEach(fields::addAll);
        Map<String, Ex> x = new LinkedHashMap<>();
        for (Map<String, String> p : rows(ts.query(capture, DISPLAY, fields, 3_000_000, 600, true, List.of()), fields)) collect(x, p);
        List<Map<String, Object>> out = new ArrayList<>();
        for (String name : PROTOCOL_FIELDS.keySet()) {
            Ex e = x.get(name);
            if (e == null || (e.done.isEmpty() && e.pending.values().stream().allMatch(Collection::isEmpty))) continue;
            List<Map<String, Object>> rows = new ArrayList<>(e.done);
            rows.addAll(e.unanswered());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("protocol", name); m.putAll(stat(rows));
            m.put("operations", grouped(rows, "op", "op")); m.put("servers", grouped(rows, "server", "server"));
            Map<String, Integer> errors = new LinkedHashMap<>();
            for (Map<String, Object> r : e.done) if (r.get("error") != null) errors.merge(r.get("op") + "\u0000" + r.get("error"), 1, Integer::sum);
            List<Map<String, Object>> kinds = new ArrayList<>();
            errors.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(TOP).forEach(en -> {
                String[] k = en.getKey().split("\u0000");
                Map<String, Object> km = new LinkedHashMap<>(); km.put("op", k[0]); km.put("error", k[1]); km.put("count", en.getValue()); kinds.add(km);
            });
            m.put("error_kinds", kinds);
            m.put("slowest", e.done.stream().filter(r -> r.get("time") != null).sorted(Comparator.comparingDouble(r -> -(Double) r.get("time"))).limit(SLOWEST).collect(Collectors.toList()));
            out.add(m);
        }
        return out;
    }

    // ---- SIP and RTP

    static final Map<Integer, Integer> RTP_CLOCK = Map.ofEntries(Map.entry(0, 8000), Map.entry(3, 8000), Map.entry(4, 8000), Map.entry(8, 8000), Map.entry(9, 8000), Map.entry(18, 8000), Map.entry(10, 44100),
            Map.entry(11, 44100), Map.entry(26, 90000), Map.entry(31, 90000), Map.entry(32, 90000), Map.entry(33, 90000), Map.entry(34, 90000));

    public static Map<String, Object> voip(TShark ts, Path capture) throws TShark.TsharkException {
        List<String> sipFields = new ArrayList<>(ADDRESS), rtpFields = new ArrayList<>(ADDRESS);
        sipFields.addAll(List.of("sip.Call-ID", "sip.Method", "sip.Status-Code", "sip.CSeq.method", "sip.from.user", "sip.to.user"));
        rtpFields.addAll(List.of("rtp.ssrc", "rtp.seq", "rtp.timestamp", "rtp.p_type"));
        Map<String, Map<String, Object>> calls = new LinkedHashMap<>();
        for (Map<String, String> p : rows(ts.query(capture, "sip", sipFields, 1_000_000, 300, true, List.of()), sipFields)) sip(calls, p);
        Map<List<String>, Map<String, Object>> streams = new LinkedHashMap<>();
        for (Map<String, String> p : rows(ts.query(capture, "rtp", rtpFields, 3_000_000, 600, true, List.of("-o", "rtp.heuristic_rtp:TRUE")), rtpFields)) rtp(streams, p);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("calls", callRows(calls)); out.put("streams", streamRows(streams));
        return out;
    }

    static void sip(Map<String, Map<String, Object>> calls, Map<String, String> p) {
        Double t = Builder.toDouble(get(p, "frame.time_epoch"));
        String cid = first(get(p, "sip.Call-ID"));
        if (t == null || cid == null) return;
        String[] ab = ends(p);
        String method = first(get(p, "sip.Method")), cseq = first(get(p, "sip.CSeq.method"));
        Integer status = toInt(first(get(p, "sip.Status-Code")));
        Map<String, Object> c = calls.computeIfAbsent(cid, k -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("call_id", cid); m.put("frame", Integer.parseInt(get(p, "frame.number"))); m.put("start", t); m.put("end", t); m.put("from_user", first(get(p, "sip.from.user"))); m.put("to_user", first(get(p, "sip.to.user")));
            m.put("method", method != null ? method : cseq); m.put("messages", 0);
            return m;
        });
        c.put("messages", (Integer) c.get("messages") + 1);
        c.put("end", Math.max(Analysis.d(c.get("end")), t));
        if ("INVITE".equals(method) && c.get("invite") == null) { c.put("invite", t); c.put("caller", ab[0]); c.put("callee", ab[1]); }
        if (status != null && "INVITE".equals(cseq)) {
            if ((status == 180 || status == 183) && c.get("ringing") == null) c.put("ringing", t);
            else if (status >= 200 && c.get("status") == null) { c.put("status", status); if (status < 300) c.put("answered", t); }
        }
        if (("BYE".equals(method) || "CANCEL".equals(method)) && c.get("bye") == null) c.put("bye", t);
    }

    static List<Map<String, Object>> callRows(Map<String, Map<String, Object>> calls) {
        List<Map<String, Object>> out = new ArrayList<>();
        calls.values().stream().sorted(Comparator.comparingDouble(c -> Analysis.d(c.get("start")))).forEach(c -> {
            double start = c.get("invite") != null ? Analysis.d(c.get("invite")) : Analysis.d(c.get("start"));
            String state = c.get("answered") != null ? (c.get("bye") == null ? "in_call" : "completed") : c.get("status") != null && ((Integer) c.get("status")) >= 300 ? "rejected" : c.get("bye") != null ? "cancelled" : c.get("invite") != null ? "unanswered" : "other";
            Map<String, Object> m = new LinkedHashMap<>();
            for (String k : new String[] {"call_id", "frame", "start", "caller", "callee", "from_user", "to_user", "method", "status", "messages"}) m.put(k, c.get(k));
            m.put("state", state);
            m.put("ringing", c.get("ringing") == null ? null : Analysis.d(c.get("ringing")) - start);
            m.put("setup", c.get("answered") == null ? null : Analysis.d(c.get("answered")) - start);
            m.put("duration", c.get("answered") == null ? null : Analysis.d(c.get("bye") != null ? c.get("bye") : c.get("end")) - Analysis.d(c.get("answered")));
            out.add(m);
        });
        return out.subList(0, Math.min(TOP * 5, out.size()));
    }

    static void rtp(Map<List<String>, Map<String, Object>> streams, Map<String, String> p) {
        Double t = Builder.toDouble(get(p, "frame.time_epoch"));
        String ssrc = first(get(p, "rtp.ssrc"));
        Integer seq = toInt(first(get(p, "rtp.seq")));
        Long ts = toLong(first(get(p, "rtp.timestamp")));
        if (t == null || ssrc == null || seq == null || ts == null) return;
        String[] ab = ends(p);
        Integer pt = toInt(first(get(p, "rtp.p_type")));
        Map<String, Object> s = streams.computeIfAbsent(List.of(ssrc, ab[0], ab[1]), k -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ssrc", ssrc); m.put("src", ab[0]); m.put("dst", ab[1]); m.put("payload", pt); m.put("first", t); m.put("last", t); m.put("packets", 0); m.put("base", seq); m.put("cycles", 0L); m.put("max_seq", seq);
            m.put("out_of_order", 0); m.put("seen", new HashSet<Long>()); m.put("jitter", 0.0); m.put("max_jitter", 0.0); m.put("jitter_sum", 0.0); m.put("max_delta", 0.0);
            m.put("prev_t", null); m.put("prev_ts", null); m.put("clock", RTP_CLOCK.getOrDefault(pt, 8000));
            return m;
        });
        s.put("packets", (Integer) s.get("packets") + 1);
        Double prevT = (Double) s.get("prev_t");
        if (prevT != null) s.put("max_delta", Math.max(Analysis.d(s.get("max_delta")), t - prevT));
        long cycles = (Long) s.get("cycles");
        int maxSeq = (Integer) s.get("max_seq");
        long ext = cycles + seq;
        int delta = (seq - maxSeq) & 0xFFFF;
        if (delta != 0 && delta < 0x8000) {
            if (seq < maxSeq) cycles += 0x10000;
            s.put("cycles", cycles);
            ext = cycles + seq;
            s.put("max_seq", seq);
        } else if (delta != 0) {
            s.put("out_of_order", (Integer) s.get("out_of_order") + 1);
            ext = cycles + seq - (seq > maxSeq ? 0x10000 : 0);
        }
        @SuppressWarnings("unchecked") Set<Long> seen = (Set<Long>) s.get("seen");
        seen.add(ext);
        if (prevT != null && delta != 0 && delta < 0x8000) {
            double d = (t - prevT) - (((ts - (Long) s.get("prev_ts")) & 0xFFFFFFFFL) / (double) (Integer) s.get("clock"));
            double j = Analysis.d(s.get("jitter")) + (Math.abs(d) - Analysis.d(s.get("jitter"))) / 16;
            s.put("jitter", j); s.put("max_jitter", Math.max(Analysis.d(s.get("max_jitter")), j)); s.put("jitter_sum", Analysis.d(s.get("jitter_sum")) + j);
        }
        if (delta == 0 || delta < 0x8000) { s.put("prev_t", t); s.put("prev_ts", ts); }
        s.put("last", t);
    }

    static List<Map<String, Object>> streamRows(Map<List<String>, Map<String, Object>> streams) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> s : streams.values()) {
            long expected = (Long) s.get("cycles") + (Integer) s.get("max_seq") - (Integer) s.get("base") + 1;
            @SuppressWarnings("unchecked") int unique = ((Set<Long>) s.get("seen")).size();
            long lost = Math.max(expected - unique, 0);
            Map<String, Object> m = new LinkedHashMap<>();
            for (String k : new String[] {"ssrc", "src", "dst", "payload", "packets", "out_of_order", "max_delta", "max_jitter"}) m.put(k, s.get(k));
            m.put("expected", expected); m.put("lost", lost); m.put("loss", expected > 0 ? (double) lost / expected : 0.0);
            m.put("mean_jitter", Analysis.d(s.get("jitter_sum")) / Math.max((Integer) s.get("packets") - 1, 1));
            m.put("start", s.get("first")); m.put("duration", Analysis.d(s.get("last")) - Analysis.d(s.get("first")));
            out.add(m);
        }
        out.sort(Comparator.comparingDouble(m -> Analysis.d(m.get("start"))));
        return out.subList(0, Math.min(TOP * 5, out.size()));
    }

    // ---- QUIC

    public static List<Map<String, Object>> quic(TShark ts, Path capture, boolean decrypted) throws TShark.TsharkException {
        List<String> fields = List.of("frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport", "quic.connection.number", "quic.version", "quic.header_form",
                "quic.stream.stream_id", "http3.frame_type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str");
        Map<String, Map<String, Object>> conns = new LinkedHashMap<>();
        for (Map<String, String> p : rows(ts.query(capture, "quic", fields, 3_000_000, 600, true, List.of()), fields)) {
            if (get(p, "quic.connection.number").isEmpty()) continue;
            Double t = Builder.toDouble(get(p, "frame.time_epoch"));
            if (t == null) continue;
            String si = Optional.ofNullable(last(get(p, "ip.src"))).filter(x -> !x.isEmpty()).orElse(last(get(p, "ipv6.src")));
            String di = Optional.ofNullable(last(get(p, "ip.dst"))).filter(x -> !x.isEmpty()).orElse(last(get(p, "ipv6.dst")));
            String here = si + ":" + last(get(p, "udp.srcport")), there = di + ":" + last(get(p, "udp.dstport"));
            String key = here.compareTo(there) <= 0 ? here + "\u0000" + there : there + "\u0000" + here;
            Map<String, Object> c = conns.computeIfAbsent(key, k -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("client", here); m.put("server", there); m.put("start_time", t); m.put("end", t); m.put("packets", 0); m.put("bytes", 0L); m.put("streams", new HashSet<Long>()); m.put("h3", false);
                return m;
            });
            c.put("end", Math.max(Analysis.d(c.get("end")), t));
            c.put("packets", (Integer) c.get("packets") + 1);
            c.put("bytes", (Long) c.get("bytes") + Optional.ofNullable(toLong(get(p, "frame.len"))).orElse(0L));
            Long version = toLong(first(get(p, "quic.version")));
            if (version != null && version != 0 && c.get("version") == null) c.put("version", version == 1 ? "1" : version == 0x6B3343CFL ? "2" : "0x" + Long.toHexString(version));
            if (c.get("sni") == null) c.put("sni", first(get(p, "tls.handshake.extensions_server_name")));
            if (c.get("handshake") == null && !here.equals(c.get("client")) && many(get(p, "quic.header_form")).contains("0")) c.put("handshake", t - Analysis.d(c.get("start_time")));
            @SuppressWarnings("unchecked") Set<Long> streams = (Set<Long>) c.get("streams");
            for (String sid : many(get(p, "quic.stream.stream_id"))) { Long v = toLong(sid); if (v != null && v % 4 == 0) streams.add(v); }
            if (!get(p, "http3.frame_type").isEmpty()) c.put("h3", true);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : conns.values()) {
            Map<String, Object> m = new LinkedHashMap<>(c);
            m.put("duration", Analysis.d(c.get("end")) - Analysis.d(c.get("start_time")));
            @SuppressWarnings("unchecked") Set<Long> streams = (Set<Long>) c.get("streams");
            m.put("requests", streams.size()); m.remove("streams"); m.remove("end");
            out.add(m);
        }
        return out.subList(0, Math.min(500, out.size()));
    }
}
