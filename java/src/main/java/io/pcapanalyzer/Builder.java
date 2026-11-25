package io.pcapanalyzer;

import java.util.*;

import static io.pcapanalyzer.TShark.AGG;

/** Turns tshark packets into connections, HTTP/1 transactions and TCP events (port of parser.py, without TLS, HTTP/2, QUIC and DNS). */
public final class Builder {
    static final int SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;
    static final double RTT_INDISTINCT = 0.0005;

    static final class Pkt {
        int frame; double t; int size; String src; long payload; int flags; long seq; boolean retrans; int win;
    }

    static final class Req {
        int frame, startFrame; String method, uri, host, version, requestId, headers, body, xff; Long contentLength;
    }

    static final class H2 {
        Map<String, String> req, resp;
        Pkt reqPk, respPk, cEnd, sEnd, lastC, lastS;
        long cData, sData;
        Integer grpc;
        String grpcMessage;
    }

    static final class Resp {
        int frame, startFrame, status, headLen; String phrase, contentType, headers, body, encoding, transfer, serverTiming, version; Long contentLength; boolean websocket;
    }

    static final class Stream {
        int sid; String a, b, client;
        List<Pkt> packets = new ArrayList<>();
        Pkt syn, synack, hsAck;
        List<double[]> pendingRtt = new ArrayList<>(); // not used for src, see rttBySrc
        List<Object[]> rttSamples = new ArrayList<>();
        List<Req> requests = new ArrayList<>();
        List<Resp> responses = new ArrayList<>();
        long reqEnd, respEnd;
        Map<Integer, H2> h2 = new LinkedHashMap<>();
        boolean tlsSeen, tlsHello, tlsServerHello, tlsCertificate;
        Pkt tlsStart, tlsEnd, tlsCcs;
        String sni, tlsVersion, tlsCipher, tlsAlpn, tlsAlert, tlsCertExpires;
        List<Integer> mss = new ArrayList<>();
        Integer wscale;
        boolean sack;
        int zeroWindows;
        List<Pkt> zeroList = new ArrayList<>();
        Map<String, Double> seen = new HashMap<>();
        Map<String, double[]> parts = new HashMap<>();
        Map<String, ArrayDeque<double[]>> wholes = new HashMap<>();
        Map<String, Long> partSize = new HashMap<>();
        Set<Integer> noRtt = new HashSet<>();
        double lastSyn;
        Long isnClient, isnServer;
        boolean closed;
        double lastT;
        boolean offload;
    }

    public final Map<Integer, Stream> streams = new TreeMap<>();
    public final List<Map<String, Object>> events = new ArrayList<>();
    /** A closed connection quiet for this long, in capture time, is finished and its packets are freed, so memory stays bounded on large captures. */
    static final double QUIET_S = 300;
    static final int SWEEP_EVERY = 100_000;
    private final List<Finished> early = new ArrayList<>();
    private final Map<Integer, Object[]> earlyNat = new HashMap<>();
    private final Set<Integer> finishedSids = new HashSet<>();
    private long sweepCounter;
    public long total, tcp, bytes, fragments, fragNeeded, truncatedPackets, copies, natViews;
    /** One row per packet with a problem Wireshark's expert information would show: {frame, time, kind, detail, src, dst}. */
    public final List<Object[]> packetIssues = new ArrayList<>();
    public final List<double[]> dnsTimes = new ArrayList<>();
    static final int MAX_PACKET_ISSUES = 200_000;
    static final Map<Integer, String> DNS_RCODES = Map.of(1, "format_error", 2, "server_failure", 3, "no_such_name", 4, "not_implemented", 5, "refused");
    static final Map<Integer, String> ICMP_UNREACHABLE = Map.of(0, "network", 1, "host", 2, "protocol", 3, "port", 4, "fragmentation_needed", 9, "network_prohibited", 10, "host_prohibited", 13, "administratively_prohibited");
    static final Map<Integer, String> ICMP6_UNREACHABLE = Map.of(0, "no_route", 1, "administratively_prohibited", 3, "address", 4, "port");
    public Double tFirst, tLast;

    static String[] many(Map<String, String> p, String key) {
        String v = p.get(key);
        return v == null ? new String[0] : v.split(String.valueOf(AGG), -1);
    }

    static String first(Map<String, String> p, String key) {
        String v = p.get(key);
        if (v == null) return null;
        int i = v.indexOf(AGG);
        return i < 0 ? v : v.substring(0, i);
    }

    static String last(Map<String, String> p, String key) {
        String v = p.get(key);
        if (v == null) return null;
        int i = v.lastIndexOf(AGG);
        return i < 0 ? v : v.substring(i + 1);
    }

    static Long toLong(String v) {
        if (v == null || v.isEmpty()) return null;
        try {
            return v.startsWith("0x") ? Long.parseLong(v.substring(2), 16) : Long.parseLong(v);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Double toDouble(String v) {
        try { return v == null || v.isEmpty() ? null : Double.valueOf(v); } catch (NumberFormatException e) { return null; }
    }

    public void add(Map<String, String> p) {
        total++;
        long size = Optional.ofNullable(toLong(p.get("frame.len"))).orElse(0L);
        bytes += size;
        Double t = toDouble(p.get("frame.time_epoch"));
        if (t == null) return;
        Long cap = toLong(p.get("frame.cap_len"));
        if (cap != null && cap < size) truncatedPackets++;
        String mf = first(p, "ip.flags.mf");
        if ("1".equals(mf) || "True".equals(mf)) fragments++;
        if ("3".equals(first(p, "icmp.type")) && "4".equals(first(p, "icmp.code"))) fragNeeded++;
        packetProblems(p, t);
        if (p.containsKey("dns.time")) { Double dt = toDouble(p.get("dns.time")); if (dt != null) dnsTimes.add(new double[] {dt, Double.parseDouble(p.get("frame.number")), t}); }
        tFirst = tFirst == null ? t : Math.min(tFirst, t);
        tLast = tLast == null ? t : Math.max(tLast, t);
        Long sidL = toLong(p.get("tcp.stream"));
        if (sidL == null) return;
        tcp++;
        int sid = sidL.intValue();
        int frame = Integer.parseInt(p.get("frame.number"));
        String srcIp = Optional.ofNullable(last(p, "ip.src")).orElse(last(p, "ipv6.src"));
        String dstIp = Optional.ofNullable(last(p, "ip.dst")).orElse(last(p, "ipv6.dst"));
        String src = srcIp + ":" + p.get("tcp.srcport"), dst = dstIp + ":" + p.get("tcp.dstport");
        if (finishedSids.contains(sid)) return; // a packet after the connection was finished and freed
        Stream s = streams.computeIfAbsent(sid, k -> { Stream n = new Stream(); n.sid = sid; n.a = src; n.b = dst; return n; });
        int flags = Optional.ofNullable(toLong(p.get("tcp.flags"))).orElse(0L).intValue();
        long payload = Optional.ofNullable(toLong(p.get("tcp.len"))).orElse(0L);
        if (isCopy(p, s, t, src, flags, payload)) { copies++; s.noRtt.add(frame); return; }
        Pkt pk = new Pkt();
        pk.frame = frame; pk.t = t; pk.size = (int) size; pk.src = src; pk.payload = payload; pk.flags = flags;
        pk.seq = Optional.ofNullable(toLong(p.get("tcp.seq"))).orElse(0L);
        pk.win = Optional.ofNullable(toLong(p.get("tcp.window_size"))).orElse(0L).intValue();
        pk.retrans = p.containsKey("tcp.analysis.retransmission") || p.containsKey("tcp.analysis.fast_retransmission");
        s.packets.add(pk);
        s.lastT = t;
        if ((flags & (FIN | RST)) != 0) s.closed = true;
        if (payload > 0 && !s.tlsSeen && !s.mss.isEmpty() && payload > Collections.max(s.mss)) s.offload = true;
        if (++sweepCounter % SWEEP_EVERY == 0) sweep(t, s);
        for (String e : TShark.EVENTS) {
            if (p.containsKey("tcp.analysis." + e)) {
                Map<String, Object> ev = new LinkedHashMap<>();
                ev.put("stream", sid); ev.put("frame", frame); ev.put("time", t); ev.put("source", src); ev.put("event", e);
                events.add(ev);
            }
        }
        if ((flags & SYN) != 0 && (flags & ACK) == 0) {
            if (s.syn == null) s.syn = pk;
            s.lastSyn = t;
            if (s.isnClient == null) s.isnClient = toLong(p.get("tcp.seq_raw"));
            s.client = src;
        } else if ((flags & SYN) != 0 && (flags & ACK) != 0) {
            if (s.synack == null) s.synack = pk;
            if (s.isnServer == null) s.isnServer = toLong(p.get("tcp.seq_raw"));
            if (s.client == null) s.client = dst;
        } else if (s.synack != null && s.hsAck == null && (flags & ACK) != 0 && src.equals(s.client)) {
            s.hsAck = pk;
        }
        Long mssVal = toLong(first(p, "tcp.options.mss_val"));
        if (mssVal != null) s.mss.add(mssVal.intValue());
        Long shift = toLong(first(p, "tcp.options.wscale.shift"));
        if (shift != null) s.wscale = s.wscale == null ? shift.intValue() : Math.min(s.wscale, shift.intValue());
        if (p.containsKey("tcp.options.sack_perm")) s.sack = true;
        if (p.containsKey("tcp.analysis.zero_window")) { s.zeroWindows++; s.zeroList.add(pk); }
        Double rtt = toDouble(p.get("tcp.analysis.ack_rtt"));
        if (rtt != null && !pk.retrans && !s.noRtt.contains(Optional.ofNullable(toLong(p.get("tcp.analysis.acks_frame"))).map(Long::intValue).orElse(-1))) s.rttSamples.add(new Object[] {src, rtt});
        tls(p, s, pk, src);
        http1(p, s, pk, src, dst);
        http2(p, s, pk, src, dst);
    }

    static final String REQUEST_ID_HEADER = Optional.ofNullable(System.getenv("PCAP_ANALYZER_REQUEST_ID_HEADER")).filter(v -> !v.isBlank()).orElse("x-request-id").toLowerCase();
    static final java.util.regex.Pattern TRACEPARENT = java.util.regex.Pattern.compile("[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}");

    /** The ID that follows a request through proxies. tshark lists the lines of pipelined requests as one block, so the Nth request owns the Nth copy of a header. */
    static String requestId(String[] lines, int index) {
        String named = header(lines, REQUEST_ID_HEADER, index);
        if (named != null && !named.isBlank()) return named;
        String tp = header(lines, "traceparent", index);
        if (tp == null) return null;
        java.util.regex.Matcher m = TRACEPARENT.matcher(tp.strip().toLowerCase());
        return m.matches() ? m.group(1) : null;
    }

    static String header(String[] lines, String name, int index) {
        String prefix = name + ":";
        int seen = 0;
        for (String l : lines) {
            if (l.toLowerCase().startsWith(prefix)) {
                if (seen++ == index) return l.substring(prefix.length()).replace("\\r\\n", "").strip();
            }
        }
        return null;
    }

    static final double SAME_ID_S = 1.0, NO_ID_S = 0.002, SYN_COPY_S = 0.5;
    static final int MAX_PARTS = 128, RECENT_WHOLES = 16;

    /** True for a second view of a packet already seen. A real retransmission has a new IP ID or comes much later. */
    private boolean isCopy(Map<String, String> p, Stream s, double t, String src, int flags, long payload) {
        String ipId = last(p, "ip.id");
        String key = src + "|" + p.get("tcp.seq") + "|" + p.get("tcp.ack") + "|" + flags + "|" + payload + "|" + ipId;
        Double before = s.seen.get(key);
        s.seen.put(key, t);
        Long idv = toLong(ipId);
        double window = idv != null && idv != 0 ? SAME_ID_S : (flags & SYN) != 0 ? SYN_COPY_S : NO_ID_S;
        if (before != null && t - before <= window) return !((flags & SYN) != 0 && (flags & ACK) != 0 && s.lastSyn > before);
        return isResegmented(p, s, t, src, payload, idv);
    }

    /** The same bytes cut differently: GSO keeps one big frame on one interface and splits it on the next, GRO joins them again. */
    private boolean isResegmented(Map<String, String> p, Stream s, double t, String src, long payload, Long ident) {
        Long seq = toLong(p.get("tcp.seq"));
        if (payload == 0 || ident == null || ident == 0 || seq == null) return false;
        double[] first = s.parts.get(src + "|" + ident);
        if (first != null && first[0] == seq && first[1] != payload && t - first[2] <= SAME_ID_S) { s.partSize.merge(src, (long) Math.min(first[1], payload), Math::min); return true; }
        ArrayDeque<double[]> recent = s.wholes.get(src);
        if (recent != null) for (double[] w : recent) {
            long k = Math.floorMod(ident - (long) w[2], 65536L), off = seq - (long) w[0];
            if (!(k > 0 && k <= MAX_PARTS && off > 0 && off % k == 0 && seq + payload <= (long) w[0] + (long) w[1] && t - w[3] <= SAME_ID_S)) continue;
            long part = off / k;
            if (payload == part) { s.partSize.put(src, part); return true; }
            if (payload < part && seq + payload == (long) w[0] + (long) w[1] && Objects.equals(s.partSize.get(src), part)) return true;
        }
        s.parts.put(src + "|" + ident, new double[] {seq, payload, t});
        ArrayDeque<double[]> q = s.wholes.computeIfAbsent(src, k -> new ArrayDeque<>());
        q.add(new double[] {seq, payload, ident, t});
        while (q.size() > RECENT_WHOLES) q.poll();
        return false;
    }

    /** Connections seen a second time after NAT, as tcpdump -i any on a node sees a Service address and then the pod. The view seen first stays. */
    /** Finishes connections that closed and stayed quiet, so their packets can be freed. */
    private void sweep(double now, Stream current) {
        List<Stream> done = new ArrayList<>();
        for (Stream s : streams.values()) if (s != current && s.closed && now - s.lastT > QUIET_S && !s.packets.isEmpty()) done.add(s);
        for (Stream s : done) {
            early.add(finish(s));
            if (s.syn != null && s.isnClient != null && s.isnServer != null) earlyNat.put(s.sid, new Object[] {s.syn.t, s.isnClient, s.isnServer});
            finishedSids.add(s.sid);
            streams.remove(s.sid);
        }
    }

    private void removeNatViews() {
        List<Stream> views = new ArrayList<>();
        for (Stream s : streams.values()) if (s.syn != null && s.isnClient != null && s.isnServer != null) views.add(s);
        views.sort(Comparator.comparingDouble((Stream s) -> s.syn.t).thenComparingInt(s -> s.sid));
        List<Object[]> all = new ArrayList<>(); // {sid, SYN time, client ISN, server ISN}
        for (Stream s : views) all.add(new Object[] {s.sid, s.syn.t, s.isnClient, s.isnServer});
        earlyNat.forEach((sid, v) -> all.add(new Object[] {sid, v[0], v[1], v[2]}));
        all.sort(Comparator.comparingDouble((Object[] v) -> (Double) v[1]).thenComparingInt(v -> (Integer) v[0]));
        Map<String, Object[]> firstSeen = new HashMap<>();
        Set<Integer> later = new HashSet<>();
        for (Object[] v : all) {
            Object[] kept = firstSeen.putIfAbsent(v[2] + "|" + v[3], v);
            if (kept != null && kept != v && (Double) v[1] - (Double) kept[1] <= SAME_ID_S) later.add((Integer) v[0]);
        }
        natViews = later.size();
        for (Integer sid : later) streams.remove(sid);
        early.removeIf(f -> later.contains(((Number) f.conn().get("stream")).intValue()));
    }

    private void issue(Map<String, String> p, double t, String kind, String detail) {
        if (packetIssues.size() >= MAX_PACKET_ISSUES) return;
        String src = Optional.ofNullable(last(p, "ip.src")).orElse(last(p, "ipv6.src")), dst = Optional.ofNullable(last(p, "ip.dst")).orElse(last(p, "ipv6.dst"));
        packetIssues.add(new Object[] {Integer.parseInt(p.get("frame.number")), t, kind, detail, src, dst});
    }

    /** Problems seen on one packet that are not about a request: bad TCP flags, congestion marks, DNS errors, ICMP errors and malformed packets. */
    private void packetProblems(Map<String, String> p, double t) {
        if (p.containsKey("_ws.malformed")) issue(p, t, "malformed", null);
        Long rcode = toLong(first(p, "dns.flags.rcode"));
        String resp = first(p, "dns.flags.response");
        if (rcode != null && rcode != 0 && ("1".equals(resp) || "True".equals(resp)) && !p.containsKey("icmp.type")) issue(p, t, "dns_error", DNS_RCODES.getOrDefault(rcode.intValue(), String.valueOf(rcode)));
        if ("3".equals(first(p, "icmp.type"))) { Long code = toLong(first(p, "icmp.code")); issue(p, t, "icmp_unreachable", code == null ? null : ICMP_UNREACHABLE.getOrDefault(code.intValue(), String.valueOf(code))); }
        else if ("1".equals(first(p, "icmpv6.type"))) { Long code = toLong(first(p, "icmpv6.code")); issue(p, t, "icmp_unreachable", code == null ? null : ICMP6_UNREACHABLE.getOrDefault(code.intValue(), String.valueOf(code))); }
        if (p.containsKey("tcp.stream") && !p.containsKey("icmp.type") && !p.containsKey("icmpv6.type")) {
            int flags = Optional.ofNullable(toLong(p.get("tcp.flags"))).orElse(0L).intValue();
            if (((flags & SYN) != 0 && (flags & (FIN | RST)) != 0) || (flags & (SYN | FIN | RST | ACK)) == 0 || ((flags & FIN) != 0 && (flags & ACK) == 0)) {
                List<String> names = new ArrayList<>();
                int[] bits = {SYN, ACK, 0x08, FIN, RST, 0x20};
                String[] labels = {"SYN", "ACK", "PSH", "FIN", "RST", "URG"};
                for (int i = 0; i < bits.length; i++) if ((flags & bits[i]) != 0) names.add(labels[i]);
                issue(p, t, "tcp_flags_invalid", names.isEmpty() ? "none" : String.join(", ", names));
            } else if ((flags & SYN) == 0 && ((flags & 0x40) != 0 || (flags & 0x80) != 0)) issue(p, t, "ecn_congestion", (flags & 0x80) != 0 ? "CWR" : "ECE");
            if (p.containsKey("tcp.analysis.reused_ports")) issue(p, t, "port_reused", p.get("tcp.srcport") + "->" + p.get("tcp.dstport"));
            if (p.containsKey("tcp.options.sack_le")) issue(p, t, "sack_blocks", String.valueOf(many(p, "tcp.options.sack_le").length));
        }
    }

    private void http2(Map<String, String> p, Stream s, Pkt pk, String src, String dst) {
        String[] types = many(p, "http2.type");
        if (types.length == 0) return;
        String[] ids = many(p, "http2.streamid"), flags = many(p, "http2.flags"), lengths = many(p, "http2.length"), counts = many(p, "http2.header.count");
        String[] names = many(p, "http2.header.name"), values = many(p, "http2.header.value");
        int hpos = 0, cpos = 0;
        for (int i = 0; i < types.length; i++) {
            String ty = types[i];
            Long sid = i < ids.length ? toLong(ids[i]) : Long.valueOf(0);
            Long fl = i < flags.length ? toLong(flags[i]) : Long.valueOf(0);
            Long ln = i < lengths.length ? toLong(lengths[i]) : Long.valueOf(0);
            Map<String, String> hdrs = new HashMap<>();
            if (ty.equals("1")) {
                int n = cpos < counts.length && toLong(counts[cpos]) != null ? toLong(counts[cpos]).intValue() : 0;
                cpos++;
                for (int k = hpos; k < hpos + n && k < names.length && k < values.length; k++) hdrs.put(names[k], values[k]);
                hpos += n;
            }
            if (sid == null || sid == 0 || (!ty.equals("0") && !ty.equals("1"))) continue;
            if (hdrs.containsKey(":method")) { if (s.client == null) s.client = src; }
            else if (hdrs.containsKey(":status")) { if (s.client == null) s.client = dst; }
            H2 st = s.h2.computeIfAbsent(sid.intValue(), k -> new H2());
            if (hdrs.containsKey("grpc-status")) { st.grpc = Optional.ofNullable(toLong(hdrs.get("grpc-status"))).map(Long::intValue).orElse(null); st.grpcMessage = hdrs.get("grpc-message"); }
            boolean isClient = src.equals(s.client);
            if (hdrs.containsKey(":method")) { st.req = hdrs; st.reqPk = pk; }
            if (hdrs.containsKey(":status") && !hdrs.get(":status").startsWith("1")) { st.resp = hdrs; st.respPk = pk; }
            if (ty.equals("0")) { if (isClient) st.cData += ln == null ? 0 : ln; else st.sData += ln == null ? 0 : ln; }
            if (isClient) st.lastC = pk; else st.lastS = pk;
            if (fl != null && (fl & 1) != 0) { if (isClient) st.cEnd = pk; else st.sEnd = pk; }
        }
    }

    static final Map<Integer, String> CIPHERS = Map.ofEntries(
            Map.entry(0x1301, "TLS_AES_128_GCM_SHA256"), Map.entry(0x1302, "TLS_AES_256_GCM_SHA384"), Map.entry(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
            Map.entry(0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256"), Map.entry(0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384"), Map.entry(0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256"),
            Map.entry(0xC030, "ECDHE_RSA_AES_256_GCM_SHA384"), Map.entry(0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305"), Map.entry(0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305"),
            Map.entry(0x009C, "RSA_AES_128_GCM_SHA256"), Map.entry(0x009D, "RSA_AES_256_GCM_SHA384"), Map.entry(0x002F, "RSA_AES_128_CBC_SHA"), Map.entry(0x0035, "RSA_AES_256_CBC_SHA"),
            Map.entry(0x000A, "RSA_3DES_EDE_CBC_SHA"), Map.entry(0x0005, "RSA_RC4_128_SHA"));
    static final Map<Integer, String> ALERTS = Map.ofEntries(
            Map.entry(0, "close_notify"), Map.entry(10, "unexpected_message"), Map.entry(20, "bad_record_mac"), Map.entry(40, "handshake_failure"), Map.entry(42, "bad_certificate"),
            Map.entry(43, "unsupported_certificate"), Map.entry(44, "certificate_revoked"), Map.entry(45, "certificate_expired"), Map.entry(46, "certificate_unknown"),
            Map.entry(47, "illegal_parameter"), Map.entry(48, "unknown_ca"), Map.entry(49, "access_denied"), Map.entry(50, "decode_error"), Map.entry(51, "decrypt_error"),
            Map.entry(70, "protocol_version"), Map.entry(71, "insufficient_security"), Map.entry(80, "internal_error"), Map.entry(90, "user_canceled"),
            Map.entry(109, "missing_extension"), Map.entry(112, "unrecognized_name"), Map.entry(116, "certificate_required"), Map.entry(120, "no_application_protocol"));

    private void tls(Map<String, String> p, Stream s, Pkt pk, String src) {
        String[] ctypes = many(p, "tls.record.content_type"), opaque = many(p, "tls.record.opaque_type");
        if (ctypes.length == 0 && opaque.length == 0) return;
        List<Long> types = new ArrayList<>();
        for (String x : ctypes) { Long v = toLong(x); if (v != null) types.add(v); }
        s.tlsSeen = true;
        if (s.tlsStart == null) s.tlsStart = pk;
        List<Long> hs = new ArrayList<>();
        for (String x : many(p, "tls.handshake.type")) { Long v = toLong(x); if (v != null) hs.add(v); }
        if (s.sni == null) s.sni = first(p, "tls.handshake.extensions_server_name");
        if (hs.contains(2L)) {
            String[] v = many(p, "tls.handshake.extensions.supported_version");
            String ver = v.length > 0 ? v[v.length - 1] : "0x0303";
            s.tlsVersion = switch (ver) { case "0x0304" -> "TLS 1.3"; case "0x0303" -> "TLS 1.2"; case "0x0302" -> "TLS 1.1"; case "0x0301" -> "TLS 1.0"; default -> "unknown"; };
            s.tlsServerHello = true;
            Long code = toLong(last(p, "tls.handshake.ciphersuite"));
            if (code != null) s.tlsCipher = CIPHERS.getOrDefault(code.intValue(), String.format("0x%04X", code));
            s.tlsAlpn = first(p, "tls.handshake.extensions_alpn_str");
        }
        if (hs.contains(20L) && src.equals(s.client)) s.tlsEnd = pk;
        if (types.contains(20L) && src.equals(s.client) && s.tlsCcs == null && s.tlsServerHello) s.tlsCcs = pk;
        if (hs.contains(1L)) s.tlsHello = true;
        if (hs.contains(11L)) s.tlsCertificate = true;
        Long alert = toLong(first(p, "tls.alert_message.desc"));
        if (alert != null && alert != 0 && s.tlsAlert == null) s.tlsAlert = ALERTS.getOrDefault(alert.intValue(), String.valueOf(alert));
        String[] times = many(p, "x509af.utcTime");
        if (times.length >= 2 && s.tlsCertExpires == null) s.tlsCertExpires = times[1];
    }

    private void http1(Map<String, String> p, Stream s, Pkt pk, String src, String dst) {
        int startFrame = pk.frame;
        for (String x : many(p, "tcp.segment")) {
            Long f = toLong(x);
            if (f != null) startFrame = Math.min(startFrame, f.intValue());
        }
        String[] methods = many(p, "http.request.method");
        if (methods.length > 0 && pk.seq < s.reqEnd) methods = new String[0];
        if (methods.length > 0) {
            String[] uris = many(p, "http.request.uri"), hosts = many(p, "http.host"), versions = many(p, "http.request.version");
            if (s.client == null) s.client = src;
            for (int i = 0; i < methods.length; i++) {
                Req r = new Req();
                r.frame = pk.frame; r.startFrame = startFrame; r.method = methods[i];
                r.uri = i < uris.length ? uris[i] : null;
                r.host = i < hosts.length ? hosts[i] : null;
                r.version = i < versions.length ? versions[i] : "HTTP/1.1";
                r.contentLength = toLong(first(p, "http.content_length"));
                r.requestId = requestId(many(p, "http.request.line"), i);
                r.headers = Privacy.maskedHeaders(many(p, "http.request.line"));
                String[] bodies = many(p, "http.file_data");
                r.body = bodies.length > 0 ? Privacy.preview(bodies[0]) : null;
                r.xff = first(p, "http.x_forwarded_for");
                s.requests.add(r);
            }
            s.reqEnd = pk.seq + pk.payload;
        }
        String[] codes = many(p, "http.response.code");
        if (codes.length > 0 && pk.seq < s.respEnd) codes = new String[0];
        if (codes.length > 0) {
            if (s.client == null) s.client = dst;
            String[] phrases = many(p, "http.response.phrase"), lengths = many(p, "http.content_length");
            for (int i = 0; i < codes.length; i++) {
                Resp r = new Resp();
                r.frame = pk.frame; r.startFrame = startFrame;
                Long c = toLong(codes[i]);
                if (c == null) continue;
                r.status = c.intValue();
                r.phrase = i < phrases.length ? phrases[i] : null;
                r.contentLength = i < lengths.length ? toLong(lengths[i]) : null;
                r.contentType = first(p, "http.content_type");
                r.encoding = first(p, "http.content_encoding"); r.transfer = first(p, "http.transfer_encoding");
                String[] rlines = many(p, "http.response.line");
                r.headers = Privacy.maskedHeaders(rlines);
                String[] versions = many(p, "http.response.version");
                r.version = i < versions.length ? versions[i] : "HTTP/1.1";
                int hl = (r.version + " " + codes[i] + " " + (r.phrase == null ? "" : r.phrase)).length() + 2 + 2;
                for (String l : rlines) hl += (l.endsWith("\\r\\n") ? l.length() - 4 : l.length()) + 2;
                r.headLen = hl;
                r.websocket = "websocket".equalsIgnoreCase(Optional.ofNullable(header(rlines, "upgrade", 0)).orElse(""));
                r.serverTiming = Optional.ofNullable(header(rlines, "server-timing", 0)).orElseGet(() -> {
                    String rt = header(rlines, "x-response-time", 0);
                    if (rt == null) return null;
                    java.util.regex.Matcher mm = java.util.regex.Pattern.compile("([0-9.]+)\\s*(ms|s)?").matcher(rt.strip());
                    return mm.matches() ? "app;dur=" + Double.parseDouble(mm.group(1)) * ("s".equals(mm.group(2)) ? 1000 : 1) : null;
                });
                String[] rb = many(p, "http.file_data");
                r.body = rb.length > 0 ? Privacy.preview(rb[0]) : null;
                s.responses.add(r);
            }
            s.respEnd = pk.seq + pk.payload;
        }
    }

    static Double pickRtt(Double handshake, List<Double> samples) {
        Double best = null;
        List<Double> all = new ArrayList<>();
        all.add(handshake);
        all.addAll(samples);
        for (Double v : all) if (v != null && v >= 0 && (best == null || v < best)) best = v;
        return best;
    }

    static String capturePoint(Double srv, Double cli) {
        if (srv == null || cli == null || Math.max(srv, cli) < RTT_INDISTINCT) return "unknown";
        if (cli <= 0.25 * srv) return "near_client";
        if (srv <= 0.25 * cli) return "near_server";
        return "middle";
    }

    /** Result of one stream: connection row and its transactions. */
    public record Finished(Map<String, Object> conn, List<Map<String, Object>> txns) {}

    public List<Finished> finish() {
        removeNatViews();
        List<Finished> out = new ArrayList<>(early);
        for (Stream s : streams.values()) if (!s.packets.isEmpty()) out.add(finish(s));
        return out;
    }

    private Finished finish(Stream s) {
        String client = s.client != null ? s.client : s.a;
        String server = client.equals(s.a) ? s.b : s.a;
        List<Double> rc = new ArrayList<>(), rs = new ArrayList<>();
        for (Object[] r : s.rttSamples) (r[0].equals(client) ? rc : rs).add((Double) r[1]);
        Double hsSrv = s.syn != null && s.synack != null ? s.synack.t - s.syn.t : null;
        Double hsCli = s.synack != null && s.hsAck != null ? s.hsAck.t - s.synack.t : null;
        Double rttSrv = pickRtt(hsSrv, rs), rttCli = pickRtt(hsCli, rc);
        Double connect = hsSrv != null && hsCli != null ? hsSrv + hsCli : null;
        Pkt closer = null;
        for (Pkt p : s.packets) if ((p.flags & RST) != 0) { closer = p; break; }
        if (closer == null) for (Pkt p : s.packets) if ((p.flags & FIN) != 0) { closer = p; break; }
        List<Map<String, Object>> txns = h1Transactions(s, client, rttSrv);
        txns.addAll(h2Transactions(s, rttSrv));
        txns.sort(Comparator.comparingDouble(x -> (Double) x.get("req_start")));
        enrich(s, client, txns, rttSrv);
        txns.sort(Comparator.comparingDouble(x -> (Double) x.get("req_start")));
        for (int i = 0; i < txns.size(); i++) {
            Map<String, Object> x = txns.get(i);
            boolean fresh = i == 0 && s.syn != null;
            x.put("seq_on_conn", i + 1);
            x.put("new_conn", fresh);
            x.put("connect_time", fresh ? connect : null);
            x.put("tls_time", fresh && s.tlsStart != null && (s.tlsEnd != null || s.tlsCcs != null) ? (s.tlsEnd != null ? s.tlsEnd : s.tlsCcs).t - s.tlsStart.t : null);
        }
        long payC = 0, payS = 0, retr = 0;
        Integer minWin = null;
        double bytesSum = 0;
        for (Pkt p : s.packets) {
            if (p.src.equals(client)) payC += p.payload; else payS += p.payload;
            if (p.retrans) retr++;
            bytesSum += p.size;
            if ((p.flags & SYN) == 0 && (minWin == null || p.win < minWin)) minWin = p.win;
        }
        Pkt firstP = s.packets.get(0), lastP = s.packets.get(s.packets.size() - 1);
        Map<String, Object> conn = new LinkedHashMap<>();
        conn.put("stream", s.sid);
        conn.put("client", client); conn.put("server", server);
        conn.put("client_ip", hostOf(client)); conn.put("client_port", portOf(client));
        conn.put("server_ip", hostOf(server)); conn.put("server_port", portOf(server));
        conn.put("sni", s.sni);
        Set<String> senders = new HashSet<>();
        for (Pkt p : s.packets) senders.add(p.src);
        conn.put("one_way", senders.size() == 1);
        conn.put("syn_seen", s.syn != null);
        boolean h2 = !s.h2.isEmpty();
        boolean websocket = s.responses.stream().anyMatch(r -> r.websocket && r.status == 101);
        conn.put("kind", websocket ? "WebSocket" : s.tlsSeen ? (h2 ? "HTTPS/2" : txns.isEmpty() ? "TLS" : "HTTPS") : h2 ? "HTTP/2" : txns.isEmpty() ? "TCP" : "HTTP");
        Pkt tlsEnd = s.tlsEnd != null ? s.tlsEnd : s.tlsCcs;
        conn.put("tls_version", s.tlsVersion); conn.put("tls_cipher", s.tlsCipher); conn.put("tls_alpn", s.tlsAlpn); conn.put("tls_alert", s.tlsAlert);
        conn.put("tls_time", s.tlsStart != null && tlsEnd != null ? tlsEnd.t - s.tlsStart.t : null);
        conn.put("tls_no_answer", s.tlsHello && !s.tlsServerHello);
        conn.put("tls_resumed", s.tlsServerHello && !s.tlsCertificate && !"TLS 1.3".equals(s.tlsVersion));
        conn.put("tls_cert_expires", s.tlsCertExpires);
        conn.put("tls_seen", s.tlsSeen);
        conn.put("offload", s.offload);
        conn.put("first_frame", firstP.frame);
        conn.put("start_time", firstP.t); conn.put("end_time", lastP.t); conn.put("duration", lastP.t - firstP.t);
        conn.put("packets", s.packets.size()); conn.put("bytes", (long) bytesSum);
        conn.put("payload_client", payC); conn.put("payload_server", payS);
        conn.put("handshake_seen", s.syn != null && s.synack != null);
        conn.put("connect_time", connect);
        conn.put("rtt_server", rttSrv); conn.put("rtt_client", rttCli);
        conn.put("capture_point", capturePoint(rttSrv, rttCli));
        conn.put("close_type", closer == null ? null : (closer.flags & RST) != 0 ? "RST" : "FIN");
        conn.put("closed_by", closer == null ? null : closer.src.equals(client) ? "client" : "server");
        conn.put("transactions", txns.size());
        conn.put("requests", txns.size());
        conn.put("retransmissions", retr);
        conn.put("min_window", minWin);
        conn.put("mss", s.mss.isEmpty() ? null : Collections.min(s.mss));
        conn.put("wscale", s.wscale); conn.put("sack", s.sack); conn.put("zero_windows", s.zeroWindows);
        conn.put("byte_ratio_db", payC > 0 && payS > 0 ? Math.round(10 * Math.log10((double) payC / payS) * 10) / 10.0 : null);
        return new Finished(conn, txns);
    }

    static String hostOf(String endpoint) { return endpoint.substring(0, endpoint.lastIndexOf(':')); }

    static Integer portOf(String endpoint) {
        try { return Integer.valueOf(endpoint.substring(endpoint.lastIndexOf(':') + 1)); } catch (NumberFormatException e) { return null; }
    }

    private List<Map<String, Object>> h1Transactions(Stream s, String client, Double rttSrv) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (s.requests.isEmpty() && s.responses.isEmpty()) return out;
        Map<Integer, Pkt> frames = new HashMap<>();
        for (Pkt p : s.packets) frames.put(p.frame, p);
        Deque<Resp> finals = new ArrayDeque<>();
        for (Resp r : s.responses) if (r.status >= 200 || r.status == 101) finals.add(r);
        List<Object[]> pairs = new ArrayList<>(); // {Req, Resp}
        for (Req q : s.requests) {
            while (!finals.isEmpty() && finals.peekFirst().startFrame < q.startFrame) pairs.add(new Object[] {null, finals.pollFirst()});
            pairs.add(new Object[] {q, finals.pollFirst()});
        }
        for (Resp r : finals) pairs.add(new Object[] {null, r});
        TreeSet<Long> respSeqs = new TreeSet<>();
        for (Resp r : s.responses) respSeqs.add(startSeq(frames, r));
        for (int i = 0; i < pairs.size(); i++) {
            Req q = (Req) pairs.get(i)[0];
            Resp r = (Resp) pairs.get(i)[1];
            if (q == null) continue;
            long nextQ = i + 1 < pairs.size() && pairs.get(i + 1)[0] != null ? ((Req) pairs.get(i + 1)[0]).startFrame : Long.MAX_VALUE;
            Integer rStart = r == null ? null : r.startFrame;
            Long rSeq = r == null ? null : startSeq(frames, r);
            Long nextR = rSeq == null ? Long.valueOf(Long.MAX_VALUE) : Optional.ofNullable(respSeqs.higher(rSeq)).orElse(Long.MAX_VALUE);
            long reqLimit = Math.min(nextQ, rStart == null ? Long.MAX_VALUE : rStart);
            Pkt qFirst = frames.getOrDefault(q.startFrame, frames.get(q.frame));
            Pkt qLast = qFirst;
            long reqBytes = 0, respBytes = 0, respMaxEnd = 0;
            Pkt rFirst = r == null ? null : frames.get(rStart), rLast = rFirst;
            for (Pkt p : s.packets) {
                if (p.src.equals(client)) {
                    if (p.payload > 0 && q.startFrame <= p.frame && p.frame < reqLimit) {
                        qLast = p;
                        if (!p.retrans) reqBytes += p.payload;
                    }
                } else if (rSeq != null && p.payload > 0 && rSeq <= p.seq && p.seq < nextR) {
                    rLast = p;
                    respMaxEnd = Math.max(respMaxEnd, p.seq + p.payload);
                }
            }
            if (rSeq != null) respBytes = Math.max(0, respMaxEnd - rSeq);
            if (r != null && r.status == 101) rLast = rFirst;
            out.add(row(s, q, r, qFirst, qLast, rFirst, rLast, rttSrv, reqBytes, respBytes));
        }
        return out;
    }

    private List<Map<String, Object>> h2Transactions(Stream s, Double rttSrv) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<Integer, H2> e : s.h2.entrySet()) {
            H2 st = e.getValue();
            if (st.req == null) continue;
            Pkt qFirst = st.reqPk, qLast = st.cEnd != null ? st.cEnd : st.lastC != null ? st.lastC : qFirst;
            Pkt rFirst = st.resp == null ? null : st.respPk, rLast = st.sEnd != null ? st.sEnd : st.lastS != null ? st.lastS : rFirst;
            Req q = new Req();
            q.frame = q.startFrame = qFirst.frame; q.method = st.req.get(":method"); q.uri = st.req.get(":path"); q.host = st.req.get(":authority"); q.version = "HTTP/2";
            Resp r = null;
            if (st.resp != null) {
                r = new Resp();
                r.frame = r.startFrame = rFirst.frame;
                Long code = toLong(st.resp.get(":status"));
                r.status = code == null ? 0 : code.intValue();
                r.contentType = st.resp.get("content-type");
            }
            q.headers = h2Headers(st.req);
            if (r != null) r.headers = h2Headers(st.resp);
            Map<String, Object> m = row(s, q, r, qFirst, qLast, rFirst, rLast, rttSrv, st.cData, st.sData);
            m.put("h2_stream", e.getKey());
            m.put("grpc_status", st.grpc); m.put("grpc_message", st.grpcMessage);
            out.add(m);
        }
        return out;
    }

    static final double DELAYED_ACK_MIN = 0.03, DELAYED_ACK_MAX = 0.5, SEND_AFTER_ACK = 0.01;

    private static double or0(Object v) { return v instanceof Number n ? n.doubleValue() : 0.0; }

    /** Retransmission and zero window waiting inside a frame range: {count, retransmission time, zero window time}. */
    private static double[] stalls(Stream s, int lo, int hi) {
        Map<String, Double> lastSeen = new HashMap<>();
        double retransN = 0, retransT = 0;
        for (Pkt p : s.packets) {
            if (p.frame > hi) break;
            if (p.payload > 0) {
                if (lo <= p.frame && p.retrans && lastSeen.containsKey(p.src)) { retransN++; retransT += p.t - lastSeen.get(p.src); }
                lastSeen.put(p.src, p.t);
            }
        }
        double zero = 0;
        for (Pkt z : s.zeroList) {
            if (z.frame < lo || z.frame > hi) continue;
            for (Pkt p : s.packets) if (p.frame > z.frame && p.src.equals(z.src) && p.win > 0) { zero += p.t - z.t; break; }
        }
        return new double[] {retransN, retransT, zero};
    }

    /** Time a sender sat idle until a late bare ACK released its next segment. */
    private static double delayedAck(Stream s, String sender, int lo, int hi) {
        List<Pkt> pk = new ArrayList<>();
        for (Pkt p : s.packets) if (p.frame >= lo && p.frame <= hi) pk.add(p);
        double total = 0;
        Pkt prev = null;
        for (Pkt p : pk) {
            if (!p.src.equals(sender) || p.payload == 0) continue;
            if (prev != null) {
                Pkt ack = null;
                for (Pkt a : pk) if (a.frame > prev.frame && a.frame < p.frame && !a.src.equals(sender) && a.payload == 0 && (a.flags & ACK) != 0) ack = a;
                if (ack != null && ack.t - prev.t >= DELAYED_ACK_MIN && ack.t - prev.t <= DELAYED_ACK_MAX && p.t - ack.t <= SEND_AFTER_ACK) total += p.t - prev.t;
            }
            prev = p;
        }
        return total;
    }

    static Double serverReported(String st) {
        if (st == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("dur=([0-9.]+)").matcher(st);
        double sum = 0;
        boolean any = false;
        while (m.find()) { sum += Double.parseDouble(m.group(1)); any = true; }
        return any ? sum / 1000 : null;
    }

    private void enrich(Stream s, String client, List<Map<String, Object>> txns, Double rttSrv) {
        String server = client.equals(s.a) ? s.b : s.a;
        for (int i = 0; i < txns.size(); i++) {
            Map<String, Object> t = txns.get(i);
            int lo = ((Number) t.get("req_frame")).intValue();
            int hi = t.get("last_frame") != null ? ((Number) t.get("last_frame")).intValue() : lo;
            double[] st = stalls(s, lo, hi);
            Integer respFrame = t.get("resp_frame") == null ? null : ((Number) t.get("resp_frame")).intValue();
            double delayedReq = delayedAck(s, client, lo, respFrame != null ? respFrame : hi);
            double delayedResp = respFrame != null ? delayedAck(s, server, respFrame, hi) : 0.0;
            boolean answered = Boolean.TRUE.equals(t.get("answered"));
            double network = answered && rttSrv != null ? rttSrv : 0.0;
            double queue = 0.0;
            Map<String, Object> prev = i > 0 ? txns.get(i - 1) : null;
            if (prev != null && t.get("h2_stream") == null && prev.get("resp_end") != null && or0(prev.get("resp_end")) > or0(t.get("req_end")) && answered) queue = or0(prev.get("resp_end")) - or0(t.get("req_end"));
            Double wait = t.get("wait") instanceof Number n ? n.doubleValue() : null;
            Double service = null;
            if (wait != null) { double svc = wait - network - queue; service = svc >= 0 ? svc : null; }
            if (queue != 0 && service == null) service = 0.0;
            double moved = st[1] + st[2] + delayedResp;
            double transfer = or0(t.get("transfer"));
            t.put("retrans_count", (long) st[0]); t.put("retrans_time", st[1]); t.put("zero_window_time", st[2]); t.put("delayed_ack_time", delayedReq + delayedResp);
            t.put("queue_time", queue); t.put("network", network); t.put("service", service);
            t.put("transfer_clean", Math.max(transfer - moved, 0.0));
            t.put("request_clean", Math.max(or0(t.get("request_send")) - delayedReq - Math.max(moved - transfer, 0.0), 0.0));
            Double bodyBytes = null;
            if (t.get("head_len") != null) bodyBytes = Math.max(or0(t.get("resp_bytes")) - or0(t.get("head_len")), 0.0);
            else if ("HTTP/2".equals(t.get("http_version"))) bodyBytes = or0(t.get("resp_bytes"));
            Double clen = t.get("resp_content_length") instanceof Number n ? n.doubleValue() : null;
            boolean https = s.tlsSeen;
            t.put("truncated", answered && clen != null && clen > 0 && Boolean.TRUE.equals(t.get("body_expected")) && bodyBytes != null && bodyBytes < clen && !https);
            t.put("server_reported", serverReported((String) t.get("server_timing")));
        }
    }

    private static String h2Headers(Map<String, String> h) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : h.entrySet()) sb.append(sb.length() > 0 ? "\n" : "").append(e.getKey()).append(": ").append(Privacy.maskHeader(e.getKey(), e.getValue()));
        return sb.toString();
    }

    private static long startSeq(Map<Integer, Pkt> frames, Resp r) {
        Pkt p = frames.containsKey(r.startFrame) ? frames.get(r.startFrame) : frames.get(r.frame);
        return p == null ? 0 : p.seq;
    }

    private Map<String, Object> row(Stream s, Req q, Resp r, Pkt qFirst, Pkt qLast, Pkt rFirst, Pkt rLast, Double rttSrv, long reqBytes, long respBytes) {
        Double wait = rFirst != null ? rFirst.t - qLast.t : null;
        Double service = wait != null && rttSrv != null ? wait - rttSrv : null;
        if (service != null && service < 0) service = null;
        Pkt end = rLast != null ? rLast : qLast;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("stream", s.sid);
        m.put("method", q.method); m.put("uri", Privacy.maskUri(q.uri)); m.put("url_template", UrlTemplate.of(q.uri)); m.put("host", q.host);
        m.put("http_version", q.version);
        m.put("status", r == null ? null : r.status); m.put("phrase", r == null ? null : r.phrase);
        m.put("answered", rFirst != null);
        m.put("req_frame", qFirst.frame); m.put("resp_frame", rFirst == null ? null : rFirst.frame);
        m.put("req_start", qFirst.t); m.put("req_end", qLast.t);
        m.put("resp_start", rFirst == null ? null : rFirst.t); m.put("resp_end", rLast == null ? null : rLast.t);
        m.put("request_send", qLast.t - qFirst.t);
        m.put("wait", wait); m.put("service", service);
        m.put("ttfb", rFirst == null ? null : rFirst.t - qFirst.t);
        m.put("transfer", rFirst == null ? null : rLast.t - rFirst.t);
        m.put("total", rFirst == null ? null : end.t - qFirst.t);
        m.put("req_bytes", reqBytes); m.put("resp_bytes", respBytes);
        m.put("content_type", r == null ? null : r.contentType);
        m.put("rtt", rttSrv);
        m.put("request_id", q.requestId);
        m.put("x_forwarded_for", q.xff);
        m.put("content_encoding", r == null ? null : r.encoding); m.put("transfer_encoding", r == null ? null : r.transfer);
        m.put("last_frame", rLast == null ? null : rLast.frame);
        m.put("head_len", r == null || r.headLen == 0 ? null : r.headLen);
        m.put("resp_content_length", r == null ? null : r.contentLength);
        m.put("body_expected", r != null && !"HEAD".equals(q.method) && !"CONNECT".equals(q.method) && r.status != 204 && r.status != 304);
        m.put("server_timing", r == null ? null : r.serverTiming);
        m.put("h2_stream", null);
        m.put("_req_headers", q.headers); m.put("_resp_headers", r == null ? null : r.headers); m.put("_req_body", q.body); m.put("_resp_body", r == null ? null : r.body);
        return m;
    }
}
