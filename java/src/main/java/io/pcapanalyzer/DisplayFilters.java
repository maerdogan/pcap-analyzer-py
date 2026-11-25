package io.pcapanalyzer;

import java.util.LinkedHashMap;
import java.util.Map;

/** The Wireshark display filters a user can pick. Only these reach tshark, so nothing typed by a user does. */
final class DisplayFilters {
    private DisplayFilters() {}

    /** Filter, then the English label that is translated in knowledge.json. The empty filter means all packets. */
    static final Map<String, String> PRESETS = new LinkedHashMap<>();
    static {
        String[][] p = {
            {"", "All packets"},
            {"http || http2", "HTTP and HTTP/2"},
            {"tls", "TLS"},
            {"tls.handshake", "TLS handshakes"},
            {"tls.alert_message", "TLS alerts"},
            {"dns", "DNS"},
            {"dns.flags.rcode != 0", "DNS errors"},
            {"tcp.analysis.flags && !tcp.analysis.window_update", "TCP problems"},
            {"tcp.analysis.retransmission || tcp.analysis.fast_retransmission", "TCP retransmissions"},
            {"tcp.analysis.zero_window || tcp.analysis.window_full", "TCP window full or zero"},
            {"tcp.flags.reset == 1", "TCP resets"},
            {"tcp.flags.syn == 1 && tcp.flags.ack == 0", "New connections (SYN)"},
            {"tcp.analysis.ack_rtt > 0.2", "Round trips over 200 ms"},
            {"http.response.code >= 400 || http2.headers.status >= 400", "HTTP errors (4xx and 5xx)"},
            {"http.response.code >= 500 || http2.headers.status >= 500", "HTTP server errors (5xx)"},
            {"http2.type == 3 || http2.type == 7", "HTTP/2 resets and GOAWAY"},
            {"proxy", "PROXY protocol"},
            {"icmp || icmpv6", "ICMP"},
        };
        for (String[] e : p) PRESETS.put(e[0], e[1]);
    }

    /** The filter when it is one of the presets, otherwise no filter. */
    static String allowed(String f) {
        String v = f == null ? "" : f.strip();
        return PRESETS.containsKey(v) ? v : "";
    }

    /** A select with every preset, the current one chosen. */
    static String select(Pages.Ctx c, String name, String current) {
        StringBuilder sb = new StringBuilder("<select name=\"").append(name).append("\">");
        String cur = allowed(current);
        for (Map.Entry<String, String> e : PRESETS.entrySet())
            sb.append("<option value=\"").append(Fmt.esc(e.getKey())).append("\"").append(e.getKey().equals(cur) ? " selected" : "").append(">").append(Fmt.esc(c.t(e.getValue()))).append("</option>");
        return sb.append("</select>").toString();
    }
}
