package io.pcapanalyzer;

import com.maxmind.db.Reader;

import java.io.File;
import java.net.InetAddress;
import java.util.Map;

/** Country and network of an address from MaxMind GeoLite2 files in PCAP_ANALYZER_GEOIP_DIR. Without them nothing is looked up. */
public final class GeoIp {
    private static Reader country, asn;
    private static boolean loaded;

    private GeoIp() {}

    private static synchronized void load() {
        if (loaded) return;
        loaded = true;
        String dir = System.getenv("PCAP_ANALYZER_GEOIP_DIR");
        if (dir == null || dir.isBlank()) return;
        File[] files = new File(dir).listFiles((d, n) -> n.endsWith(".mmdb"));
        if (files == null) return;
        for (File f : files) {
            try {
                if (f.getName().contains("Country") && country == null) country = new Reader(f);
                else if (f.getName().contains("ASN") && asn == null) asn = new Reader(f);
            } catch (Exception ignored) { }
        }
    }

    public static boolean available() { load(); return country != null || asn != null; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> look(Reader r, String address) {
        if (r == null) return null;
        try { return r.get(InetAddress.getByName(address), Map.class); } catch (Exception e) { return null; }
    }

    public static String country(String address) {
        load();
        Map<String, Object> m = look(country, address);
        return m != null && m.get("country") instanceof Map<?, ?> c && c.get("iso_code") != null ? c.get("iso_code").toString() : null;
    }

    public static String asn(String address) {
        load();
        Map<String, Object> m = look(asn, address);
        if (m == null || m.get("autonomous_system_number") == null) return null;
        return "AS" + m.get("autonomous_system_number") + (m.get("autonomous_system_organization") != null ? " " + m.get("autonomous_system_organization") : "");
    }
}
