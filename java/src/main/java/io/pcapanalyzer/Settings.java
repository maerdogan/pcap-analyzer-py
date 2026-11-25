package io.pcapanalyzer;

import java.nio.file.Path;

/** Settings come from environment variables, like the Python version. */
public final class Settings {
    public static final long MAX_UPLOAD = 1L << 30;
    private Settings() {}

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    /** Random bytes as lowercase hex: ids of analyses, tokens and saved filters. */
    static String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return java.util.HexFormat.of().formatHex(b);
    }

    public static Path workdir() {
        String v = System.getenv("PCAP_ANALYZER_WORKDIR");
        if (v != null && !v.isBlank()) return Path.of(v);
        // next to the server that runs the app: Tomcat's instance folder, else the folder the JVM was started in
        String base = System.getProperty("catalina.base");
        return Path.of(base != null && !base.isBlank() ? base : System.getProperty("user.dir"), "data");
    }

    /** tshark: PCAP_ANALYZER_TSHARK when set, else the copy bundled in the WAR (Linux x86_64), else tshark from PATH. */
    public static String tshark() {
        String v = System.getenv("PCAP_ANALYZER_TSHARK");
        if (v != null && !v.isBlank()) return v;
        Path bundled = BundledTShark.path();
        return bundled != null ? bundled.toString() : "tshark";
    }

    /** Environment for a tshark run: the bundled copy reads its dissector data from its own share folder, unless WIRESHARK_DATA_DIR is set. */
    public static void tsharkEnv(java.util.Map<String, String> env, String binary) {
        Path data = BundledTShark.dataDir();
        if (data != null && binary.equals(String.valueOf(BundledTShark.path())) && System.getenv("WIRESHARK_DATA_DIR") == null) env.put("WIRESHARK_DATA_DIR", data.toString());
    }

    public static String adminUser() {
        String v = System.getenv("PCAP_ANALYZER_ADMIN_USER");
        return v != null && !v.isBlank() ? v : "admin";
    }

    /** Plain admin password. Empty means no one can sign in. */
    public static String adminPassword() {
        String v = System.getenv("PCAP_ANALYZER_ADMIN_PASSWORD");
        return v == null ? "" : v;
    }

    /** The capture stays on disk so packets, graphs and followed streams can be read again. Set PCAP_ANALYZER_KEEP_CAPTURE=0 to delete it after the analysis. */
    public static boolean keepCapture() { return !"0".equals(System.getenv("PCAP_ANALYZER_KEEP_CAPTURE")); }

    public static int ttlDays() {
        try { return Math.max(1, Integer.parseInt(System.getenv("PCAP_ANALYZER_TTL_DAYS"))); } catch (RuntimeException e) { return 7; }
    }

    public static long timeoutSeconds() {
        try { return Long.parseLong(System.getenv("PCAP_ANALYZER_TIMEOUT_S")); } catch (RuntimeException e) { return 900; }
    }
}
