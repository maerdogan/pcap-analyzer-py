package io.pcapanalyzer;

import java.nio.file.Path;

/** Settings come from environment variables, like the Python version. */
public final class Settings {
    public static final long MAX_UPLOAD = 1L << 30;
    private Settings() {}

    public static Path workdir() {
        String v = System.getenv("PCAP_ANALYZER_WORKDIR");
        return Path.of(v != null && !v.isBlank() ? v : System.getProperty("java.io.tmpdir") + "/pcap-analyzer");
    }

    public static String tshark() {
        String v = System.getenv("PCAP_ANALYZER_TSHARK");
        return v != null && !v.isBlank() ? v : "tshark";
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
