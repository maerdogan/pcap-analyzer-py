package io.pcapanalyzer;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/** Number, size and time formats of the Python interface. */
public final class Fmt {
    private Fmt() {}

    public static String seconds(Double v) {
        if (v == null) return "–";
        return v < 1 ? String.format(Locale.ROOT, "%.1f ms", v * 1000) : String.format(Locale.ROOT, "%.2f s", v);
    }

    /** Used inside explanations, where Python prints whole milliseconds. */
    public static String duration(double s) {
        return s < 1 ? String.format(Locale.ROOT, "%.0f ms", s * 1000) : String.format(Locale.ROOT, "%.2f s", s);
    }

    public static String size(Number n) {
        if (n == null) return "–";
        double v = n.doubleValue();
        String[] units = {"B", "KB", "MB", "GB"};
        for (int i = 0; i < units.length; i++) {
            if (v < 1024 || i == units.length - 1) return i == 0 ? String.format(Locale.ROOT, "%.0f B", v) : String.format(Locale.ROOT, "%.1f %s", v, units[i]);
            v /= 1024;
        }
        return "–";
    }

    private static LocalDateTime at(double epoch) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli((long) (epoch * 1000)), ZoneId.systemDefault());
    }

    public static String when(Double v) { return v == null || v == 0 ? "–" : at(v).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")); }
    public static String day(double v) { return at(v).format(DateTimeFormatter.ofPattern("yyyy-MM-dd")); }
    public static String clock(double v) { return at(v).format(DateTimeFormatter.ofPattern("HH:mm")); }

    public static String esc(Object o) {
        if (o == null) return "";
        return o.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
