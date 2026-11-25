package io.pcapanalyzer;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/** Deletes analyses nobody has opened for PCAP_ANALYZER_TTL_DAYS days (7 by default): at start and every hour, whether or not anyone uses the app.
 *  "Opened" is the time of the analysis's .seen file, set when a page of it is shown; an analysis never opened counts from its upload. */
@WebListener
public class Cleaner implements ServletContextListener {
    private static final Logger LOG = Logger.getLogger(Cleaner.class.getName());
    private static final Pattern ID = Pattern.compile("[0-9a-f]{16}");
    private ScheduledExecutorService timer;

    @Override
    public void contextInitialized(ServletContextEvent e) {
        timer = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "pcap-analyzer-cleaner"); t.setDaemon(true); return t; });
        timer.scheduleWithFixedDelay(() -> { run(); scan(); }, 1, 60, TimeUnit.MINUTES);
    }

    @Override
    public void contextDestroyed(ServletContextEvent e) { if (timer != null) timer.shutdownNow(); }

    static long lastUse(Path dir) throws IOException {
        Path seen = dir.resolve(".seen"), meta = dir.resolve("meta.json");
        long t = Files.getLastModifiedTime(Files.exists(meta) ? meta : dir).toMillis();
        if (Files.exists(seen)) t = Math.max(t, Files.getLastModifiedTime(seen).toMillis());
        return t;
    }

    /** Looks for files put or changed by hand: anything plain in the data folder, and settings or results that no longer verify. */
    static void scan() {
        if (!Vault.isSetUp()) return;
        Path wd = Settings.workdir();
        try (var walk = Files.walk(wd)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (!Files.isRegularFile(p)) continue;
                String n = p.getFileName().toString();
                if (p.startsWith(wd.resolve(".runtime")) || p.equals(Vault.keyring()) || p.equals(Records.auditFile()) || n.equals(".seen") || n.endsWith(".tmp")) continue;
                if (Files.size(p) == 0 || !Vault.encrypted(p)) { Vault.alert(p, "The file is not encrypted. It was put or changed by hand."); continue; }
                if (n.endsWith(".json") && Vault.isUnlocked()) Vault.verify(p);
            }
        } catch (IOException | RuntimeException ex) {
            LOG.warning("Checking the data folder failed: " + ex);
        }
    }

    static void run() {
        Path wd = Settings.workdir();
        if (!Files.isDirectory(wd)) return;
        long cutoff = System.currentTimeMillis() - Settings.ttlDays() * 86_400_000L;
        int removed = 0;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(wd)) {
            for (Path d : ds) {
                if (!Files.isDirectory(d) || !ID.matcher(d.getFileName().toString()).matches()) continue;
                // an analysis still running has no meta yet; give it a day before it counts as left over
                if (!Files.exists(d.resolve("meta.json")) && Files.getLastModifiedTime(d).toMillis() > System.currentTimeMillis() - 86_400_000L) continue;
                if (lastUse(d) >= cutoff) continue;
                try (var walk = Files.walk(d)) { walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) { } }); }
                removed++;
                Records.audit("expired", "server", d.getFileName().toString());
            }
        } catch (IOException | RuntimeException ex) {
            LOG.warning("Cleaning up old analyses failed: " + ex);
        }
        if (removed > 0) LOG.info("Deleted " + removed + " analyses not opened for " + Settings.ttlDays() + " days");
    }
}
