package io.pcapanalyzer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The tshark packed into the WAR, unpacked once into the work folder. It brings its own musl loader and libraries, so it runs on any Linux x86_64. */
final class BundledTShark {
    private static final Logger LOG = Logger.getLogger(BundledTShark.class.getName());
    private static final String ARCHIVE = "/tshark/tshark-linux-x86_64.tar.gz";
    private static volatile Path home;
    private static volatile boolean tried;

    private BundledTShark() {}

    static Path path() {
        Path h = home();
        return h == null ? null : h.resolve("tshark/bin/tshark");
    }

    static Path dataDir() {
        Path h = home();
        return h == null ? null : h.resolve("tshark/share/wireshark");
    }

    private static Path home() {
        if (tried) return home;
        synchronized (BundledTShark.class) {
            if (!tried) {
                try { home = unpack(); } catch (IOException | RuntimeException e) { LOG.log(Level.WARNING, "The bundled tshark could not be unpacked; tshark from PATH is used", e); }
                tried = true;
            }
        }
        return home;
    }

    private static Path unpack() throws IOException {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT), arch = System.getProperty("os.arch", "");
        if (!os.contains("linux") || !(arch.equals("amd64") || arch.equals("x86_64"))) return null;
        java.net.URL url = BundledTShark.class.getResource(ARCHIVE);
        if (url == null) return null;
        long size = url.openConnection().getContentLengthLong();
        // one folder per archive, so a new WAR with another tshark unpacks next to the old one
        Path dir = Settings.workdir().resolve(".runtime").resolve("tshark-" + Long.toString(size, 36));
        if (Files.isExecutable(dir.resolve("tshark/bin/tshark.real")) && Files.exists(dir.resolve(".complete"))) return dir;
        Files.createDirectories(dir.getParent());
        Path tmp = Files.createTempDirectory(dir.getParent(), "unpack-");
        Path tgz = tmp.resolve("tshark.tar.gz");
        try (InputStream in = url.openStream()) { Files.copy(in, tgz, StandardCopyOption.REPLACE_EXISTING); }
        try {
            Process p = new ProcessBuilder("tar", "-xzf", tgz.toString(), "-C", tmp.toString()).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes());
            if (!p.waitFor(120, TimeUnit.SECONDS) || p.exitValue() != 0) throw new IOException("tar failed: " + out.strip());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        Files.delete(tgz);
        Files.createFile(tmp.resolve(".complete"));
        try {
            Files.move(tmp, dir, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            if (!Files.exists(dir.resolve(".complete"))) throw e;  // another node of a shared work folder was first
        }
        LOG.info("Bundled tshark unpacked into " + dir);
        return dir;
    }
}
