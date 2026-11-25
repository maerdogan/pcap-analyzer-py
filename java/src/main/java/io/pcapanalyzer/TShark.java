package io.pcapanalyzer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Runs tshark and yields one field map per packet. */
public final class TShark {
    public static final char AGG = '\u001f';
    public static final int[] MIN_VERSION = {4, 0};
    public static final List<String> EVENTS = List.of("retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order",
            "lost_segment", "ack_lost_segment", "duplicate_ack", "zero_window", "zero_window_probe", "window_full", "window_update", "keep_alive");
    public static final List<String> FIELDS = new ArrayList<>(List.of(
            "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.len", "tcp.flags", "tcp.window_size",
            "tcp.analysis.ack_rtt", "ip.id", "tcp.ack", "tcp.seq_raw", "frame.cap_len", "ip.flags.mf", "dns.qry.name", "dns.time", "dns.flags.response", "dns.flags.rcode", "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code", "_ws.malformed",
            "tcp.options.sack_le", "tcp.analysis.reused_ports", "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm",
            "http.request.method", "http.request.uri", "http.request.version", "http.host", "http.response.code",
            "http.response.phrase", "http.response.version", "http.content_length", "http.content_type",
            "tcp.segment", "http.request.line", "http.response.line", "http.file_data", "http.x_forwarded_for", "http.content_encoding", "http.transfer_encoding", "tls.record.content_type", "tls.record.opaque_type", "tls.handshake.type", "tls.handshake.extensions_server_name",
            "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite", "tls.handshake.extensions_alpn_str", "tls.alert_message.desc", "x509af.utcTime", "tls.handshake.certificate_length", "x509ce.dNSName", "nstrace.pdevno", "nstrace.l_pdevno", "nstrace.tcpdbg.rtrtt", "nstrace.rtt", "proxy.version", "proxy.v1.magic", "proxy.src.ipv4", "proxy.src.ipv6", "proxy.srcport", "proxy.dst.ipv4", "proxy.dst.ipv6", "proxy.dstport",
            "http2.type", "http2.streamid", "http2.flags", "http2.length", "http2.header.count", "http2.header.name", "http2.header.value",
            "http2.rst_stream.error", "http2.goaway.error", "http2.window_update.window_size_increment", "http2.settings.id", "http2.settings.initial_window_size"));
    static {
        for (String e : EVENTS) FIELDS.add("tcp.analysis." + e);
    }

    public static class TsharkException extends Exception {
        public TsharkException(String m) { super(m); }
    }

    private final String binary;

    public TShark(String binary) { this.binary = binary; }

    /** A process of tshark or mergecap, with the environment the bundled tshark needs. */
    private ProcessBuilder pb(String... cmd) { return pb(java.util.Arrays.asList(cmd)); }

    private ProcessBuilder pb(List<String> cmd) {
        ProcessBuilder b = new ProcessBuilder(cmd);
        Settings.tsharkEnv(b.environment(), binary);
        return b;
    }

    /** A daemon thread that kills the process when it runs longer than the limit. Interrupt it once the process is done. */
    private static Thread killAfter(Process p, long seconds) {
        Thread t = new Thread(() -> { try { if (!p.waitFor(seconds, TimeUnit.SECONDS)) p.destroyForcibly(); } catch (InterruptedException ignored) { } });
        t.setDaemon(true);
        t.start();
        return t;
    }

    /** Waits for the process; past the limit it is killed and the run fails. */
    private static void awaitOrKill(Process p, long seconds, String what) throws InterruptedException, TsharkException {
        if (!p.waitFor(seconds, TimeUnit.SECONDS)) { p.destroyForcibly(); throw new TsharkException(what + " took too long"); }
    }

    /** Feeds the capture to tshark's standard input: the capture stays where it is, and no copy fills /tmp. A reader that stops early simply ends the feed. */
    static Process pump(Process p, Path capture) {
        Thread t = new Thread(() -> {
            try (java.io.OutputStream out = p.getOutputStream(); java.io.InputStream in = Vault.in(capture)) {
                in.transferTo(out);
            } catch (IOException e) {
                // a capture that cannot be read, such as one locked or changed by hand: stop tshark rather than leave it waiting for input
                p.destroyForcibly();
            }
        }, "tshark-feed");
        t.setDaemon(true);
        t.start();
        return p;
    }

    public String version() throws TsharkException {
        try {
            Process p = pb(binary, "--version").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            Matcher m = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)").matcher(out);
            if (!m.find()) throw new TsharkException("tshark version could not be read");
            int major = Integer.parseInt(m.group(1)), minor = Integer.parseInt(m.group(2));
            if (major < MIN_VERSION[0] || (major == MIN_VERSION[0] && minor < MIN_VERSION[1]))
                throw new TsharkException("tshark " + m.group() + " is too old, need 4.0 or newer");
            return m.group();
        } catch (IOException | InterruptedException e) {
            throw new TsharkException("tshark could not be started: " + e.getMessage());
        }
    }

    /** Reads the capture and calls {@code sink} per packet. {@code timeoutSeconds} of 0 means no limit. */
    public void read(Path capture, String filter, long timeoutSeconds, Consumer<Map<String, String>> sink) throws TsharkException {
        read(capture, null, filter, timeoutSeconds, sink);
    }

    /** With a TLS key log, tshark decrypts the sessions it names. */
    public void read(Path capture, Path keylog, String filter, long timeoutSeconds, Consumer<Map<String, String>> sink) throws TsharkException {
        read(capture, keylog, null, List.of(), filter, timeoutSeconds, sink);
    }

    /** With an RSA private key as well as, or instead of, a key log, and with Decode As rules such as tcp.port==9000,http. */
    public void read(Path capture, Path keylog, Path rsaKey, List<String> decodeAs, String filter, long timeoutSeconds, Consumer<Map<String, String>> sink) throws TsharkException {
        // Ubuntu's AppArmor profile stops tshark from reading most paths, so it reads a private copy under /tmp.
        Path keyCopy = null, rsaCopy = null;
        try {
            if (keylog != null) {
                keyCopy = Files.createTempFile(Path.of("/tmp"), "pcap-analyzer-key-", ".log");
                Files.copy(keylog, keyCopy, StandardCopyOption.REPLACE_EXISTING);
            }
            if (rsaKey != null) {
                rsaCopy = Files.createTempFile(Path.of("/tmp"), "pcap-analyzer-rsa-", ".key");
                Files.copy(rsaKey, rsaCopy, StandardCopyOption.REPLACE_EXISTING);
            }
            readFile(capture, keyCopy, rsaCopy, decodeAs, filter, timeoutSeconds, sink);
        } catch (IOException e) {
            throw new TsharkException("capture could not be read: " + e.getMessage());
        } finally {
            if (keyCopy != null) try { Files.deleteIfExists(keyCopy); } catch (IOException ignored) { }
            if (rsaCopy != null) try { Files.deleteIfExists(rsaCopy); } catch (IOException ignored) { }
        }
    }

    /** Reads chosen fields of the packets that match a display filter, one String[] per packet (at most {@code limit}). */
    public List<String[]> query(Path capture, String filter, List<String> fields, int limit, long timeoutSeconds) throws TsharkException {
        return query(capture, filter, fields, limit, timeoutSeconds, false, List.of());
    }

    /** With {@code all}, a field that occurs several times in a packet gives all values, joined by the unit separator. {@code extra} are further tshark options. */
    public List<String[]> query(Path capture, String filter, List<String> fields, int limit, long timeoutSeconds, boolean all, List<String> extra) throws TsharkException {
        try {
            List<String> cmd = new ArrayList<>(List.of(binary, "-n", "-r", "-", "-o", "http.desegment_body:FALSE", "-o", "http.desegment_headers:FALSE",
                    "-o", "tcp.desegment_tcp_streams:TRUE", "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", all ? "occurrence=a" : "occurrence=f", "-E", "aggregator=" + AGG));
            cmd.addAll(extra);
            if (filter != null && !filter.isBlank()) { cmd.add("-Y"); cmd.add(filter); }
            for (String f : fields) { cmd.add("-e"); cmd.add(f); }
            Process p = pump(pb(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start(), capture);
            Thread killer = timeoutSeconds > 0 ? killAfter(p, timeoutSeconds) : null;
            List<String[]> rows = new ArrayList<>();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8), 1 << 16)) {
                String line;
                while ((line = r.readLine()) != null && rows.size() < limit) rows.add(line.split("\t", -1));
            }
            p.destroy();
            if (killer != null) killer.interrupt();
            return rows;
        } catch (IOException e) {
            throw new TsharkException("tshark could not be run: " + e.getMessage());
        }
    }

    /** The text of one TCP stream, as Wireshark's Follow TCP Stream shows it (ASCII, at most 400 KB). */
    public String follow(Path capture, int stream, long timeoutSeconds) throws TsharkException {
        try {
            Process p = pump(pb(binary, "-n", "-r", "-", "-q", "-z", "follow,tcp,ascii," + stream).redirectError(ProcessBuilder.Redirect.DISCARD).start(), capture);
            Thread killer = killAfter(p, timeoutSeconds);
            byte[] data = p.getInputStream().readNBytes(400_000);
            p.destroy();
            killer.interrupt();
            return new String(data, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new TsharkException("tshark could not be run: " + e.getMessage());
        }
    }

    /** Joins parts of one capture into a single file, in time order. */
    public static void merge(List<Path> parts, Path out, long timeoutSeconds) throws TsharkException {
        List<Path> copies = new ArrayList<>();
        Path merged = null;
        try {
            for (Path p : parts) { Path c = Files.createTempFile(Path.of("/tmp"), "pcap-analyzer-part-", ".cap"); Files.copy(p, c, StandardCopyOption.REPLACE_EXISTING); copies.add(c); }
            merged = Files.createTempFile(Path.of("/tmp"), "pcap-analyzer-merged-", ".pcapng");
            List<String> cmd = new ArrayList<>(List.of("mergecap", "-w", merged.toString()));
            for (Path c : copies) cmd.add(c.toString());
            Process pr = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String msg = new String(pr.getInputStream().readNBytes(4000), StandardCharsets.UTF_8);
            awaitOrKill(pr, timeoutSeconds, "mergecap");
            if (pr.exitValue() != 0) throw new TsharkException(msg.strip().isEmpty() ? "mergecap could not join the files" : msg.strip().replaceAll(" ?\"?/\\S*\"?", ""));
            Files.copy(merged, out, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | InterruptedException e) {
            throw new TsharkException("mergecap could not be started: " + e.getMessage());
        } finally {
            for (Path c : copies) try { Files.deleteIfExists(c); } catch (IOException ignored) { }
            if (merged != null) try { Files.deleteIfExists(merged); } catch (IOException ignored) { }
        }
    }

    /** One TCP connection as a new capture file, kept whole so Wireshark can reassemble it. */
    public byte[] extract(Path capture, int stream, long timeoutSeconds) throws TsharkException {
        Path out = null;
        try {
            out = Files.createTempFile(Path.of("/tmp"), "pcap-analyzer-", ".pcapng");
            Process p = pump(pb(binary, "-n", "-r", "-", "-Y", "tcp.stream == " + stream, "-w", out.toString()).redirectErrorStream(true).start(), capture);
            p.getInputStream().readAllBytes();
            awaitOrKill(p, timeoutSeconds, "tshark");
            return Files.readAllBytes(out);
        } catch (IOException | InterruptedException e) {
            throw new TsharkException("tshark could not be run: " + e.getMessage());
        } finally {
            if (out != null) try { Files.deleteIfExists(out); } catch (IOException ignored) { }
        }
    }

    /** Lines of Follow TCP Stream in raw (hex per line) or hex-dump form. A tab at the start marks the second node. */
    public List<String> followLines(Path capture, int stream, String mode, long timeoutSeconds) throws TsharkException {
        String text = statsText(capture, "follow,tcp," + mode + "," + stream, timeoutSeconds);
        return new ArrayList<>(Arrays.asList(text.split("\n", -1)));
    }

    /** Files carried in the capture, as Wireshark's Export Objects finds them. Returns false when this tshark does not know the protocol. */
    public boolean exportObjects(Path capture, String protocol, Path outDir, long timeoutSeconds) throws TsharkException {
        try {
            Path tmpOut = Files.createTempDirectory(Path.of("/tmp"), "pcap-analyzer-obj-");
            try {
                Process p = pump(pb(binary, "-n", "-r", "-", "-q", "--export-objects", protocol + "," + tmpOut).redirectErrorStream(true).start(), capture);
                p.getInputStream().readNBytes(4000);
                awaitOrKill(p, timeoutSeconds, "tshark");
                if (p.exitValue() != 0) return false;
                try (var ds = Files.newDirectoryStream(tmpOut)) { for (Path f : ds) if (Files.isRegularFile(f)) Files.move(f, outDir.resolve(f.getFileName()), StandardCopyOption.REPLACE_EXISTING); }
                return true;
            } finally {
                try (var walk = Files.walk(tmpOut)) { walk.sorted(Comparator.reverseOrder()).forEach(x -> x.toFile().delete()); }
            }
        } catch (IOException | InterruptedException e) {
            throw new TsharkException("tshark could not be run: " + e.getMessage());
        }
    }

    /** The text of one tshark statistic, such as io,phs. */
    public String statsText(Path capture, String statistic, long timeoutSeconds) throws TsharkException {
        try {
            Process p = pump(pb(binary, "-n", "-r", "-", "-q", "-z", statistic).redirectError(ProcessBuilder.Redirect.DISCARD).start(), capture);
            Thread killer = killAfter(p, timeoutSeconds);
            byte[] data = p.getInputStream().readNBytes(2_000_000);
            p.destroy();
            killer.interrupt();
            return new String(data, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new TsharkException("tshark could not be run: " + e.getMessage());
        }
    }

    private void readFile(Path capture, Path keylog, Path rsaKey, List<String> decodeAs, String filter, long timeoutSeconds, Consumer<Map<String, String>> sink) throws TsharkException {
        List<String> cmd = new ArrayList<>(List.of(binary, "-n", "-r", "-",
                "-o", "http.desegment_body:FALSE", "-o", "http.desegment_headers:FALSE",
                "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tcp.reassemble_out_of_order:TRUE",
                // A PROXY protocol header comes before HTTP or TLS on the same port, so its heuristic has to run before the port's dissector
                "-o", "tcp.try_heuristic_first:TRUE",
                "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=" + AGG));
        if (keylog != null) { cmd.add("-o"); cmd.add("tls.keylog_file:" + keylog); }
        if (rsaKey != null) { cmd.add("-o"); cmd.add("uat:rsa_keys:\"" + rsaKey + "\",\"\""); }
        for (String rule : decodeAs) { cmd.add("-d"); cmd.add(rule); }
        if (filter != null && !filter.isBlank()) { cmd.add("-Y"); cmd.add(filter); }
        for (String f : FIELDS) { cmd.add("-e"); cmd.add(f); }
        Process p;
        try {
            p = pump(pb(cmd).start(), capture);
        } catch (IOException e) {
            throw new TsharkException("tshark could not be started: " + e.getMessage());
        }
        StringBuilder err = new StringBuilder();
        Thread drain = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) if (err.length() < 4000) err.append(l).append('\n');
            } catch (IOException ignored) { }
        });
        drain.setDaemon(true);
        drain.start();
        Thread killer = timeoutSeconds > 0 ? killAfter(p, timeoutSeconds) : null;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = r.readLine()) != null) {
                String[] cols = line.split("\t", -1);
                Map<String, String> row = new HashMap<>(32);
                for (int i = 0; i < cols.length && i < FIELDS.size(); i++) if (!cols[i].isEmpty()) row.put(FIELDS.get(i), cols[i]);
                sink.accept(row);
            }
            int code = p.waitFor();
            drain.join(1000);
            if (code != 0) {
                String msg = err.toString().strip();
                throw new TsharkException(msg.isEmpty() ? "tshark exited with code " + code : lastLine(msg));
            }
        } catch (IOException | InterruptedException e) {
            p.destroyForcibly();
            throw new TsharkException("tshark failed: " + e.getMessage());
        } finally {
            if (killer != null) killer.interrupt();
        }
    }

    private static String lastLine(String s) {
        int i = s.lastIndexOf('\n');
        return (i < 0 ? s : s.substring(i + 1)).replaceAll(" ?\"?/\\S*\"?", "");
    }
}
