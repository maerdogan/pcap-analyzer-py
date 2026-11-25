package io.pcapanalyzer;

import java.io.Console;
import java.nio.file.*;
import java.util.*;

/**
 * Command line of the same engine, writing into the same work folder as the web pages.
 *
 *   analyze FILE [--keylog F ...] [--rsa-key F] [--host IP] [--port N] [--display-filter EXPR] [--decode-as RULE]
 *   list
 *   inspect ID [--src IP] [--src-port N] [--dst IP] [--port N] [--kind K] [--url TEXT]
 *   check ID [--p95 S] [--error-rate PERCENT] [--slowest S]      exit code 2 when a limit is broken
 *   set-password
 */
public final class Cli {
    private Cli() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) { usage(); return; }
        Map<String, String> opt = new HashMap<>();
        List<String> pos = new ArrayList<>(), decode = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--") && i + 1 < args.length) {
                if (args[i].equals("--decode-as")) decode.add(args[++i]);
                else if (args[i].equals("--keylog")) opt.merge("keylog", args[++i], (a, b) -> a + "\u0000" + b); // may be given more than once
                else opt.put(args[i].substring(2), args[++i]);
            } else pos.add(args[i]);
        }
        switch (args[0]) {
            case "analyze" -> analyze(pos, opt, decode);
            case "list" -> { for (Map<String, Object> m : list()) System.out.println(m.get("id") + "  " + m.get("filename") + "  " + m.get("transactions") + " requests"); }
            case "inspect" -> System.out.println(Json.write(Inspect.run(Inspect.query(params(opt)), load(pos, "result.json"))));
            case "check" -> System.exit(check(pos, opt));
            case "set-password" -> setPassword();
            default -> { usage(); System.exit(1); }
        }
    }

    private static void usage() {
        System.out.println("usage: java -jar pcap-analyzer-cli.jar analyze FILE [--keylog F ...] [--rsa-key F] [--host IP] [--host2 IP] [--port N] [--display-filter EXPR] [--decode-as RULE]\n"
                + "       list | inspect ID [--src IP] [--src-port N] [--dst IP] [--port N] [--kind K] [--url TEXT]\n"
                + "       check ID [--p95 S] [--error-rate PERCENT] [--slowest S]   (exit code 2 when a limit is broken)\n"
                + "       set-password\nSettings come from the same PCAP_ANALYZER_* variables as the web application.");
    }

    private static Map<String, String[]> params(Map<String, String> opt) {
        Map<String, String[]> m = new HashMap<>();
        for (var e : opt.entrySet()) m.put(e.getKey().replace('-', '_'), new String[] {e.getValue()});
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> load(List<String> pos, String file) throws Exception {
        if (pos.isEmpty() || !pos.get(0).matches("[0-9a-f]{16}")) throw new IllegalArgumentException("Give the analysis ID.");
        return (Map<String, Object>) Json.parse(Files.readString(Settings.workdir().resolve(pos.get(0)).resolve(file)));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list() throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!Files.isDirectory(Settings.workdir())) return out;
        try (var ds = Files.newDirectoryStream(Settings.workdir())) {
            for (Path d : ds) if (d.getFileName().toString().matches("[0-9a-f]{16}") && Files.exists(d.resolve("meta.json"))) out.add((Map<String, Object>) Json.parse(Files.readString(d.resolve("meta.json"))));
        }
        out.sort((a, b) -> Double.compare(Analysis.d(b.get("created")), Analysis.d(a.get("created"))));
        return out;
    }

    private static void analyze(List<String> pos, Map<String, String> opt, List<String> decode) throws Exception {
        if (pos.isEmpty()) { usage(); System.exit(1); }
        Path file = Path.of(pos.get(0));
        if (!Files.isRegularFile(file)) { System.err.println("No such file: " + file); System.exit(1); }
        List<String> parts = new ArrayList<>();
        for (String k : new String[] {"host", "host2"}) if (opt.get(k) != null) parts.add((opt.get(k).contains(":") ? "ipv6" : "ip") + ".addr == " + opt.get(k));
        if (opt.get("port") != null) parts.add("tcp.port == " + Integer.parseInt(opt.get("port")));
        if (opt.get("display-filter") != null) parts.add("(" + opt.get("display-filter") + ")");
        String filter = String.join(" and ", parts);
        String id = Settings.randomHex(8);
        Path dir = Settings.workdir().resolve(id);
        Files.createDirectories(dir);
        Path cap = dir.resolve("capture.bin");
        Files.copy(file, cap);
        // Keys are copied into the analysis folder first, so removing them after the analysis never touches the user's own files.
        Path key = null, rsa = null;
        if (opt.get("keylog") != null) {
            key = dir.resolve("keylog.tmp");
            KeyLogs.join(java.util.Arrays.stream(opt.get("keylog").split("\u0000")).map(Path::of).toList(), key);
        }
        if (opt.get("rsa-key") != null) { rsa = dir.resolve("rsa.tmp"); Files.copy(Path.of(opt.get("rsa-key")), rsa); }
        try {
            Runner.analyze(id, dir, cap, key, rsa, decode, filter, file.getFileName().toString(), "cli");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        System.out.println(id);
    }

    @SuppressWarnings("unchecked")
    private static int check(List<String> pos, Map<String, String> opt) throws Exception {
        Map<String, Object> http = (Map<String, Object>) load(pos, "result.json").get("http");
        double requests = Analysis.d(http.get("requests")), rate = requests > 0 ? Analysis.d(http.get("failed")) / requests * 100 : 0;
        List<String> broken = new ArrayList<>();
        if (opt.get("p95") != null && Analysis.d(http.get("p95_total")) > Double.parseDouble(opt.get("p95"))) broken.add("p95 " + Fmt.seconds(Analysis.dn(http.get("p95_total"))) + " > " + opt.get("p95") + " s");
        if (opt.get("slowest") != null && Analysis.d(http.get("max_total")) > Double.parseDouble(opt.get("slowest"))) broken.add("slowest " + Fmt.seconds(Analysis.dn(http.get("max_total"))) + " > " + opt.get("slowest") + " s");
        if (opt.get("error-rate") != null && rate > Double.parseDouble(opt.get("error-rate"))) broken.add(String.format(Locale.ROOT, "error rate %.1f%% > %s%%", rate, opt.get("error-rate")));
        System.out.println(String.format(Locale.ROOT, "%.0f requests, %.0f failed (%.1f%%), p95 %s, slowest %s", requests, Analysis.d(http.get("failed")), rate, Fmt.seconds(Analysis.dn(http.get("p95_total"))), Fmt.seconds(Analysis.dn(http.get("max_total")))));
        for (String b : broken) System.out.println("BROKEN: " + b);
        return broken.isEmpty() ? 0 : 2;
    }

    private static void setPassword() throws Exception {
        Console console = System.console();
        String a, b;
        if (console != null) { a = new String(console.readPassword("New password: ")); b = new String(console.readPassword("Again: ")); }
        else { Scanner in = new Scanner(System.in); a = in.nextLine(); b = a; }
        if (a.length() < Passwords.MIN_LENGTH) { System.err.println("At least " + Passwords.MIN_LENGTH + " characters."); System.exit(1); }
        if (!a.equals(b)) { System.err.println("The two passwords are not the same."); System.exit(1); }
        Passwords.save(a);
        System.out.println("Password saved in " + Settings.workdir());
    }
}
