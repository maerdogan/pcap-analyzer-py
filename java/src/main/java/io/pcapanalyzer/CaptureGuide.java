package io.pcapanalyzer;

import java.util.*;

/** Ready commands for taking a capture on a Linux server, in a pod or on a worker node. */
public final class CaptureGuide {
    public static final double SAFE_SHARE = 0.95;
    public static final int DEFAULT_SECONDS = 120;
    public static final String DEFAULT_IMAGE = "nicolaka/netshoot";
    private static final String TUNNEL_PORTS = "udp port 4789 or udp port 6081";

    public record Point(String key, String title, List<String> lines, String text, String shows, String hides) {}

    private CaptureGuide() {}

    /** Shell quoting, as Python's shlex.quote does it. */
    static String q(String s) {
        if (s.isEmpty()) return "''";
        return s.matches("[A-Za-z0-9@%+=:,./-]+") ? s : "'" + s.replace("'", "'\"'\"'") + "'";
    }

    private static String bpf(String server, String port, String client) {
        List<String> parts = new ArrayList<>();
        if (server != null) parts.add("host " + server);
        if (client != null) parts.add("host " + client);
        if (port != null) parts.add("tcp port " + port);
        return String.join(" and ", parts);
    }

    private static String tcpdump(String iface, String bpf, int seconds, long limit, String path) {
        String cmd = "timeout " + seconds + " tcpdump -i " + q(iface) + " -nn -s 0 -U -w -";
        if (!bpf.isEmpty()) cmd += " " + q(bpf);
        cmd += " | head -c " + limit;
        return path != null ? cmd + " > " + q(path) : cmd;
    }

    public static List<Point> commands(Pages.Ctx c, String server, String port, String client, int seconds, int maxMb, String iface, String namespace, String pod, String container, String image) {
        long limit = (long) (maxMb * 1_000_000L * SAFE_SHARE);
        String bpf = bpf(server, port, client);
        String linux = tcpdump(iface, bpf, seconds, limit, "/tmp/server.pcap");
        String inner = tcpdump("any", bpf, seconds, limit, null);
        String target = "-n " + q(namespace) + " pod/" + q(pod);
        String podCmd = "kubectl debug " + target + " --image=" + q(image) + " --target=" + q(container) + " --attach --quiet -- sh -c " + q(inner) + " > pod.pcap";
        List<Point> out = new ArrayList<>();
        out.add(new Point("linux", c.t("Linux server"), List.of("sudo sh -c " + q(linux)),
                c.t("Run this on the server, or on a client you manage. Files stay under the upload limit, and the capture stops after {n} seconds.", "n", seconds),
                c.t("Everything that reaches this machine: its service time, and its side of the network."), c.t("What happened before the traffic got here.")));
        out.add(new Point("pod", c.t("Pod"), List.of(podCmd),
                c.t("Run this from a machine with kubectl. It adds a temporary container that shares the pod's network, and saves the capture on your machine. The image must be reachable from the cluster."),
                c.t("The pod's own view with pod IP addresses and no tunnel headers. This is the cleanest place to measure service time."), c.t("Anything on the node or in the network around the pod.")));
        out.add(new Point("node_pod", c.t("Worker node, pod network"), List.of("PID=$(sudo crictl inspect --output go-template --template '{{.info.pid}}' " + q(container) + ")",
                "sudo nsenter -t \"$PID\" -n sh -c " + q(tcpdump("any", bpf, seconds, limit, "/tmp/pod.pcap"))),
                c.t("Use this when you can reach the node but cannot add a container to the pod. Replace CONTAINER with the container ID from `crictl ps`."),
                c.t("The same view as inside the pod, without changing the pod."), c.t("Anything on the node or in the network around the pod.")));
        out.add(new Point("node_uplink", c.t("Worker node, outer interface"), List.of("sudo sh -c " + q(tcpdump(!iface.equals("any") ? iface : "eth0", TUNNEL_PORTS, seconds, limit, "/tmp/uplink.pcap"))),
                c.t("Use this to see loss between nodes. Set the interface to the node's real one. An address filter does not work here, because pod traffic is inside the tunnel."),
                c.t("Pod traffic inside VXLAN or Geneve, and packets lost between nodes. The app reads the addresses inside the tunnel."), c.t("Traffic that stays on one node.")));
        out.add(new Point("keylog", c.t("HTTPS key log"), List.of("SSLKEYLOGFILE=/tmp/keys.log curl https://example.test/"),
                c.t("Encrypted traffic needs its session keys. Set this variable on the client before it connects, then upload the file with the capture. It works with curl, Firefox, Chrome and many other programs."),
                c.t("URLs and HTTP timing inside HTTPS."), c.t("If TLS ends on NetScaler, the two sides have different keys. Each side needs its own key log.")));
        return out;
    }
}
