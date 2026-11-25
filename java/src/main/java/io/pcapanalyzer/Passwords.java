package io.pcapanalyzer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/** The password of the shared login. A password set in the app is kept as a salted hash and replaces PCAP_ANALYZER_ADMIN_PASSWORD. */
public final class Passwords {
    public static final int MIN_LENGTH = 12;
    private static final int ITERATIONS = 210_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Passwords() {}

    private static byte[] hash(String password, byte[] salt) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256)).getEncoded();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> stored() {
        try {
            Object o = Json.parse(Files.readString(Settings.workdir().resolve("password.json"), StandardCharsets.UTF_8));
            return o instanceof Map ? (Map<String, Object>) o : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** True when a password is set, in the app or in the environment. */
    public static boolean configured() { return stored() != null || !Settings.adminPassword().isEmpty(); }

    public static boolean matches(String candidate) {
        Map<String, Object> s = stored();
        if (s == null) {
            String env = Settings.adminPassword();
            return !env.isEmpty() && MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8), env.getBytes(StandardCharsets.UTF_8));
        }
        return MessageDigest.isEqual(hash(candidate, HexFormat.of().parseHex((String) s.get("salt"))), HexFormat.of().parseHex((String) s.get("hash")));
    }

    public static void save(String password) throws IOException {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("salt", HexFormat.of().formatHex(salt)); m.put("hash", HexFormat.of().formatHex(hash(password, salt)));
        Files.createDirectories(Settings.workdir());
        Path tmp = Settings.workdir().resolve("password.json.tmp");
        Files.writeString(tmp, Json.write(m), StandardCharsets.UTF_8);
        Files.move(tmp, Settings.workdir().resolve("password.json"), StandardCopyOption.ATOMIC_MOVE);
    }
}
