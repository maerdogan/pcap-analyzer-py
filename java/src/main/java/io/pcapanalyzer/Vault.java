package io.pcapanalyzer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.Logger;

/**
 * Everything the app keeps on disk is encrypted here: captures, analysis results, users, settings and the audit log.
 *
 * <p>Each file has its own random 256-bit key and is encrypted with AES-256-GCM in 1 MiB segments, so captures of any size stream
 * without being held in memory, and a changed, cut or reordered segment is found. The file key is wrapped with the data key pair,
 * RSA-2048 with OAEP and SHA-256. Writing needs only its public half, so uploads work at any time.
 *
 * <p>The private half of the data key pair is encrypted with the master key, a 16-character secret the admin sets. The master key is in
 * turn wrapped with a second RSA-2048 key pair, whose private half is encrypted with a key derived from the setup admin's password
 * (PBKDF2-HMAC-SHA256, 310,000 rounds). So after a restart nothing can be read until the admin signs in; a copy of the folder on another
 * machine cannot be opened without the admin's password. A new admin password re-wraps only the admin key pair, and a new master key
 * re-encrypts only the data private key, so no file has to be rewritten.
 */
final class Vault {
    static final String ALGORITHM = "Files: AES-256-GCM in 1 MiB segments, a random key per file. File keys: RSA-2048 OAEP (SHA-256). "
            + "Data private key: AES-256-GCM with a key derived from the master key (PBKDF2-HMAC-SHA256, 310,000 rounds). "
            + "Master key: RSA-2048 OAEP with the admin key pair, whose private key is AES-256-GCM with a key derived from the setup admin's password (PBKDF2-HMAC-SHA256, 310,000 rounds). "
            + "User passwords: PBKDF2-HMAC-SHA256 (210,000 rounds) one-way hashes, inside the encrypted users file.";

    private static final Logger LOG = Logger.getLogger(Vault.class.getName());
    private static final byte[] MAGIC = "PAV1".getBytes(StandardCharsets.US_ASCII);
    private static final int SEGMENT = 1 << 20, TAG_BITS = 128, ROUNDS = 310_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private static volatile PublicKey dataPub;
    private static volatile PrivateKey dataPriv;
    private static volatile String master;
    private static volatile byte[] adminCheck;          // salted digest of the admin password that unlocked the vault, for fast checks
    private static final byte[] CHECK_SALT = new byte[16];
    static { RANDOM.nextBytes(CHECK_SALT); }

    /** Problems with files found while reading them: changed, cut, unencrypted or of unknown origin. Admins see them as a notice. */
    private static final List<Map<String, Object>> ALERTS = Collections.synchronizedList(new ArrayList<>());

    private Vault() {}

    static Path keyring() { return Settings.workdir().resolve(".keyring"); }

    static boolean isSetUp() { return Files.isRegularFile(keyring()); }
    static boolean isUnlocked() { return dataPriv != null; }

    /** The master key, for the admin to see. Null while locked. */
    static String masterKey() { return master; }

    /** 16 characters, at least one of them neither a letter nor a digit. Returns the problem as an English UI text, or null. */
    static String masterProblem(String key) {
        if (key == null || key.length() != 16) return "The master key must have exactly 16 characters.";
        if (key.chars().allMatch(Character::isLetterOrDigit)) return "The master key must not be only letters and digits. Add at least one sign such as ! or #.";
        if (key.chars().anyMatch(ch -> ch < 33 || ch > 126)) return "Use printable characters without spaces in the master key.";
        return null;
    }

    // ---- key management

    /** Creates both key pairs, encrypts every file already in the work folder and forgets the old plain admin password file. */
    static synchronized void setUp(String adminPassword, String masterKey) throws IOException, GeneralSecurityException {
        if (isSetUp()) throw new IllegalStateException("already set up");
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048, RANDOM);
        KeyPair data = g.generateKeyPair(), admin = g.generateKeyPair();
        Map<String, Object> ring = new LinkedHashMap<>();
        ring.put("version", 1);
        ring.put("data_public", b64(data.getPublic().getEncoded()));
        ring.put("data_private", seal(data.getPrivate().getEncoded(), masterKey));
        ring.put("admin_public", b64(admin.getPublic().getEncoded()));
        ring.put("admin_private", seal(admin.getPrivate().getEncoded(), adminPassword));
        ring.put("master", b64(rsa(Cipher.ENCRYPT_MODE, admin.getPublic(), masterKey.getBytes(StandardCharsets.UTF_8))));
        writeRing(ring);
        dataPub = data.getPublic(); dataPriv = data.getPrivate(); master = masterKey; adminCheck = check(adminPassword);
        Records.hideAudit();
        migrate(Settings.workdir());
        Files.deleteIfExists(Settings.workdir().resolve("password.json"));
        LOG.info("Vault set up; files in the work folder are encrypted");
    }

    /** Opens the vault with the setup admin's password. Returns false when the password is wrong. */
    static synchronized boolean unlock(String adminPassword) {
        if (isUnlocked()) return checkAdmin(adminPassword);
        try {
            Map<String, Object> ring = ring();
            PrivateKey adminPriv = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(open(ring.get("admin_private"), adminPassword)));
            String mk = new String(rsa(Cipher.DECRYPT_MODE, adminPriv, unb64(ring.get("master"))), StandardCharsets.UTF_8);
            PrivateKey priv = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(open(ring.get("data_private"), mk)));
            dataPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(ring.get("data_public"))));
            master = mk; dataPriv = priv; adminCheck = check(adminPassword);
            LOG.info("Vault unlocked by the setup admin");
            return true;
        } catch (javax.crypto.AEADBadTagException e) {
            return false;
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            alert(keyring(), "The key file could not be read: " + e.getClass().getSimpleName());
            return false;
        }
    }

    /** True when the password is the setup admin's. Checks the admin key without unlocking anything else. */
    static boolean checkAdmin(String adminPassword) {
        byte[] c = adminCheck;
        if (c != null) return MessageDigest.isEqual(c, check(adminPassword));
        try { open(ring().get("admin_private"), adminPassword); return true; } catch (Exception e) { return false; }
    }

    /** A new setup admin password: only the admin private key is re-encrypted. */
    static synchronized void changeAdminPassword(String oldPassword, String newPassword) throws IOException, GeneralSecurityException {
        Map<String, Object> ring = ring();
        byte[] adminPriv = open(ring.get("admin_private"), oldPassword);
        ring.put("admin_private", seal(adminPriv, newPassword));
        writeRing(ring);
        adminCheck = check(newPassword);
    }

    /** A new master key: the data private key is re-encrypted with it, and it is wrapped again for the admin. */
    static synchronized void changeMaster(String newMaster) throws IOException, GeneralSecurityException {
        if (!isUnlocked()) throw new IllegalStateException("locked");
        Map<String, Object> ring = ring();
        PublicKey adminPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(ring.get("admin_public"))));
        ring.put("data_private", seal(dataPriv.getEncoded(), newMaster));
        ring.put("master", b64(rsa(Cipher.ENCRYPT_MODE, adminPub, newMaster.getBytes(StandardCharsets.UTF_8))));
        writeRing(ring);
        master = newMaster;
    }

    private static PublicKey publicKey() throws IOException, GeneralSecurityException {
        PublicKey p = dataPub;
        if (p == null) dataPub = p = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(ring().get("data_public"))));
        return p;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ring() throws IOException {
        return (Map<String, Object>) Json.parse(Files.readString(keyring(), StandardCharsets.UTF_8));
    }

    private static void writeRing(Map<String, Object> ring) throws IOException {
        Files.createDirectories(Settings.workdir());
        Path tmp = Settings.workdir().resolve(".keyring.tmp");
        Files.writeString(tmp, Json.write(ring), StandardCharsets.UTF_8);
        private600(tmp);
        Files.move(tmp, keyring(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    // ---- files

    static final class LockedException extends IOException {
        LockedException() { super("The vault is locked until the admin signs in."); }
    }

    /** True when the file starts like a vault file. */
    static boolean encrypted(Path file) {
        try (InputStream in = Files.newInputStream(file)) { return Arrays.equals(in.readNBytes(4), MAGIC); } catch (IOException e) { return false; }
    }

    /** A JSON file read through the vault; null when it is missing or cannot be read. */
    static Object readJson(Path file) {
        try { return Files.exists(file) ? Json.parse(readText(file)) : null; } catch (IOException | RuntimeException e) { return null; }
    }

    /** Text of a file. A plain file is read as it is only before the vault is set up; afterwards it is a changed file. */
    static String readText(Path file) throws IOException {
        try (InputStream in = in(file)) { return new String(in.readAllBytes(), StandardCharsets.UTF_8); }
    }

    static void writeText(Path file, String text) throws IOException {
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try (OutputStream out = out(tmp)) { out.write(text.getBytes(StandardCharsets.UTF_8)); }
        Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** Reads a file, decrypting it as it streams. A changed segment, a cut file or a plain file where an encrypted one belongs is reported to the admin. */
    static InputStream in(Path file) throws IOException {
        InputStream raw = new BufferedInputStream(Files.newInputStream(file), 1 << 16);
        raw.mark(4);
        boolean enc = Arrays.equals(raw.readNBytes(4), MAGIC);
        raw.reset();
        if (!enc) {
            if (!isSetUp()) return raw;
            raw.close();
            alert(file, "The file is not encrypted. It was put or changed by hand.");
            throw new IOException("unencrypted file: " + file.getFileName());
        }
        if (!isUnlocked()) { raw.close(); throw new LockedException(); }
        raw.skipNBytes(4);
        DataInputStream d = new DataInputStream(raw);
        byte[] wrapped = new byte[d.readUnsignedShort()];
        d.readFully(wrapped);
        byte[] prefix = new byte[4];
        d.readFully(prefix);
        SecretKey key;
        try { key = new SecretKeySpec(rsa(Cipher.DECRYPT_MODE, dataPriv, wrapped), "AES"); }
        catch (GeneralSecurityException e) { d.close(); alert(file, "The file key does not open. The file was changed by hand."); throw new IOException("bad file key", e); }
        return new SegmentIn(d, key, prefix, file);
    }

    /** Writes a file encrypted, or plain before the vault is set up. */
    static OutputStream out(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        OutputStream raw = new BufferedOutputStream(Files.newOutputStream(file), 1 << 16);
        try { private600(file); } catch (IOException ignored) { }
        if (!isSetUp()) return raw;
        return wrap(raw);
    }

    /** The encrypting stream over any output: header with the wrapped file key, then segments. */
    static OutputStream wrap(OutputStream raw) throws IOException {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, RANDOM);
            SecretKey key = kg.generateKey();
            byte[] wrapped = rsa(Cipher.ENCRYPT_MODE, publicKey(), key.getEncoded());
            byte[] prefix = new byte[4];
            RANDOM.nextBytes(prefix);
            DataOutputStream d = new DataOutputStream(raw);
            d.write(MAGIC); d.writeShort(wrapped.length); d.write(wrapped); d.write(prefix);
            return new SegmentOut(d, key, prefix);
        } catch (GeneralSecurityException e) {
            raw.close();
            throw new IOException(e);
        }
    }

    /** Small data encrypted as one vault blob, such as one line of the audit log. */
    static byte[] sealBytes(byte[] plain) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (OutputStream o = wrap(bo)) { o.write(plain); }
        return bo.toByteArray();
    }

    static byte[] openBytes(byte[] blob, Path forNotice) throws IOException {
        if (!isUnlocked()) throw new LockedException();
        if (blob.length < 4 || !Arrays.equals(Arrays.copyOf(blob, 4), MAGIC)) { alert(forNotice, "A record is not encrypted. The file was changed by hand."); throw new IOException("plain record"); }
        DataInputStream d = new DataInputStream(new ByteArrayInputStream(blob, 4, blob.length - 4));
        byte[] wrapped = new byte[d.readUnsignedShort()];
        d.readFully(wrapped);
        byte[] prefix = new byte[4];
        d.readFully(prefix);
        try (InputStream in = new SegmentIn(d, new SecretKeySpec(rsa(Cipher.DECRYPT_MODE, dataPriv, wrapped), "AES"), prefix, forNotice)) { return in.readAllBytes(); }
        catch (GeneralSecurityException e) { alert(forNotice, "A record does not open. The file was changed by hand."); throw new IOException(e); }
    }

    /** Encrypts a plain file in place. */
    static void encryptInPlace(Path file) throws IOException {
        if (!isSetUp() || encrypted(file)) return;
        Path tmp = file.resolveSibling(file.getFileName() + ".enc.tmp");
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file)); OutputStream out = out(tmp)) { in.transferTo(out); }
        Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** Encrypts every plain file under the work folder, except the bundled tshark. */
    private static void migrate(Path root) throws IOException {
        try (var walk = Files.walk(root)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (!Files.isRegularFile(p) || p.startsWith(root.resolve(".runtime")) || p.equals(keyring()) || p.equals(Records.auditFile()) || p.getFileName().toString().equals("password.json")) continue;
                encryptInPlace(p);
            }
        }
    }

    /** Reads a whole file to its end, so every segment's tag is checked. Returns false and raises a notice when it does not verify. */
    static boolean verify(Path file) {
        try (InputStream in = in(file)) { in.transferTo(OutputStream.nullOutputStream()); return true; }
        catch (LockedException e) { return true; }
        catch (IOException e) { return false; }
    }

    // ---- notices

    static void alert(Path file, String reason) {
        Path wd = Settings.workdir();
        String name = file.startsWith(wd) ? wd.relativize(file).toString() : file.getFileName().toString();
        synchronized (ALERTS) {
            for (Map<String, Object> a : ALERTS) if (name.equals(a.get("file")) && reason.equals(a.get("reason"))) return;
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("time", System.currentTimeMillis() / 1000.0); a.put("file", name); a.put("reason", reason);
            ALERTS.add(a);
            if (ALERTS.size() > 200) ALERTS.remove(0);
        }
        LOG.warning("File integrity: " + name + ": " + reason);
        Records.audit("file_tampered", "server", name + ": " + reason);
    }

    /** Forgets the keys in memory, as a restart does. */
    static synchronized void lock() { dataPub = null; dataPriv = null; master = null; adminCheck = null; }

    static List<Map<String, Object>> alerts() { synchronized (ALERTS) { return new ArrayList<>(ALERTS); } }
    static void clearAlerts() { ALERTS.clear(); }

    // ---- primitives

    /** AES-256-GCM with a key derived from a secret: {salt, iv, data} in base64. */
    private static Map<String, Object> seal(byte[] plain, String secret) throws GeneralSecurityException {
        byte[] salt = new byte[16], iv = new byte[12];
        RANDOM.nextBytes(salt); RANDOM.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, derive(secret, salt), new GCMParameterSpec(TAG_BITS, iv));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("salt", b64(salt)); m.put("iv", b64(iv)); m.put("data", b64(c.doFinal(plain)));
        return m;
    }

    @SuppressWarnings("unchecked")
    private static byte[] open(Object sealed, String secret) throws GeneralSecurityException {
        Map<String, Object> m = (Map<String, Object>) sealed;
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, derive(secret, unb64(m.get("salt"))), new GCMParameterSpec(TAG_BITS, unb64(m.get("iv"))));
        return c.doFinal(unb64(m.get("data")));
    }

    private static SecretKey derive(String secret, byte[] salt) throws GeneralSecurityException {
        byte[] k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(secret.toCharArray(), salt, ROUNDS, 256)).getEncoded();
        return new SecretKeySpec(k, "AES");
    }

    private static byte[] rsa(int mode, Key key, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(mode, key, OAEP);
        return c.doFinal(data);
    }

    private static byte[] check(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(CHECK_SALT);
            return md.digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] unb64(Object s) { return Base64.getDecoder().decode(String.valueOf(s)); }

    static void private600(Path p) throws IOException {
        try { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); } catch (UnsupportedOperationException ignored) { }
    }

    /** Nonce of a segment: the file's random prefix and the segment number. The last segment is marked in the associated data, so a cut file is found. */
    private static byte[] nonce(byte[] prefix, long index) {
        return ByteBuffer.allocate(12).put(prefix).putLong(index).array();
    }

    private static byte[] aad(long index, boolean last) {
        return ByteBuffer.allocate(9).putLong(index).put((byte) (last ? 1 : 0)).array();
    }

    private static final class SegmentOut extends OutputStream {
        private final DataOutputStream out;
        private final SecretKey key;
        private final byte[] prefix, buf = new byte[SEGMENT];
        private int n;
        private long index;
        private boolean closed;

        SegmentOut(DataOutputStream out, SecretKey key, byte[] prefix) { this.out = out; this.key = key; this.prefix = prefix; }

        @Override public void write(int b) throws IOException { if (n == SEGMENT) flushSegment(false); buf[n++] = (byte) b; }

        @Override public void write(byte[] b, int off, int len) throws IOException {
            while (len > 0) {
                if (n == SEGMENT) flushSegment(false);
                int k = Math.min(len, SEGMENT - n);
                System.arraycopy(b, off, buf, n, k);
                n += k; off += k; len -= k;
            }
        }

        private void flushSegment(boolean last) throws IOException {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce(prefix, index)));
                c.updateAAD(aad(index, last));
                byte[] ct = c.doFinal(buf, 0, n);
                out.writeByte(last ? 1 : 0); out.writeInt(ct.length); out.write(ct);
                index++; n = 0;
            } catch (GeneralSecurityException e) { throw new IOException(e); }
        }

        @Override public void close() throws IOException {
            if (closed) return;
            closed = true;
            flushSegment(true);
            out.close();
        }
    }

    private static final class SegmentIn extends InputStream {
        private final DataInputStream in;
        private final SecretKey key;
        private final byte[] prefix;
        private final Path file;
        private byte[] buf = new byte[0];
        private int pos;
        private long index;
        private boolean done;

        SegmentIn(DataInputStream in, SecretKey key, byte[] prefix, Path file) { this.in = in; this.key = key; this.prefix = prefix; this.file = file; }

        private boolean fill() throws IOException {
            while (pos >= buf.length) {
                if (done) return false;
                int last, len;
                try { last = in.readUnsignedByte(); len = in.readInt(); }
                catch (EOFException e) { alert(file, "The file ends early. It was cut or changed by hand."); throw new IOException("cut file", e); }
                if (len < 16 || len > SEGMENT + 16) { alert(file, "A segment has a wrong length. The file was changed by hand."); throw new IOException("bad segment"); }
                byte[] ct = new byte[len];
                try { in.readFully(ct); } catch (EOFException e) { alert(file, "The file ends early. It was cut or changed by hand."); throw new IOException("cut file", e); }
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce(prefix, index)));
                    c.updateAAD(aad(index, last == 1));
                    buf = c.doFinal(ct);
                } catch (GeneralSecurityException e) {
                    alert(file, "A segment does not verify. The file was changed by hand.");
                    throw new IOException("changed file", e);
                }
                pos = 0; index++;
                if (last == 1) {
                    done = true;
                    if (in.read() != -1) { alert(file, "Data follows the end of the file. It was changed by hand."); throw new IOException("trailing data"); }
                }
            }
            return true;
        }

        @Override public int read() throws IOException { return fill() ? buf[pos++] & 0xff : -1; }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (!fill()) return -1;
            int k = Math.min(len, buf.length - pos);
            System.arraycopy(buf, pos, b, off, k);
            pos += k;
            return k;
        }

        @Override public void close() throws IOException { in.close(); }
    }
}
