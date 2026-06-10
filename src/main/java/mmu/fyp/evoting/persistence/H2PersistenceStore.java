package mmu.fyp.evoting.persistence;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.entities.bulletinboard.BBEntry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * H2 embedded-file persistence backing the {@link mmu.fyp.evoting.gui.ElectionSystem}.
 *
 * <p>The store is created from a file path; H2 manages a single {@code .mv.db} file
 * at that location with no external server required. The same code works against
 * MySQL / PostgreSQL by changing only the JDBC URL — the SQL is standard
 * (insertions use {@code MERGE} for upserts which is the SQL:2003 keyword).
 *
 * <p>State persisted:
 * <ul>
 *   <li><b>election</b> (single row): candidate count, vid, voting-open flag, and
 *       all EC keys (EOLTAA user keypair + CA-issued certificate, MuSig2 member
 *       keypairs, Cramer-Shoup encryption keypair). EC keys must persist or
 *       previously-encrypted ballots become undecryptable.</li>
 *   <li><b>registered_voters</b>: D1 — every voter the CA has approved, with
 *       their (escrowed) EOLTAA user keypair and allocated directory position.</li>
 *   <li><b>pending_registrations</b>: requests waiting for the CA's decision.</li>
 *   <li><b>registration_outcomes</b>: approval/rejection history (one row per IC,
 *       latest outcome wins).</li>
 *   <li><b>bb_entries</b>: D2 + D3 — the hash-chained bulletin board, with each
 *       entry's serialised content plus the {@code prev}/{@code this} hash bytes
 *       so the chain can be replayed on load.</li>
 *   <li><b>citizen_registry</b>: pre-seeded eligible-citizen list (reference data
 *       — would be a live NRD lookup in production).</li>
 * </ul>
 */
public final class H2PersistenceStore implements AutoCloseable {

    private static final String SCHEMA_DDL = """
            CREATE TABLE IF NOT EXISTS election (
                id INT PRIMARY KEY,
                candidate_count INT NOT NULL,
                vid VARBINARY(64) NOT NULL,
                voting_open BOOLEAN NOT NULL DEFAULT FALSE,
                ec_upk         VARBINARY(64) NOT NULL,
                ec_usk         VARBINARY(64) NOT NULL,
                ec_cert_r      VARBINARY(64) NOT NULL,
                ec_cert_s      VARBINARY(64) NOT NULL,
                musig_members  VARBINARY(8192) NOT NULL,
                cs_pk_g2   VARBINARY(64) NOT NULL,
                cs_pk_c    VARBINARY(64) NOT NULL,
                cs_pk_d    VARBINARY(64) NOT NULL,
                cs_pk_h    VARBINARY(64) NOT NULL,
                cs_sk_x1   VARBINARY(64) NOT NULL,
                cs_sk_x2   VARBINARY(64) NOT NULL,
                cs_sk_y1   VARBINARY(64) NOT NULL,
                cs_sk_y2   VARBINARY(64) NOT NULL,
                cs_sk_z    VARBINARY(64) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registered_voters (
                ic VARCHAR(40) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                directory_position INT NOT NULL UNIQUE,
                user_pk VARBINARY(64) NOT NULL,
                user_sk VARBINARY(64) NOT NULL,
                registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS pending_registrations (
                ic VARCHAR(40) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                user_pk VARBINARY(64) NOT NULL,
                user_sk VARBINARY(64) NOT NULL,
                submitted_at BIGINT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registration_outcomes (
                ic VARCHAR(40) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                directory_position INT NOT NULL,
                status VARCHAR(500) NOT NULL,
                approved BOOLEAN NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bb_entries (
                idx INT PRIMARY KEY,
                entry_type VARCHAR(32) NOT NULL,
                content_bytes VARBINARY(65536) NOT NULL,
                prev_hash VARBINARY(64) NOT NULL,
                this_hash VARBINARY(64) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS citizen_registry (
                ic VARCHAR(40) PRIMARY KEY,
                name VARCHAR(255) NOT NULL
            );
            """;

    private final Connection conn;
    private final Path dbPath;

    public H2PersistenceStore(Path dbPath) throws SQLException, IOException {
        this.dbPath = dbPath;
        if (dbPath.getParent() != null) Files.createDirectories(dbPath.getParent());
        String url = "jdbc:h2:file:" + dbPath.toAbsolutePath() + ";DB_CLOSE_DELAY=-1";
        this.conn = DriverManager.getConnection(url, "sa", "");
        try (Statement st = conn.createStatement()) {
            for (String stmt : SCHEMA_DDL.split(";")) {
                String trimmed = stmt.trim();
                if (!trimmed.isEmpty()) st.execute(trimmed);
            }
        }
    }

    @Override
    public void close() throws SQLException {
        if (conn != null && !conn.isClosed()) conn.close();
    }

    public Path dbPath() { return dbPath; }

    /**
     * Default DB file location: {@code <project-root>/db/election}. The project root
     * is detected by walking up from the JVM's working directory looking for a
     * {@code pom.xml}, so the DB lives alongside the source tree regardless of where
     * the user launches from (CLI, NetBeans, double-click JAR, etc.). If no project
     * root is found, falls back to {@code <cwd>/db/election}.
     *
     * <p>Override with {@code -Dfyp.db.path=/some/other/path} when needed (e.g.
     * unit tests use a temp dir, production deployment uses a managed mount).
     */
    public static Path resolveDefaultDbPath() {
        String custom = System.getProperty("fyp.db.path");
        if (custom != null && !custom.isEmpty()) return Path.of(custom);
        Path root = findProjectRoot();
        return root.resolve("db").resolve("election");
    }

    private static Path findProjectRoot() {
        Path cwd = Path.of("").toAbsolutePath();
        Path probe = cwd;
        while (probe != null) {
            if (java.nio.file.Files.exists(probe.resolve("pom.xml"))) return probe;
            probe = probe.getParent();
        }
        return cwd; // fallback
    }

    // ---------- citizen registry ----------

    public record CitizenEntry(String name, String icNumber) {}

    /** Load all citizen rows; if table empty, seed with the supplied list and return that. */
    public synchronized List<CitizenEntry> loadOrSeedCitizenRegistry(List<CitizenEntry> seed) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT ic, name FROM citizen_registry ORDER BY ic")) {
            List<CitizenEntry> existing = new ArrayList<>();
            while (rs.next()) {
                existing.add(new CitizenEntry(rs.getString("name"), rs.getString("ic")));
            }
            if (!existing.isEmpty()) return existing;
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO citizen_registry (ic, name) VALUES (?, ?)")) {
            for (CitizenEntry c : seed) {
                ps.setString(1, c.icNumber());
                ps.setString(2, c.name());
                ps.addBatch();
            }
            ps.executeBatch();
        }
        return new ArrayList<>(seed);
    }

    // ---------- election + EC keys ----------

    public record LoadedElection(
            int candidateCount, byte[] vid, boolean votingOpen,
            EOLTAA.UserKeyPair ecKey, EOLTAA.Certificate ecCertificate,
            List<MuSig2.KeyPair> musigMembers, CramerShoup.KeyPair cs) {}

    public synchronized Optional<LoadedElection> loadElection() throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT * FROM election WHERE id = 1")) {
            if (!rs.next()) return Optional.empty();
            EOLTAA.UserKeyPair ecKey = new EOLTAA.UserKeyPair(
                    new EOLTAA.UserPublicKey(Serialization.decodePoint(rs.getBytes("ec_upk"))),
                    new EOLTAA.UserSecretKey(Serialization.decodeScalar(rs.getBytes("ec_usk"))));
            EOLTAA.Certificate ecCert = new EOLTAA.Certificate(
                    Serialization.decodePoint(rs.getBytes("ec_cert_r")),
                    Serialization.decodeScalar(rs.getBytes("ec_cert_s")));
            List<MuSig2.KeyPair> musig = decodeMusigMembers(rs.getBytes("musig_members"));
            CramerShoup.PublicKey csPk = new CramerShoup.PublicKey(
                    Serialization.decodePoint(rs.getBytes("cs_pk_g2")),
                    Serialization.decodePoint(rs.getBytes("cs_pk_c")),
                    Serialization.decodePoint(rs.getBytes("cs_pk_d")),
                    Serialization.decodePoint(rs.getBytes("cs_pk_h")));
            CramerShoup.SecretKey csSk = new CramerShoup.SecretKey(
                    Serialization.decodeScalar(rs.getBytes("cs_sk_x1")),
                    Serialization.decodeScalar(rs.getBytes("cs_sk_x2")),
                    Serialization.decodeScalar(rs.getBytes("cs_sk_y1")),
                    Serialization.decodeScalar(rs.getBytes("cs_sk_y2")),
                    Serialization.decodeScalar(rs.getBytes("cs_sk_z")));
            return Optional.of(new LoadedElection(
                    rs.getInt("candidate_count"), rs.getBytes("vid"), rs.getBoolean("voting_open"),
                    ecKey, ecCert, musig, new CramerShoup.KeyPair(csPk, csSk)));
        }
    }

    public synchronized void saveElection(int candidateCount, byte[] vid, boolean votingOpen,
                                          EOLTAA.UserKeyPair ecKey, EOLTAA.Certificate ecCert,
                                          List<MuSig2.KeyPair> musigMembers,
                                          CramerShoup.KeyPair cs) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "MERGE INTO election (id, candidate_count, vid, voting_open, "
              + "ec_upk, ec_usk, ec_cert_r, ec_cert_s, musig_members, "
              + "cs_pk_g2, cs_pk_c, cs_pk_d, cs_pk_h, "
              + "cs_sk_x1, cs_sk_x2, cs_sk_y1, cs_sk_y2, cs_sk_z) "
              + "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            int i = 1;
            ps.setInt(i++, candidateCount);
            ps.setBytes(i++, vid);
            ps.setBoolean(i++, votingOpen);
            ps.setBytes(i++, Serialization.encodePoint(ecKey.upk().Y()));
            ps.setBytes(i++, Serialization.encodeScalar(ecKey.usk().x()));
            ps.setBytes(i++, Serialization.encodePoint(ecCert.R()));
            ps.setBytes(i++, Serialization.encodeScalar(ecCert.s()));
            ps.setBytes(i++, encodeMusigMembers(musigMembers));
            ps.setBytes(i++, Serialization.encodePoint(cs.pk().g2()));
            ps.setBytes(i++, Serialization.encodePoint(cs.pk().c()));
            ps.setBytes(i++, Serialization.encodePoint(cs.pk().d()));
            ps.setBytes(i++, Serialization.encodePoint(cs.pk().h()));
            ps.setBytes(i++, Serialization.encodeScalar(cs.sk().x1()));
            ps.setBytes(i++, Serialization.encodeScalar(cs.sk().x2()));
            ps.setBytes(i++, Serialization.encodeScalar(cs.sk().y1()));
            ps.setBytes(i++, Serialization.encodeScalar(cs.sk().y2()));
            ps.setBytes(i, Serialization.encodeScalar(cs.sk().z()));
            ps.executeUpdate();
        }
    }

    /** Concatenate (length-prefixed) the n MuSig2 member keypairs into one VARBINARY blob. */
    private static byte[] encodeMusigMembers(List<MuSig2.KeyPair> members) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            out.writeInt(members.size());
            for (MuSig2.KeyPair kp : members) {
                byte[] pk = Serialization.encodePoint(kp.pk().X());
                byte[] sk = Serialization.encodeScalar(kp.sk().x());
                out.writeInt(pk.length); out.write(pk);
                out.writeInt(sk.length); out.write(sk);
            }
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("failed to encode MuSig2 members", e);
        }
    }

    private static List<MuSig2.KeyPair> decodeMusigMembers(byte[] blob) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(blob))) {
            int n = in.readInt();
            List<MuSig2.KeyPair> out = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                int pkLen = in.readInt();  byte[] pk = in.readNBytes(pkLen);
                int skLen = in.readInt();  byte[] sk = in.readNBytes(skLen);
                out.add(new MuSig2.KeyPair(
                        new MuSig2.PublicKey(Serialization.decodePoint(pk)),
                        new MuSig2.SecretKey(Serialization.decodeScalar(sk))));
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("failed to decode MuSig2 members", e);
        }
    }

    public synchronized void setVotingOpen(boolean open) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE election SET voting_open = ? WHERE id = 1")) {
            ps.setBoolean(1, open);
            ps.executeUpdate();
        }
    }

    // ---------- registered voters ----------

    // user_pk / user_sk are the voter's EOLTAA user keypair (compressed
    // secp256k1 point + 256-bit scalar). The CA holds them in escrow per
    // §3.7.2 of the deviation notes so it can compute event-bound linking
    // tags during tracing.

    public record RegisteredVoter(String icNumber, String name, int directoryPosition,
                                  EOLTAA.UserKeyPair credentials) {}

    public synchronized void insertRegisteredVoter(String ic, String name, int directoryPosition,
                                                   EOLTAA.UserKeyPair kp) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO registered_voters (ic, name, directory_position, user_pk, user_sk) "
              + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, ic);
            ps.setString(2, name);
            ps.setInt(3, directoryPosition);
            ps.setBytes(4, Serialization.encodePoint(kp.upk().Y()));
            ps.setBytes(5, Serialization.encodeScalar(kp.usk().x()));
            ps.executeUpdate();
        }
    }

    public synchronized List<RegisteredVoter> loadRegisteredVoters() throws SQLException {
        List<RegisteredVoter> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT ic, name, directory_position, user_pk, user_sk "
                   + "FROM registered_voters ORDER BY directory_position")) {
            while (rs.next()) {
                EOLTAA.UserKeyPair kp = new EOLTAA.UserKeyPair(
                        new EOLTAA.UserPublicKey(Serialization.decodePoint(rs.getBytes("user_pk"))),
                        new EOLTAA.UserSecretKey(Serialization.decodeScalar(rs.getBytes("user_sk"))));
                out.add(new RegisteredVoter(
                        rs.getString("ic"), rs.getString("name"),
                        rs.getInt("directory_position"), kp));
            }
        }
        return out;
    }

    // ---------- pending registrations ----------

    public record PendingRow(String icNumber, String name, EOLTAA.UserKeyPair credentials, long submittedAt) {}

    public synchronized void insertPendingRegistration(String ic, String name,
                                                       EOLTAA.UserKeyPair kp, long submittedAt) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO pending_registrations (ic, name, user_pk, user_sk, submitted_at) "
              + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, ic);
            ps.setString(2, name);
            ps.setBytes(3, Serialization.encodePoint(kp.upk().Y()));
            ps.setBytes(4, Serialization.encodeScalar(kp.usk().x()));
            ps.setLong(5, submittedAt);
            ps.executeUpdate();
        }
    }

    public synchronized void deletePendingRegistration(String ic) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "DELETE FROM pending_registrations WHERE ic = ?")) {
            ps.setString(1, ic);
            ps.executeUpdate();
        }
    }

    public synchronized List<PendingRow> loadPendingRegistrations() throws SQLException {
        List<PendingRow> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT ic, name, user_pk, user_sk, submitted_at "
                   + "FROM pending_registrations ORDER BY submitted_at")) {
            while (rs.next()) {
                EOLTAA.UserKeyPair kp = new EOLTAA.UserKeyPair(
                        new EOLTAA.UserPublicKey(Serialization.decodePoint(rs.getBytes("user_pk"))),
                        new EOLTAA.UserSecretKey(Serialization.decodeScalar(rs.getBytes("user_sk"))));
                out.add(new PendingRow(
                        rs.getString("ic"), rs.getString("name"),
                        kp, rs.getLong("submitted_at")));
            }
        }
        return out;
    }

    // ---------- registration outcomes ----------

    public record OutcomeRow(String icNumber, String name, int directoryPosition,
                             String status, boolean approved) {}

    public synchronized void upsertRegistrationOutcome(String ic, String name, int directoryPosition,
                                                       String status, boolean approved) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "MERGE INTO registration_outcomes (ic, name, directory_position, status, approved) "
              + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, ic);
            ps.setString(2, name);
            ps.setInt(3, directoryPosition);
            ps.setString(4, status);
            ps.setBoolean(5, approved);
            ps.executeUpdate();
        }
    }

    public synchronized List<OutcomeRow> loadRegistrationOutcomes() throws SQLException {
        List<OutcomeRow> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT ic, name, directory_position, status, approved "
                   + "FROM registration_outcomes ORDER BY directory_position, ic")) {
            while (rs.next()) {
                out.add(new OutcomeRow(
                        rs.getString("ic"), rs.getString("name"),
                        rs.getInt("directory_position"), rs.getString("status"),
                        rs.getBoolean("approved")));
            }
        }
        return out;
    }

    // ---------- BB entries ----------

    public record BBRow(int idx, BBEntry content, byte[] prevHash, byte[] thisHash) {}

    public synchronized void appendBBEntry(int idx, BBEntry entry, byte[] prevHash, byte[] thisHash)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO bb_entries (idx, entry_type, content_bytes, prev_hash, this_hash) "
              + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setInt(1, idx);
            ps.setString(2, Serialization.bbEntryTypeLabel(entry));
            ps.setBytes(3, Serialization.encodeBBEntry(entry));
            ps.setBytes(4, prevHash);
            ps.setBytes(5, thisHash);
            ps.executeUpdate();
        }
    }

    public synchronized List<BBRow> loadBBEntries() throws SQLException {
        List<BBRow> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT idx, content_bytes, prev_hash, this_hash "
                   + "FROM bb_entries ORDER BY idx")) {
            while (rs.next()) {
                BBEntry content = Serialization.decodeBBEntry(rs.getBytes("content_bytes"));
                out.add(new BBRow(rs.getInt("idx"), content,
                        rs.getBytes("prev_hash"), rs.getBytes("this_hash")));
            }
        }
        return out;
    }

    // ---------- reset ----------

    /** Wipe election state but keep the citizen registry. */
    public synchronized void reset() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("DELETE FROM bb_entries");
            st.execute("DELETE FROM registration_outcomes");
            st.execute("DELETE FROM pending_registrations");
            st.execute("DELETE FROM registered_voters");
            st.execute("DELETE FROM election");
        }
    }
}
