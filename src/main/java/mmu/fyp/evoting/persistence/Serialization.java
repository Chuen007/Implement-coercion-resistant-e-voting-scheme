package mmu.fyp.evoting.persistence;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.bulletinboard.BBEntry;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.ParamNotice;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom byte-level encoders / decoders for every type the persistence layer
 * needs to write to or read from the database. The format is deterministic and
 * fixed by this class; it is independent of Java's built-in serialisation
 * (which is fragile across JVM versions and has known security risks).
 *
 * <p>The encoding is length-prefixed for variable-size types (BigInteger,
 * String, List, Map) and fixed-length for ECPoint (compressed secp256k1, 33
 * bytes). Sealed-interface members (BBEntry subtypes) are tagged with a single
 * byte discriminator.
 */
public final class Serialization {

    /** Tag bytes for the BBEntry sealed hierarchy. */
    private static final byte TAG_VID    = 1;
    private static final byte TAG_BALLOT = 2;
    private static final byte TAG_TALLY  = 3;
    private static final byte TAG_PARAM  = 4;

    private Serialization() {}

    // ---------- low-level helpers ----------

    public static byte[] encodePoint(ECPoint p) {
        return Group.encode(p); // 33 bytes for compressed secp256k1
    }

    public static ECPoint decodePoint(byte[] bytes) {
        return Group.decode(bytes);
    }

    public static byte[] encodeScalar(BigInteger s) {
        return s.toByteArray();
    }

    public static BigInteger decodeScalar(byte[] bytes) {
        return new BigInteger(bytes);
    }

    private static void writeBytes(DataOutputStream out, byte[] b) throws IOException {
        out.writeInt(b.length);
        out.write(b);
    }

    private static byte[] readBytes(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > 1_000_000) throw new IOException("invalid length: " + n);
        byte[] b = new byte[n];
        in.readFully(b);
        return b;
    }

    private static void writePoint(DataOutputStream out, ECPoint p) throws IOException {
        writeBytes(out, encodePoint(p));
    }

    private static ECPoint readPoint(DataInputStream in) throws IOException {
        return decodePoint(readBytes(in));
    }

    private static void writeScalar(DataOutputStream out, BigInteger s) throws IOException {
        writeBytes(out, encodeScalar(s));
    }

    private static BigInteger readScalar(DataInputStream in) throws IOException {
        return decodeScalar(readBytes(in));
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        writeBytes(out, s.getBytes(StandardCharsets.UTF_8));
    }

    private static String readString(DataInputStream in) throws IOException {
        return new String(readBytes(in), StandardCharsets.UTF_8);
    }

    // ---------- EOLTAA authentication token ----------

    public static byte[] encodeAuthToken(EOLTAA.AuthToken token) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            writePoint(out, token.linkingTag());
            out.writeInt(token.challenges().size());
            for (BigInteger c : token.challenges()) writeScalar(out, c);
            out.writeInt(token.responses().size());
            for (BigInteger s : token.responses()) writeScalar(out, s);
            writeBytes(out, token.event());
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static EOLTAA.AuthToken decodeAuthToken(byte[] bytes) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            ECPoint linkingTag = readPoint(in);
            int cn = in.readInt();
            List<BigInteger> challenges = new ArrayList<>(cn);
            for (int i = 0; i < cn; i++) challenges.add(readScalar(in));
            int sn = in.readInt();
            List<BigInteger> responses = new ArrayList<>(sn);
            for (int i = 0; i < sn; i++) responses.add(readScalar(in));
            byte[] event = readBytes(in);
            return new EOLTAA.AuthToken(linkingTag, challenges, responses, event);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------- Cramer-Shoup ----------

    public static byte[] encodeCramerShoupCiphertext(CramerShoup.Ciphertext ct) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            writePoint(out, ct.u1());
            writePoint(out, ct.u2());
            writePoint(out, ct.e());
            writePoint(out, ct.v());
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static CramerShoup.Ciphertext decodeCramerShoupCiphertext(byte[] bytes) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            return new CramerShoup.Ciphertext(
                    readPoint(in), readPoint(in), readPoint(in), readPoint(in));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------- BulletinBoard entries (tagged union) ----------

    public static byte[] encodeBBEntry(BBEntry entry) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            switch (entry) {
                case ParamNotice p -> {
                    out.writeByte(TAG_PARAM);
                    writeString(out, p.groupName());
                    writeString(out, p.musigScheme());
                    writeScalar(out, p.sigmaChallengeOrder());
                    writeString(out, p.commitmentScheme());
                    writeString(out, p.pkeScheme());
                }
                case VidNotice v -> {
                    out.writeByte(TAG_VID);
                    writeBytes(out, v.vid());
                    writeBytes(out, encodeAuthToken(v.ecAuth()));
                }
                case Ballot b -> {
                    out.writeByte(TAG_BALLOT);
                    writeBytes(out, encodeCramerShoupCiphertext(b.ct()));
                    writeBytes(out, encodeAuthToken(b.voterAuth()));
                }
                case TallyResult r -> {
                    out.writeByte(TAG_TALLY);
                    out.writeInt(r.counts().size());
                    for (Map.Entry<Integer, Integer> e : r.counts().entrySet()) {
                        out.writeInt(e.getKey());
                        out.writeInt(e.getValue());
                    }
                    out.writeInt(r.tracedDoubleVoters().size());
                    for (String id : r.tracedDoubleVoters()) writeString(out, id);
                    // Decryption records: (u1, e, plaintext) per counted ballot
                    out.writeInt(r.decryptions().size());
                    for (TallyResult.DecryptionRecord d : r.decryptions()) {
                        writePoint(out, d.u1());
                        writePoint(out, d.e());
                        writePoint(out, d.plaintext());
                    }
                    // π_result NIZK transcript
                    boolean hasProof = r.decryptionProof() != null;
                    out.writeBoolean(hasProof);
                    if (hasProof) {
                        out.writeInt(r.decryptionProof().first().a().size());
                        for (ECPoint p : r.decryptionProof().first().a()) writePoint(out, p);
                        writeScalar(out, r.decryptionProof().challenge());
                        writeScalar(out, r.decryptionProof().response());
                    }
                }
            }
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static BBEntry decodeBBEntry(byte[] bytes) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            byte tag = in.readByte();
            return switch (tag) {
                case TAG_PARAM -> new ParamNotice(
                        readString(in), readString(in), readScalar(in),
                        readString(in), readString(in));
                case TAG_VID -> new VidNotice(readBytes(in), decodeAuthToken(readBytes(in)));
                case TAG_BALLOT -> new Ballot(
                        decodeCramerShoupCiphertext(readBytes(in)),
                        decodeAuthToken(readBytes(in)));
                case TAG_TALLY -> {
                    int countN = in.readInt();
                    Map<Integer, Integer> counts = new LinkedHashMap<>();
                    for (int i = 0; i < countN; i++) counts.put(in.readInt(), in.readInt());
                    int tracedN = in.readInt();
                    List<String> traced = new ArrayList<>(tracedN);
                    for (int i = 0; i < tracedN; i++) traced.add(readString(in));
                    int decN = in.readInt();
                    List<TallyResult.DecryptionRecord> decs = new ArrayList<>(decN);
                    for (int i = 0; i < decN; i++) {
                        decs.add(new TallyResult.DecryptionRecord(
                                readPoint(in), readPoint(in), readPoint(in)));
                    }
                    boolean hasProof = in.readBoolean();
                    mmu.fyp.evoting.crypto.sigma.SigmaDLEq.Transcript proof = null;
                    if (hasProof) {
                        int aN = in.readInt();
                        List<ECPoint> a = new ArrayList<>(aN);
                        for (int i = 0; i < aN; i++) a.add(readPoint(in));
                        BigInteger chal = readScalar(in);
                        BigInteger resp = readScalar(in);
                        proof = new mmu.fyp.evoting.crypto.sigma.SigmaDLEq.Transcript(
                                new mmu.fyp.evoting.crypto.sigma.SigmaDLEq.FirstMessage(a),
                                chal, resp);
                    }
                    yield new TallyResult(counts, traced, decs, proof);
                }
                default -> throw new IOException("unknown BBEntry tag: " + tag);
            };
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Discriminator for the BBEntry type stored in DB rows (for human-readable filtering). */
    public static String bbEntryTypeLabel(BBEntry e) {
        return switch (e) {
            case ParamNotice p -> "ParamNotice";
            case VidNotice v -> "VidNotice";
            case Ballot b -> "Ballot";
            case TallyResult r -> "TallyResult";
        };
    }
}
