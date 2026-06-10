package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Tally phase: verify each ballot, detect double-votes, decrypt the rest, post
 * the result together with a NIZK that the decryption was performed correctly
 * under the published EC encryption key.
 *
 * <p>Architecturally, the tally is owned by the Election Committee — see
 * {@link mmu.fyp.evoting.entities.ec.ElectionCommittee#runTally}. This class is the
 * static helper that the EC's method delegates to; tests can call it directly with
 * an explicit {@code (ec, ca, bb)} triple when that is more convenient.
 */
public final class Tally {

    private Tally() {}

    public static TallyResult run(ElectionCommittee ec, CertificateAuthority ca, BulletinBoard bb) {
        VidNotice vidNotice = null;
        List<Ballot> ballots = new ArrayList<>();
        for (var entry : bb.entries()) {
            if (entry.content() instanceof VidNotice v) vidNotice = v;
            else if (entry.content() instanceof Ballot b) ballots.add(b);
        }
        if (vidNotice == null) throw new IllegalStateException("no vid notice on bulletin board");
        byte[] vid = vidNotice.vid();
        List<EOLTAA.UserPublicKey> directory = ca.directory();
        EOLTAA.MasterPublicKey mpk = ca.masterPublicKey();

        // Step 1. Verify each ballot's EOLTAA authentication token (Φ.Verify).
        List<Ballot> validBallots = new ArrayList<>();
        for (Ballot b : ballots) {
            byte[] msg = MessageEncoding.ballotMessage(vid, b.ct());
            if (EOLTAA.verify(msg, b.voterAuth(), directory, mpk)) {
                validBallots.add(b);
            }
        }

        // Step 2. Detect double-votes by grouping on linking tag (Φ.Link).
        Map<ECPoint, List<Ballot>> byTag = new LinkedHashMap<>();
        for (Ballot b : validBallots) {
            byTag.computeIfAbsent(b.voterAuth().linkingTag(), k -> new ArrayList<>()).add(b);
        }
        Set<Ballot> discarded = new HashSet<>();
        List<String> doubleVoters = new ArrayList<>();
        for (var entry : byTag.entrySet()) {
            if (entry.getValue().size() > 1) {
                discarded.addAll(entry.getValue());
                // Step 3. Φ.Trace — CA-assisted identification of the double-voter.
                ca.trace(entry.getKey(), vid).ifPresent(doubleVoters::add);
            }
        }

        // Step 4. Decrypt remaining ballots and record (u1, e, m) for the NIZK.
        Map<Integer, Integer> counts = new TreeMap<>();
        List<TallyResult.DecryptionRecord> decryptions = new ArrayList<>();
        for (Ballot b : validBallots) {
            if (discarded.contains(b)) continue;
            Optional<ECPoint> mOpt = CramerShoup.decrypt(b.ct(), ec.encryptionSk());
            if (mOpt.isEmpty()) continue;
            ECPoint m = mOpt.get();
            Optional<Integer> voteOpt = decodeVote(m, ec.candidateCount());
            if (voteOpt.isEmpty()) continue;
            // Step 5. Count.
            counts.merge(voteOpt.get(), 1, Integer::sum);
            decryptions.add(new TallyResult.DecryptionRecord(b.ct().u1(), b.ct().e(), m));
        }

        // Step 6. Generate NIZK π_result: prove EC used a single secret z such that
        // h = z·G AND for every counted ballot, e_i - m_i = z·u1_i. This is exactly
        // Σ-DLEq with bases [G, u1_1, ...] and points [h, e_1-m_1, ...].
        SigmaDLEq.Transcript proof = proveCorrectDecryption(
                ec.encryptionPk(), ec.encryptionSk().z(), decryptions);

        TallyResult result = new TallyResult(counts, doubleVoters, decryptions, proof);
        bb.append(result);
        return result;
    }

    /** Resolves m = G^v back to v ∈ {1..k} by exhaustive comparison. */
    public static Optional<Integer> decodeVote(ECPoint m, int maxCandidate) {
        for (int v = 1; v <= maxCandidate; v++) {
            if (Group.mulG(BigInteger.valueOf(v)).equals(m)) return Optional.of(v);
        }
        return Optional.empty();
    }

    // ====================================================================
    // NIZK π_result: prove correct Cramer-Shoup decryption (Tally step 6)
    // ====================================================================

    /** Build the DLEq statement: bases = [G, u1_1, ...], points = [h, e_1-m_1, ...]. */
    private static SigmaDLEq.Statement decryptionStatement(
            CramerShoup.PublicKey pk, List<TallyResult.DecryptionRecord> decryptions) {
        List<ECPoint> bases  = new ArrayList<>(decryptions.size() + 1);
        List<ECPoint> points = new ArrayList<>(decryptions.size() + 1);
        bases.add(Group.G);
        points.add(pk.h());
        for (TallyResult.DecryptionRecord d : decryptions) {
            bases.add(d.u1());
            // points: e_i + (-m_i) = e_i - m_i
            points.add(Group.add(d.e(), d.plaintext().negate()));
        }
        return new SigmaDLEq.Statement(bases, points);
    }

    /** Prover: Fiat-Shamir NIZK over Σ-DLEq with EC's encryption secret z as witness. */
    private static SigmaDLEq.Transcript proveCorrectDecryption(
            CramerShoup.PublicKey pk, BigInteger z,
            List<TallyResult.DecryptionRecord> decryptions) {
        SigmaDLEq.Statement stmt = decryptionStatement(pk, decryptions);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, z);
        BigInteger challenge = fiatShamirChallenge(stmt, session.firstMessage());
        BigInteger response = SigmaDLEq.respond(session, challenge);
        return new SigmaDLEq.Transcript(session.firstMessage(), challenge, response);
    }

    /**
     * Verifier: anyone holding the EC public key can call this to confirm the
     * EC tallied correctly. Recomputes the statement from the published
     * decryption records, recomputes the Fiat-Shamir challenge, and runs
     * Σ-DLEq verify.
     */
    public static boolean verifyTallyProof(TallyResult result, CramerShoup.PublicKey pk) {
        if (result.decryptionProof() == null) return false;
        // The proof is for the set of decryptions the EC committed to. If the
        // claimed counts do not match the decryptions list, that is independently
        // checkable (do the per-candidate totals add up?), so we check that too.
        Map<Integer, Integer> recount = new TreeMap<>();
        for (TallyResult.DecryptionRecord d : result.decryptions()) {
            for (int v = 1; ; v++) {
                if (Group.mulG(BigInteger.valueOf(v)).equals(d.plaintext())) {
                    recount.merge(v, 1, Integer::sum);
                    break;
                }
                if (v > 1024) return false;   // bounded sanity escape
            }
        }
        if (!recount.equals(new TreeMap<>(result.counts()))) return false;

        SigmaDLEq.Statement stmt = decryptionStatement(pk, result.decryptions());
        BigInteger expected = fiatShamirChallenge(stmt, result.decryptionProof().first());
        if (!expected.equals(result.decryptionProof().challenge())) return false;
        return SigmaDLEq.verify(stmt, result.decryptionProof().first(),
                result.decryptionProof().challenge(),
                result.decryptionProof().response());
    }

    /** H(domain ‖ bases ‖ points ‖ first-message) mod N — Fiat-Shamir collapse to a scalar. */
    private static BigInteger fiatShamirChallenge(SigmaDLEq.Statement stmt, SigmaDLEq.FirstMessage first) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("FYP2-tally-NIZK".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            for (ECPoint b : stmt.bases())  sha.update(Group.encode(b));
            for (ECPoint p : stmt.points()) sha.update(Group.encode(p));
            for (ECPoint a : first.a())     sha.update(Group.encode(a));
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
