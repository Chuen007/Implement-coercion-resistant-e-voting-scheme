package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Tally-phase NIZK π_result (Kho et al. 2025 §6.1 Tally step 6):
 * the EC publishes a zero-knowledge proof that its decryption was performed
 * with the same secret z that defines the public key h = z·G.
 */
class TallyProofTest {

    private record Election(CertificateAuthority ca, ElectionCommittee ec,
                            BulletinBoard bb, VotingContext ctx, List<Voter> voters) {}

    private static Election setUp(int voterCount, int candidates) {
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(candidates);
        ec.setCertificate(ca.registerEc(ec.upk()));

        List<Voter> voters = new ArrayList<>();
        for (int i = 0; i < voterCount; i++) {
            voters.add(Voter.register(ca, "voter-" + i, EOLTAA.uKeyGen()));
        }
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(),
                ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());
        return new Election(ca, ec, bb, ctx, voters);
    }

    @Test
    void honestTallyProducesVerifiableProof() {
        Election e = setUp(3, 3);
        VoteProtocol.run(e.voters().get(0), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.voters().get(1), e.ctx(), e.ec(), e.bb(), 2);
        VoteProtocol.run(e.voters().get(2), e.ctx(), e.ec(), e.bb(), 1);

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        assertNotNull(result.decryptionProof(), "tally must produce a π_result");
        assertEquals(3, result.decryptions().size(),
                "all three honest ballots are recorded in the decryption list");
        assertTrue(Tally.verifyTallyProof(result, e.ec().encryptionPk()),
                "any party holding the EC encryption pk can verify π_result");
    }

    @Test
    void proofRejectsTamperedCounts() {
        Election e = setUp(2, 3);
        VoteProtocol.run(e.voters().get(0), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.voters().get(1), e.ctx(), e.ec(), e.bb(), 1);

        TallyResult honest = Tally.run(e.ec(), e.ca(), e.bb());
        // Counts say (1->2) but if we forge counts (1->1, 2->1) without changing
        // the decryption list, the recount check inside verifyTallyProof rejects it.
        TallyResult tampered = new TallyResult(
                java.util.Map.of(1, 1, 2, 1),
                honest.tracedDoubleVoters(),
                honest.decryptions(),
                honest.decryptionProof());
        assertFalse(Tally.verifyTallyProof(tampered, e.ec().encryptionPk()),
                "verifier must reject counts that contradict the per-ballot decryption list");
    }

    @Test
    void proofRejectsTamperedDecryption() {
        Election e = setUp(2, 3);
        VoteProtocol.run(e.voters().get(0), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.voters().get(1), e.ctx(), e.ec(), e.bb(), 2);

        TallyResult honest = Tally.run(e.ec(), e.ca(), e.bb());

        // Swap one (u1, e, m) triple's plaintext for a different candidate point.
        List<TallyResult.DecryptionRecord> bad = new ArrayList<>(honest.decryptions());
        var first = bad.get(0);
        bad.set(0, new TallyResult.DecryptionRecord(
                first.u1(), first.e(),
                Group.mulG(BigInteger.valueOf(3))));   // claim it decrypts to candidate 3
        TallyResult tampered = new TallyResult(
                java.util.Map.of(3, 1, 2, 1),    // tampered counts to match
                honest.tracedDoubleVoters(),
                bad,
                honest.decryptionProof());
        assertFalse(Tally.verifyTallyProof(tampered, e.ec().encryptionPk()),
                "the σ-DLEq check fails because (e_i - m'_i) is no longer z·u1_i");
    }

    @Test
    void proofRejectsForgedTranscript() {
        Election e = setUp(2, 3);
        VoteProtocol.run(e.voters().get(0), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.voters().get(1), e.ctx(), e.ec(), e.bb(), 2);

        TallyResult honest = Tally.run(e.ec(), e.ca(), e.bb());

        // Replace the proof's response with a random scalar.
        SigmaDLEq.Transcript original = honest.decryptionProof();
        SigmaDLEq.Transcript forged = new SigmaDLEq.Transcript(
                original.first(),
                original.challenge(),
                Group.randomScalar());   // wrong response
        TallyResult tampered = new TallyResult(
                honest.counts(), honest.tracedDoubleVoters(),
                honest.decryptions(), forged);
        assertFalse(Tally.verifyTallyProof(tampered, e.ec().encryptionPk()),
                "Σ-DLEq verify must reject a forged response");
    }

    @Test
    void proofWorksForLargerElectorate() {
        Election e = setUp(10, 3);
        for (int i = 0; i < 10; i++) {
            VoteProtocol.run(e.voters().get(i), e.ctx(), e.ec(), e.bb(), 1 + (i % 3));
        }
        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());
        assertEquals(10, result.decryptions().size());
        assertTrue(Tally.verifyTallyProof(result, e.ec().encryptionPk()),
                "NIZK scales to n=10 ballots");
    }

    @Test
    void proofVerifiesAfterPersistenceRoundtrip() {
        // The proof is bundled into the TallyResult BB entry; serialise + decode
        // and verify the proof survives the round-trip.
        Election e = setUp(3, 3);
        VoteProtocol.run(e.voters().get(0), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.voters().get(1), e.ctx(), e.ec(), e.bb(), 2);
        VoteProtocol.run(e.voters().get(2), e.ctx(), e.ec(), e.bb(), 3);

        TallyResult original = Tally.run(e.ec(), e.ca(), e.bb());
        byte[] encoded = mmu.fyp.evoting.persistence.Serialization.encodeBBEntry(original);
        var decoded = (TallyResult) mmu.fyp.evoting.persistence.Serialization.decodeBBEntry(encoded);

        assertEquals(original.counts(), decoded.counts());
        assertEquals(original.decryptions().size(), decoded.decryptions().size());
        assertTrue(Tally.verifyTallyProof(decoded, e.ec().encryptionPk()),
                "proof must verify after going through the byte serialisation layer");
    }
}
