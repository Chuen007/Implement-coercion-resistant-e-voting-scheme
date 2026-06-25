package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.protocol.Messages;
import mmu.fyp.evoting.protocol.Tally;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Coercion-resistance side-effect experiments requested in Dr Kho's review
 * (June 2026). Beyond "genuine verifies" and "simulated verifies" (covered in
 * {@link CoercionFakeTest}), the review asks for explicit evidence that:
 * <ul>
 *   <li>"Simulated transcripts do not affect the actual ballot stored on the
 *       bulletin board."</li>
 *   <li>"Simulated transcripts do not alter the final tally."</li>
 * </ul>
 *
 * <p>Together these show the fake-transcript mechanism is a pure voter-side
 * simulation: it convinces the coercer without touching any election state.
 */
class CoercionNoSideEffectTest {

    private record Setup(CertificateAuthority ca, ElectionCommittee ec, BulletinBoard bb,
                         VotingContext ctx, VoterSession session) {}

    /** Single-voter election; the voter casts their REAL vote and we keep the session. */
    private static Setup voteFor(int realCandidate) {
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));
        Voter alice = Voter.register(ca, "Alice", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(),
                ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        VoterSession session = alice.beginVote(ctx, realCandidate);
        ECVoteSession ecs = ec.beginVoteSession();
        Messages.Round2 r2 = session.step2();
        Messages.Round3 r3 = ecs.processStep2(r2);
        Messages.Round4 r4 = session.processStep3(r3);
        Messages.Round5 r5 = ecs.processStep4(r4);
        session.finalize(r5, bb);
        return new Setup(ca, ec, bb, ctx, session);
    }

    @Test
    void fakeGenerationDoesNotMutateBulletinBoard() {
        Setup s = voteFor(1);

        int entriesBefore = s.bb().entries().size();
        byte[] tipBefore = s.bb().tipHash();
        Ballot ballotBefore = s.bb().ballots().get(0);
        byte[] ballotBytesBefore = ballotBefore.encodeForHash();

        // Generate several fakes (and one genuine transcript for good measure).
        CoercionFake.real(s.session());
        for (int target = 1; target <= 3; target++) {
            CoercionFake.Transcript fake = CoercionFake.fake(s.session(), target);
            assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()));
        }

        // The bulletin board is bit-for-bit unchanged.
        assertEquals(entriesBefore, s.bb().entries().size(),
                "fake generation must not append anything to the BB");
        assertArrayEquals(tipBefore, s.bb().tipHash(),
                "BB hash-chain tip must be unchanged");
        assertArrayEquals(ballotBytesBefore, s.bb().ballots().get(0).encodeForHash(),
                "the stored ballot must be byte-identical");
        assertTrue(s.bb().verifyChain(), "hash chain must still verify end-to-end");
    }

    @Test
    void fakeGenerationDoesNotAlterTally() {
        Setup s = voteFor(1);   // real vote: candidate 1

        // The coercer demands proof of voting for candidate 2; the voter fakes it.
        CoercionFake.Transcript fake = CoercionFake.fake(s.session(), 2);
        assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()),
                "the coercer accepts the simulated transcript");

        // The tally still counts the REAL vote.
        TallyResult result = Tally.run(s.ec(), s.ca(), s.bb());
        assertEquals(Integer.valueOf(1), result.counts().get(1),
                "the real vote (candidate 1) is counted");
        assertNull(result.counts().get(2),
                "the faked candidate (2) receives no vote");
        assertTrue(result.tracedDoubleVoters().isEmpty(),
                "fake generation must not look like a double vote");
    }

    @Test
    void manyFakesAcrossAllCandidatesStillTallyOriginalVote() {
        Setup s = voteFor(3);   // real vote: candidate 3

        // Coercer pressure for every possible candidate, several times each.
        for (int round = 0; round < 3; round++) {
            for (int target = 1; target <= 3; target++) {
                CoercionFake.Transcript fake = CoercionFake.fake(s.session(), target);
                assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()));
            }
        }

        TallyResult result = Tally.run(s.ec(), s.ca(), s.bb());
        assertEquals(Integer.valueOf(1), result.counts().get(3),
                "only the real vote is in the tally");
        assertNull(result.counts().get(1));
        assertNull(result.counts().get(2));
        assertTrue(Tally.verifyTallyProof(result, s.ec().encryptionPk()),
                "π_result still verifies — fakes left no trace in the tally pipeline");
    }
}
