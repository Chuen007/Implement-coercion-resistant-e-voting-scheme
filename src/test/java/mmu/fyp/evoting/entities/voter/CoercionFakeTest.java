package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.protocol.Messages;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class CoercionFakeTest {

    private record Setup(VoterSession session, VotingContext ctx) {}

    /** Set up a single-voter election, run the vote protocol, return the session. */
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
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        VoterSession session = alice.beginVote(ctx, realCandidate);
        ECVoteSession ecs = ec.beginVoteSession();
        Messages.Round2 r2 = session.step2();
        Messages.Round3 r3 = ecs.processStep2(r2);
        Messages.Round4 r4 = session.processStep3(r3);
        Messages.Round5 r5 = ecs.processStep4(r4);
        session.finalize(r5, bb);
        return new Setup(session, ctx);
    }

    @Test
    void realTranscriptVerifies() {
        Setup s = voteFor(1);
        CoercionFake.Transcript real = CoercionFake.real(s.session());
        assertTrue(CoercionFake.verify(real, s.ctx().ecEncryptionPk()));
    }

    @Test
    void fakeTranscriptForDifferentCandidateVerifies() {
        Setup s = voteFor(1);
        CoercionFake.Transcript fake = CoercionFake.fake(s.session(), 2);
        assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()));
        assertEquals(2, fake.candidate());
    }

    @Test
    void realAndFakeShareCiphertextAndCommitment() {
        Setup s = voteFor(1);
        CoercionFake.Transcript real = CoercionFake.real(s.session());
        CoercionFake.Transcript fake = CoercionFake.fake(s.session(), 3);
        assertEquals(real.ct(), fake.ct(), "ciphertext is on the public BB and cannot change");
        assertEquals(real.commitment(), fake.commitment(), "commitment is fixed at protocol round 2");
        assertEquals(real.pedersenH(), fake.pedersenH(), "Pedersen base is shared between voter and EC");
    }

    @Test
    void realAndFakeDifferInSigmaPartsAndOpening() {
        Setup s = voteFor(1);
        CoercionFake.Transcript real = CoercionFake.real(s.session());
        CoercionFake.Transcript fake = CoercionFake.fake(s.session(), 2);
        assertNotEquals(real.candidate(), fake.candidate());
        assertNotEquals(real.sigmaE(), fake.sigmaE());
        assertNotEquals(real.sigmaZ(), fake.sigmaZ());
        assertNotEquals(real.pedersenR(), fake.pedersenR());
    }

    @Test
    void fakeForActualChoiceAlsoVerifies() {
        // A coercer may demand the actual choice; the voter can still produce a "fake" indistinguishable from any other.
        Setup s = voteFor(2);
        CoercionFake.Transcript fake = CoercionFake.fake(s.session(), 2);
        assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()));
    }

    @Test
    void anyTargetCandidateProducesValidFake() {
        Setup s = voteFor(1);
        for (int target = 1; target <= 3; target++) {
            CoercionFake.Transcript fake = CoercionFake.fake(s.session(), target);
            assertTrue(CoercionFake.verify(fake, s.ctx().ecEncryptionPk()),
                    "fake transcript for target=" + target + " failed to verify");
            assertEquals(target, fake.candidate());
        }
    }

    @Test
    void verifyRejectsTamperedTranscript() {
        Setup s = voteFor(1);
        CoercionFake.Transcript real = CoercionFake.real(s.session());
        CoercionFake.Transcript tampered = new CoercionFake.Transcript(
                real.candidate(), real.ct(), real.commitment(), real.pedersenH(),
                real.sigmaA(), real.sigmaE().add(BigInteger.ONE), real.sigmaZ(), real.pedersenR()
        );
        assertFalse(CoercionFake.verify(tampered, s.ctx().ecEncryptionPk()));
    }

    @Test
    void fakeSurvivesMultipleRegenerations() {
        // Producing fake twice for the same target should give two valid but different transcripts
        // (since the simulator picks fresh randomness).
        Setup s = voteFor(1);
        CoercionFake.Transcript fake1 = CoercionFake.fake(s.session(), 3);
        CoercionFake.Transcript fake2 = CoercionFake.fake(s.session(), 3);
        assertTrue(CoercionFake.verify(fake1, s.ctx().ecEncryptionPk()));
        assertTrue(CoercionFake.verify(fake2, s.ctx().ecEncryptionPk()));
        assertNotEquals(fake1.sigmaE(), fake2.sigmaE(), "two simulator runs should pick different challenges");
    }
}
