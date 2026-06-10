package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DoubleVoteTest {

    /** Build a 2-voter election. */
    private static Election twoVoterElection() {
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));
        Voter alice = Voter.register(ca, "Alice", EOLTAA.uKeyGen());
        Voter bob = Voter.register(ca, "Bob", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());
        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());
        return new Election(ca, ec, bb, ctx, alice, bob);
    }

    private record Election(CertificateAuthority ca, ElectionCommittee ec, BulletinBoard bb,
                            VotingContext ctx, Voter alice, Voter bob) {}

    @Test
    void sameVoterSameElectionProducesIdenticalLinkingTag() {
        Election e = twoVoterElection();
        Ballot a1 = VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        Ballot a2 = VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);
        assertEquals(a1.voterAuth().linkingTag(), a2.voterAuth().linkingTag(),
                "EOLTAA linking tag depends on (voter usk, event vid) — not on the candidate");
    }

    @Test
    void differentVotersHaveDifferentLinkingTags() {
        Election e = twoVoterElection();
        Ballot alice = VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        Ballot bob = VoteProtocol.run(e.bob(), e.ctx(), e.ec(), e.bb(), 2);
        assertNotEquals(alice.voterAuth().linkingTag(), bob.voterAuth().linkingTag());
    }

    @Test
    void doubleVoteIsDetected_BothBallotsDiscarded_VoterTraced() {
        Election e = twoVoterElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);
        VoteProtocol.run(e.bob(), e.ctx(), e.ec(), e.bb(), 2);

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // Alice's "vote" for candidate 1 should not be counted (discarded as duplicate)
        assertNull(result.counts().get(1));
        // Bob's vote for candidate 2 counts (it's not a duplicate); Alice's duplicate ballot for candidate 2 does not.
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        // Alice is traced as a double voter
        assertEquals(1, result.tracedDoubleVoters().size());
        assertEquals("Alice", result.tracedDoubleVoters().get(0));
    }

    @Test
    void tripleVoteByOneVoterStillTracesOnlyOnce() {
        Election e = twoVoterElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 3);

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // No votes count; Alice traced exactly once.
        assertTrue(result.counts().isEmpty() || result.counts().values().stream().mapToInt(Integer::intValue).sum() == 0);
        assertEquals(1, result.tracedDoubleVoters().size());
        assertEquals("Alice", result.tracedDoubleVoters().get(0));
    }

    @Test
    void twoVotersBothDoubleVote_BothTraced() {
        Election e = twoVoterElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);
        VoteProtocol.run(e.bob(), e.ctx(), e.ec(), e.bb(), 3);
        VoteProtocol.run(e.bob(), e.ctx(), e.ec(), e.bb(), 1);

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // No legitimate votes
        for (int v = 1; v <= 3; v++) {
            Integer c = result.counts().get(v);
            assertTrue(c == null || c == 0, "candidate " + v + " should have 0 valid votes");
        }
        // Both voters traced
        assertEquals(2, result.tracedDoubleVoters().size());
        assertTrue(result.tracedDoubleVoters().contains("Alice"));
        assertTrue(result.tracedDoubleVoters().contains("Bob"));
    }

    @Test
    void honestSingleVoteStillCountsWithoutTrace() {
        Election e = twoVoterElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);
        VoteProtocol.run(e.bob(), e.ctx(), e.ec(), e.bb(), 2);

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        assertEquals(Integer.valueOf(1), result.counts().get(1));
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertTrue(result.tracedDoubleVoters().isEmpty());
    }
}
