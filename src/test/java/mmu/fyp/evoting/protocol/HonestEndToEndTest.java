package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.ParamNotice;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HonestEndToEndTest {

    /** Sets up CA + EC + n voters and returns the assembled VotingContext. */
    private static Setup setUpElection(int candidateCount, String... identities) {
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(candidateCount);
        ec.setCertificate(ca.registerEc(ec.upk()));

        List<Voter> voters = new ArrayList<>();
        for (String id : identities) {
            voters.add(Voter.register(ca, id, EOLTAA.uKeyGen()));
        }
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice vidNotice = ec.publishVid(bb, ca.masterPublicKey());

        VotingContext ctx = new VotingContext(
                vidNotice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        return new Setup(ca, ec, bb, voters, ctx);
    }

    private record Setup(CertificateAuthority ca, ElectionCommittee ec, BulletinBoard bb,
                         List<Voter> voters, VotingContext ctx) {}

    @Test
    void singleVoterHonestPath() {
        Setup s = setUpElection(3, "Alice");

        Ballot ballot = VoteProtocol.run(s.voters().get(0), s.ctx(), s.ec(), s.bb(), 2);
        assertNotNull(ballot);

        TallyResult result = Tally.run(s.ec(), s.ca(), s.bb());
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertNull(result.counts().get(1));
        assertNull(result.counts().get(3));
        assertTrue(result.tracedDoubleVoters().isEmpty());
    }

    @Test
    void threeVotersHonestPath() {
        Setup s = setUpElection(3, "Alice", "Bob", "Carol");

        VoteProtocol.run(s.voters().get(0), s.ctx(), s.ec(), s.bb(), 1);
        VoteProtocol.run(s.voters().get(1), s.ctx(), s.ec(), s.bb(), 2);
        VoteProtocol.run(s.voters().get(2), s.ctx(), s.ec(), s.bb(), 1);

        TallyResult result = Tally.run(s.ec(), s.ca(), s.bb());
        assertEquals(Integer.valueOf(2), result.counts().get(1));
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertNull(result.counts().get(3));
        assertTrue(result.tracedDoubleVoters().isEmpty());
    }

    @Test
    void bulletinBoardChainVerifies() {
        Setup s = setUpElection(3, "Alice", "Bob", "Carol");

        VoteProtocol.run(s.voters().get(0), s.ctx(), s.ec(), s.bb(), 1);
        VoteProtocol.run(s.voters().get(1), s.ctx(), s.ec(), s.bb(), 2);
        Tally.run(s.ec(), s.ca(), s.bb());

        assertTrue(s.bb().verifyChain(), "the hash chain of the bulletin board must verify end-to-end");
    }

    @Test
    void caIdentifiesVotersByPositionInRing() {
        Setup s = setUpElection(3, "Alice", "Bob", "Carol");
        assertEquals(0, s.ca().positionOf("Alice"));
        assertEquals(1, s.ca().positionOf("Bob"));
        assertEquals(2, s.ca().positionOf("Carol"));
        assertEquals(-1, s.ca().positionOf("Dan"));
    }

    @Test
    void allCandidatesCanWin() {
        Setup s = setUpElection(3, "Alice", "Bob", "Carol");
        VoteProtocol.run(s.voters().get(0), s.ctx(), s.ec(), s.bb(), 3);
        VoteProtocol.run(s.voters().get(1), s.ctx(), s.ec(), s.bb(), 3);
        VoteProtocol.run(s.voters().get(2), s.ctx(), s.ec(), s.bb(), 3);
        TallyResult result = Tally.run(s.ec(), s.ca(), s.bb());
        assertEquals(Integer.valueOf(3), result.counts().get(3));
    }

    @Test
    void bulletinBoardContainsParamThenVidThenBallotsThenResult() {
        Setup s = setUpElection(3, "Alice");
        VoteProtocol.run(s.voters().get(0), s.ctx(), s.ec(), s.bb(), 1);
        Tally.run(s.ec(), s.ca(), s.bb());

        var entries = s.bb().entries();
        assertEquals(4, entries.size());
        assertInstanceOf(ParamNotice.class, entries.get(0).content());
        assertInstanceOf(VidNotice.class,   entries.get(1).content());
        assertInstanceOf(Ballot.class,      entries.get(2).content());
        assertInstanceOf(TallyResult.class, entries.get(3).content());
    }
}
