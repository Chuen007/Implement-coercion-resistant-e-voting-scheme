package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
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

class ForgedBallotTest {

    private static Election aliceOnlyElection() {
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
        return new Election(ca, ec, bb, ctx, alice);
    }

    private record Election(CertificateAuthority ca, ElectionCommittee ec, BulletinBoard bb,
                            VotingContext ctx, Voter alice) {}

    /** A random EOLTAA authentication token of the given directory size — almost surely invalid. */
    private static EOLTAA.AuthToken randomToken(int dirSize, byte[] event) {
        List<BigInteger> challenges = new ArrayList<>(dirSize);
        List<BigInteger> responses = new ArrayList<>(dirSize);
        for (int i = 0; i < dirSize; i++) {
            challenges.add(Group.randomScalar());
            responses.add(Group.randomScalar());
        }
        return new EOLTAA.AuthToken(Group.mulG(Group.randomScalar()), challenges, responses, event);
    }

    @Test
    void randomSignatureForgeryIsRejected() {
        Election e = aliceOnlyElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);

        CramerShoup.Ciphertext bogusCt = CramerShoup.encrypt(
                Group.mulG(BigInteger.valueOf(1)), Group.randomScalar(), e.ec().encryptionPk());
        e.bb().append(new Ballot(bogusCt,
                randomToken(e.ca().directory().size(), e.ctx().vidNotice().vid())));

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // Alice's legitimate vote for 2 counts; the forged "vote 1" is dropped.
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertNull(result.counts().get(1));
        assertTrue(result.tracedDoubleVoters().isEmpty());
    }

    @Test
    void signatureRebindingAttackIsRejected() {
        Election e = aliceOnlyElection();
        Ballot legitimate = VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 1);

        // Attacker reuses Alice's signature but with a different ciphertext.
        CramerShoup.Ciphertext mallorysCt = CramerShoup.encrypt(
                Group.mulG(BigInteger.valueOf(3)), Group.randomScalar(), e.ec().encryptionPk());
        e.bb().append(new Ballot(mallorysCt, legitimate.voterAuth()));

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // Alice's real vote (1) counts; the rebound "vote 3" is dropped because the EOLTAA
        // token was over (vid || serialize(Alice.ct)), not (vid || serialize(Mallory.ct)).
        assertEquals(Integer.valueOf(1), result.counts().get(1));
        assertNull(result.counts().get(3));
    }

    @Test
    void manyRandomForgeriesAllRejected() {
        Election e = aliceOnlyElection();
        VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);

        // Inject 20 random ballots.
        for (int i = 0; i < 20; i++) {
            CramerShoup.Ciphertext ct = CramerShoup.encrypt(
                    Group.mulG(BigInteger.valueOf(1 + (i % 3))),
                    Group.randomScalar(),
                    e.ec().encryptionPk());
            e.bb().append(new Ballot(ct,
                    randomToken(e.ca().directory().size(), e.ctx().vidNotice().vid())));
        }

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // Only Alice's legitimate vote counts.
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertNull(result.counts().get(1));
        assertNull(result.counts().get(3));
    }

    @Test
    void forgedBallotDoesNotTriggerFalseDoubleVoteDetection() {
        // A forged ballot is discarded BEFORE the linking-tag grouping step, so even if
        // by luck its linking tag matched Alice's, the legitimate vote would still count.
        Election e = aliceOnlyElection();
        Ballot legitimate = VoteProtocol.run(e.alice(), e.ctx(), e.ec(), e.bb(), 2);

        // Try to construct a forgery that uses Alice's real linking tag (no algebraic
        // attack — just bad luck simulation: same tag, random other components).
        int dirSize = e.ca().directory().size();
        List<BigInteger> randomChallenges = new ArrayList<>();
        List<BigInteger> randomResponses = new ArrayList<>();
        for (int i = 0; i < dirSize; i++) {
            randomChallenges.add(Group.randomScalar());
            randomResponses.add(Group.randomScalar());
        }
        EOLTAA.AuthToken collidingToken = new EOLTAA.AuthToken(
                legitimate.voterAuth().linkingTag(), randomChallenges, randomResponses,
                e.ctx().vidNotice().vid());

        CramerShoup.Ciphertext eveCt = CramerShoup.encrypt(
                Group.mulG(BigInteger.valueOf(1)), Group.randomScalar(), e.ec().encryptionPk());
        e.bb().append(new Ballot(eveCt, collidingToken));

        TallyResult result = Tally.run(e.ec(), e.ca(), e.bb());

        // Alice's vote still counts; she is NOT falsely traced as a double voter.
        assertEquals(Integer.valueOf(1), result.counts().get(2));
        assertTrue(result.tracedDoubleVoters().isEmpty(),
                "forged ballot with matching tag must not trigger a false double-vote trace");
    }
}
