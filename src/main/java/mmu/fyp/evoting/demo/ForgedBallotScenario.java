package mmu.fyp.evoting.demo;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import mmu.fyp.evoting.protocol.VoteProtocol;

import java.math.BigInteger;
import java.util.List;

/** Narrated demo of forged-ballot rejection via EOLTAA authentication verification. */
public final class ForgedBallotScenario {

    private ForgedBallotScenario() {}

    public static void run() {
        System.out.println("=== Forged ballot rejection scenario ===");
        System.out.println("Alice votes legitimately. An attacker injects two kinds of forgery:");
        System.out.println("  (a) a ballot with a random EOLTAA authentication token");
        System.out.println("  (b) a ballot that reuses Alice's token with a swapped ciphertext");
        System.out.println("Expected: both forgeries discarded, only Alice's real vote counts.");
        System.out.println();

        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));

        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        System.out.println("[vote] Alice casts legitimate vote for candidate 2");
        Ballot legitimate = VoteProtocol.run(alice, ctx, ec, bb, 2);
        System.out.println();

        System.out.println("[attack-a] Eve injects a ballot with a random EOLTAA authentication token");
        CramerShoup.Ciphertext eveCt = CramerShoup.encrypt(
                Group.mulG(BigInteger.valueOf(1)),
                Group.randomScalar(),
                ec.encryptionPk());
        // Random token: a random linking tag plus random challenge/response scalars of the
        // directory size. Will almost surely fail the Σ-OR-proof closure check at tally.
        int dirSize = ca.directory().size();
        java.util.ArrayList<BigInteger> randomChallenges = new java.util.ArrayList<>(dirSize);
        java.util.ArrayList<BigInteger> randomResponses = new java.util.ArrayList<>(dirSize);
        for (int i = 0; i < dirSize; i++) {
            randomChallenges.add(Group.randomScalar());
            randomResponses.add(Group.randomScalar());
        }
        EOLTAA.AuthToken randomToken = new EOLTAA.AuthToken(
                Group.mulG(Group.randomScalar()),
                randomChallenges, randomResponses, notice.vid());
        bb.append(new Ballot(eveCt, randomToken));
        System.out.println("        forged ballot appended to BB (no access control modelled -- this is what a network injection looks like)");
        System.out.println();

        System.out.println("[attack-b] Mallory takes Alice's posted ballot and swaps in a different ciphertext for v=3");
        CramerShoup.Ciphertext mallorysCt = CramerShoup.encrypt(
                Group.mulG(BigInteger.valueOf(3)),
                Group.randomScalar(),
                ec.encryptionPk());
        bb.append(new Ballot(mallorysCt, legitimate.voterAuth()));
        System.out.println("        signature-rebinding attempt appended to BB");
        System.out.println();

        System.out.println("[tally] running tally");
        TallyResult result = ec.runTally(ca, bb);
        System.out.println();

        System.out.println("=== Result ===");
        for (int v = 1; v <= ec.candidateCount(); v++) {
            int count = result.counts().getOrDefault(v, 0);
            System.out.println("  candidate " + v + ": " + count + " vote(s)");
        }
        System.out.println("  traced double voters: " + result.tracedDoubleVoters());
        System.out.println();
        System.out.println("[outcome]");
        System.out.println("  Forgery (a) failed because the EOLTAA Σ-OR-proof closure equation");
        System.out.println("    Σ c_i == H_chl(...) did not hold for the random challenge/response values.");
        System.out.println("  Forgery (b) failed because the EOLTAA token is computed over (vid || serialize(Ci)),");
        System.out.println("    so swapping Ci invalidates the verification hash.");
        System.out.println("  Only Alice's real vote (candidate 2) counted.");
        System.out.println("[bb] hash chain verifies: " + bb.verifyChain());
    }
}
