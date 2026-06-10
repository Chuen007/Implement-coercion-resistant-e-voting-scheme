package mmu.fyp.evoting.demo;

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
import mmu.fyp.evoting.protocol.VoteProtocol;

import java.util.Map;

/** Narrated demo of double-vote detection + CA-assisted tracing. */
public final class DoubleVoteScenario {

    private DoubleVoteScenario() {}

    public static void run() {
        System.out.println("=== Double-vote detection scenario ===");
        System.out.println("Alice tries to vote twice (once for v=1, once for v=2). Bob votes once for v=2.");
        System.out.println("Expected: Alice's BOTH ballots discarded, her identity traced, only Bob's vote counts.");
        System.out.println();

        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));

        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        Voter bob = Voter.register(ca, "voter-Bob", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        System.out.println("[vote] Alice casts vote #1 for candidate 1");
        Ballot a1 = VoteProtocol.run(alice, ctx, ec, bb, 1);
        System.out.println("        linking tag = " + linkingTagHex(a1));

        System.out.println("[vote] Alice casts vote #2 for candidate 2 (double vote!)");
        Ballot a2 = VoteProtocol.run(alice, ctx, ec, bb, 2);
        System.out.println("        linking tag = " + linkingTagHex(a2));
        System.out.println("        ^ identical to vote #1 because the EOLTAA tag depends on (voter.usk, event vid)");

        System.out.println("[vote] Bob casts vote for candidate 2");
        Ballot b1 = VoteProtocol.run(bob, ctx, ec, bb, 2);
        System.out.println("        linking tag = " + linkingTagHex(b1));
        System.out.println("        ^ different from Alice's tags");
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
        System.out.println("  Alice's two ballots were detected via matching linking tags and BOTH discarded.");
        System.out.println("  CA scanned its registry, recomputing the EOLTAA tag usk_i · H_eid(vid) for each voter,");
        System.out.println("  and identified the offender: " + result.tracedDoubleVoters());
        System.out.println("  Only Bob's vote counted: candidate 2.");
        System.out.println("[bb] hash chain verifies: " + bb.verifyChain());
    }

    private static String linkingTagHex(Ballot b) {
        byte[] enc = Group.encode(b.voterAuth().linkingTag());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(12, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }
}
