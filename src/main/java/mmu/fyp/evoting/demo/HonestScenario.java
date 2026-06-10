package mmu.fyp.evoting.demo;

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

import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Narrated honest-path demo: 3 candidates, 3 voters, no coercion, no double-voting. */
public final class HonestScenario {

    private HonestScenario() {}

    public static void run() {
        System.out.println("=== Honest voting scenario ===");
        System.out.println("3 candidates (1=Alice, 2=Bob, 3=Carol); 3 voters; no coercion.");
        System.out.println();

        System.out.println("[setup] creating Certificate Authority and Election Committee");
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));
        System.out.println("[setup] CA: EOLTAA master keypair (MPK, MSK) | EC keys: EOLTAA user keypair + cert (vid), MuSig2 n=3 (per-Ci σ), Cramer-Shoup PKE");
        System.out.println();

        System.out.println("[register] generating voter keypairs and enrolling with CA");
        String[] identities = {"voter-Alice", "voter-Bob", "voter-Carol"};
        int[] preferences = {1, 2, 1};   // Alice→1, Bob→2, Carol→1
        Voter[] voters = new Voter[identities.length];
        for (int i = 0; i < identities.length; i++) {
            EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
            voters[i] = Voter.register(ca, identities[i], kp);
            System.out.printf("  - %s: position=%d, upk=%s...%n",
                    identities[i], i, prefix(kp.upk().Y()));
        }
        ec.setDirectory(ca.directory());
        System.out.println();

        System.out.println("[vid] EC publishes vid notice to bulletin board");
        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice vidNotice = ec.publishVid(bb, ca.masterPublicKey());
        System.out.printf("  vid = %s%n", HexFormat.of().formatHex(vidNotice.vid()));
        System.out.println();

        VotingContext ctx = new VotingContext(
                vidNotice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        System.out.println("[vote] each voter runs the 4-round protocol with the EC");
        for (int i = 0; i < voters.length; i++) {
            System.out.printf("  %s casts vote for candidate %d%n", identities[i], preferences[i]);
            Ballot ballot = VoteProtocol.run(voters[i], ctx, ec, bb, preferences[i]);
            System.out.printf("    [ok] sigma-proof verified, ballot posted, linking tag = %s%n",
                    prefix(ballot.voterAuth().linkingTag()));
        }
        System.out.println();

        System.out.println("[tally] EC verifies signatures, checks for double-votes, decrypts");
        TallyResult result = ec.runTally(ca, bb);
        System.out.println();

        System.out.println("=== Result ===");
        for (Map.Entry<Integer, Integer> e : result.counts().entrySet()) {
            System.out.printf("  candidate %d: %d vote(s)%n", e.getKey(), e.getValue());
        }
        for (int v = 1; v <= ec.candidateCount(); v++) {
            if (!result.counts().containsKey(v)) {
                System.out.printf("  candidate %d: 0 vote(s)%n", v);
            }
        }
        if (result.tracedDoubleVoters().isEmpty()) {
            System.out.println("  no double-voting detected");
        } else {
            System.out.println("  traced double voters: " + result.tracedDoubleVoters());
        }
        System.out.println();
        System.out.println("[bb] bulletin board hash chain verifies: " + bb.verifyChain());
        System.out.println("[bb] " + bb.entries().size() + " entries total");
        System.out.println("[bb] D2 ballots posted: " + bb.ballots().size()
                + ", D3 result published: " + bb.result().isPresent());
        System.out.println();
        System.out.println("[check-result] each voter queries the bulletin board for the published tally:");
        for (Voter voter : voters) {
            voter.checkResult(bb).ifPresent(r -> System.out.printf(
                    "  %s reads result: counts=%s%n", voter.identity(), r.counts()));
        }
    }

    private static String prefix(org.bouncycastle.math.ec.ECPoint p) {
        byte[] enc = mmu.fyp.evoting.crypto.group.Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(6, enc.length); i++) {
            sb.append(String.format("%02x", enc[i] & 0xff));
        }
        return sb.toString();
    }
}
