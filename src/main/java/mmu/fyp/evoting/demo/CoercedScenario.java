package mmu.fyp.evoting.demo;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.CoercionFake;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VoterSession;
import mmu.fyp.evoting.entities.voter.VotingContext;
import mmu.fyp.evoting.protocol.Messages;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/** Coerced-voter narrated demo. Shows real and fake transcripts side-by-side and confirms both verify. */
public final class CoercedScenario {

    private static final int REAL_VOTE = 1;
    private static final int TARGET_VOTE = 2;

    private CoercedScenario() {}

    public static void run() {
        System.out.println("=== Coerced voter scenario ===");
        System.out.println("Alice votes for candidate " + REAL_VOTE + " (her real choice).");
        System.out.println("After voting, a coercer demands Alice prove she voted for candidate " + TARGET_VOTE + ".");
        System.out.println("Alice produces a fake transcript that the coercer cannot tell apart from a genuine run for v*=" + TARGET_VOTE + ".");
        System.out.println();

        // Setup
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

        // Cast a real vote — drive the rounds manually so we keep a handle on the session.
        System.out.println("[vote] Alice runs the 4-round Vote protocol for v=" + REAL_VOTE);
        VoterSession session = alice.beginVote(ctx, REAL_VOTE);
        ECVoteSession ecs = ec.beginVoteSession();
        Messages.Round2 r2 = session.step2();
        Messages.Round3 r3 = ecs.processStep2(r2);
        Messages.Round4 r4 = session.processStep3(r3);
        Messages.Round5 r5 = ecs.processStep4(r4);
        Ballot ballot = session.finalize(r5, bb);
        System.out.println("[vote] ballot posted; ciphertext on BB encrypts v=" + REAL_VOTE + " (hidden under CCA2)");
        System.out.println();

        // Coercion: generate real and fake transcripts.
        System.out.println("[coerce] coercer demands proof Alice voted v*=" + TARGET_VOTE);
        CoercionFake.Transcript real = CoercionFake.real(session);
        CoercionFake.Transcript fake = CoercionFake.fake(session, TARGET_VOTE);
        System.out.println();

        printSideBySide(real, fake);

        System.out.println();
        System.out.println("[verify] both transcripts subjected to the same sigma-proof and Pedersen-opening checks:");
        boolean realOk = CoercionFake.verify(real, ctx.ecEncryptionPk());
        boolean fakeOk = CoercionFake.verify(fake, ctx.ecEncryptionPk());
        System.out.printf("  real (claims v=%d): verifies = %s%n", real.candidate(), realOk);
        System.out.printf("  fake (claims v=%d): verifies = %s%n", fake.candidate(), fakeOk);

        System.out.println();
        System.out.println("[conclusion]");
        System.out.println("  Both transcripts pass every check the coercer can apply on the public channel.");
        System.out.println("  The ciphertext on the BB is CCA2-secure: its actual plaintext is hidden.");
        System.out.println("  The voter therefore preserves their real choice while satisfying the coercer.");
    }

    private static void printSideBySide(CoercionFake.Transcript a, CoercionFake.Transcript b) {
        System.out.println("                                  REAL                                  FAKE");
        line("candidate v",            String.valueOf(a.candidate()),       String.valueOf(b.candidate()));
        line("ciphertext u1",          point(a.ct().u1()),                  point(b.ct().u1()));
        line("ciphertext e",           point(a.ct().e()),                   point(b.ct().e()));
        line("commitment cmt",         point(a.commitment()),               point(b.commitment()));
        line("Pedersen base h_v",      point(a.pedersenH()),                point(b.pedersenH()));
        line("sigma A[0]",             point(a.sigmaA().a().get(0)),        point(b.sigmaA().a().get(0)));
        line("sigma E (challenge)",    scalar(a.sigmaE()),                  scalar(b.sigmaE()));
        line("sigma Z (response)",     scalar(a.sigmaZ()),                  scalar(b.sigmaZ()));
        line("Pedersen r_hat",         scalar(a.pedersenR()),               scalar(b.pedersenR()));
    }

    private static void line(String label, String a, String b) {
        System.out.printf("  %-27s : %-37s %-37s%n", label, a, b);
    }

    private static String point(ECPoint p) {
        byte[] enc = Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(12, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private static String scalar(BigInteger s) {
        byte[] b = s.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(12, b.length); i++) sb.append(String.format("%02x", b[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }
}
