package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VoterSession;
import mmu.fyp.evoting.entities.voter.VotingContext;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cast-as-Intended (CAI) tamper experiments requested in Dr Kho's review
 * (June 2026): "including additional experiments showing that the verification
 * process fails when ciphertexts, commitments, or proofs are deliberately
 * tampered with."
 *
 * <p>Each test drives the 4-round Vote protocol manually and corrupts exactly
 * one element, asserting the corresponding verifier rejects it:
 * <ul>
 *   <li>swapped candidate (malicious EC) → Σ-verify at finalize</li>
 *   <li>tampered ciphertext → MuSig2.verify at processStep3</li>
 *   <li>tampered multi-signature → MuSig2.verify at processStep3</li>
 *   <li>tampered Σ first message a → Σ-verify at finalize</li>
 *   <li>tampered Σ response z → Σ-verify at finalize</li>
 *   <li>wrong commitment opening → Pedersen.open at EC processStep4</li>
 * </ul>
 */
class CaiTamperTest {

    private record Election(CertificateAuthority ca, ElectionCommittee ec,
                            BulletinBoard bb, VotingContext ctx, Voter alice) {}

    private static Election setUp() {
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
        return new Election(ca, ec, bb, ctx, alice);
    }

    /**
     * THE core CAI experiment: the EC receives v=1 but encrypts v'=2, then
     * proves (honestly, with the real witness) that the ciphertext encrypts 2.
     * The voter verifies the transcript against the statement "Ci encrypts MY
     * candidate (1)" — so the otherwise-valid proof fails and the swap is caught.
     */
    @Test
    void maliciousEcEncryptingWrongCandidateIsCaught() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);   // voter chooses 1
        session.step2();

        // Malicious EC side: encrypt candidate 2 instead, with a fully valid
        // signature and a fully valid proof FOR CANDIDATE 2.
        ECPoint mWrong = Group.mulG(BigInteger.valueOf(2));
        BigInteger r = Group.randomScalar();
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(mWrong, r, e.ec().encryptionPk());
        MuSig2.Signature sig = e.ec().sign(MessageEncoding.serializeCiphertext(ct));
        SigmaDLEq.Statement stmtWrong = EncryptionRelation.build(mWrong, ct, e.ec().encryptionPk());
        SigmaDLEq.Session sigmaSession = SigmaDLEq.commit(stmtWrong, r);
        Messages.Round3 evil = new Messages.Round3(ct, sig, sigmaSession.firstMessage());

        // The multi-signature is genuine, so step 3 passes...
        Messages.Round4 r4 = session.processStep3(evil);
        BigInteger z = SigmaDLEq.respond(sigmaSession, r4.e());

        // ...but the voter verifies against THEIR candidate (1), so finalize rejects.
        assertThrows(IllegalStateException.class,
                () -> session.finalize(new Messages.Round5(z), e.bb()),
                "voter must detect that the EC encrypted a different candidate");
        assertEquals(0, e.bb().ballots().size(), "no ballot may reach the BB after a detected swap");
    }

    @Test
    void tamperedCiphertextRejectedByMusigCheck() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);
        ECVoteSession ecs = e.ec().beginVoteSession();
        Messages.Round3 honest = ecs.processStep2(session.step2());

        // Replace the ciphertext but keep the EC's original signature.
        CramerShoup.Ciphertext other = CramerShoup.encrypt(
                Group.mulG(BigInteger.ONE), e.ec().encryptionPk());
        Messages.Round3 tampered = new Messages.Round3(other, honest.ecSig(), honest.sigmaA());

        assertThrows(IllegalStateException.class, () -> session.processStep3(tampered),
                "σ was signed over the original Ci, so it must not verify over a swapped one");
    }

    @Test
    void tamperedMultiSignatureRejected() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);
        ECVoteSession ecs = e.ec().beginVoteSession();
        Messages.Round3 honest = ecs.processStep2(session.step2());

        MuSig2.Signature forged = new MuSig2.Signature(
                honest.ecSig().R(), honest.ecSig().s().add(BigInteger.ONE).mod(Group.N));
        Messages.Round3 tampered = new Messages.Round3(honest.ct(), forged, honest.sigmaA());

        assertThrows(IllegalStateException.class, () -> session.processStep3(tampered));
    }

    @Test
    void tamperedSigmaFirstMessageRejectedAtFinalize() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);
        ECVoteSession ecs = e.ec().beginVoteSession();
        Messages.Round3 honest = ecs.processStep2(session.step2());

        // Random points of the right arity: the MuSig2 check (over ct only)
        // still passes, but the Σ transcript can no longer verify.
        List<ECPoint> junk = List.of(
                Group.mulG(Group.randomScalar()), Group.mulG(Group.randomScalar()),
                Group.mulG(Group.randomScalar()), Group.mulG(Group.randomScalar()));
        Messages.Round3 tampered = new Messages.Round3(
                honest.ct(), honest.ecSig(), new SigmaDLEq.FirstMessage(junk));

        Messages.Round4 r4 = session.processStep3(tampered);
        Messages.Round5 r5 = ecs.processStep4(r4);
        assertThrows(IllegalStateException.class, () -> session.finalize(r5, e.bb()));
        assertEquals(0, e.bb().ballots().size());
    }

    @Test
    void tamperedSigmaResponseRejectedAtFinalize() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);
        ECVoteSession ecs = e.ec().beginVoteSession();
        Messages.Round4 r4 = session.processStep3(ecs.processStep2(session.step2()));
        Messages.Round5 honest = ecs.processStep4(r4);

        Messages.Round5 tampered = new Messages.Round5(
                honest.z().add(BigInteger.ONE).mod(Group.N));
        assertThrows(IllegalStateException.class, () -> session.finalize(tampered, e.bb()));
        assertEquals(0, e.bb().ballots().size());
    }

    @Test
    void wrongCommitmentOpeningRejectedByEc() {
        Election e = setUp();
        VoterSession session = e.alice().beginVote(e.ctx(), 1);
        ECVoteSession ecs = e.ec().beginVoteSession();
        Messages.Round4 r4 = session.processStep3(ecs.processStep2(session.step2()));

        // Open the commitment to a different challenge than the one committed.
        Messages.Round4 tampered = new Messages.Round4(
                r4.e().add(BigInteger.ONE).mod(Group.N), r4.rHat());
        assertThrows(IllegalArgumentException.class, () -> ecs.processStep4(tampered),
                "EC must reject an opening that does not match the round-2 commitment");
    }
}
