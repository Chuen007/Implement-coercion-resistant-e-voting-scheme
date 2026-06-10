package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.pedersen.Pedersen;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.protocol.EncryptionRelation;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Coercion-resistance feature. After voting, the voter can produce a fake transcript
 * claiming any candidate v*, indistinguishable from a real run for v* by anything the
 * coercer can verify on the public channel.
 *
 * <p>Mechanism: the Σ-protocol HVZK simulator yields a verifying (a*, e*, z*) for
 * the statement (v*, Ci) without the witness r. The Pedersen trapdoor lets the same
 * commitment open to (e*, r̂*) under the equivocation formula. The ciphertext on
 * the bulletin board is untouched and IND-CCA2 hides which v it actually encrypts.
 *
 * <p><b>Important: fake transcripts produced here NEVER touch the bulletin board.</b>
 * They live only between the voter and the coercer over a private channel. The
 * bulletin board records exactly one ballot per honest vote; the tally counts the
 * voter's real choice. The "fake" is just defensive evidence the voter shows a
 * coercer to satisfy a demand to "prove" they voted for v*.
 */
public final class CoercionFake {

    /** The data a voter would show a coercer to claim they voted for {@code candidate}. */
    public record Transcript(
            int candidate,
            CramerShoup.Ciphertext ct,
            ECPoint commitment,
            ECPoint pedersenH,
            SigmaDLEq.FirstMessage sigmaA,
            BigInteger sigmaE,
            BigInteger sigmaZ,
            BigInteger pedersenR
    ) {}

    private CoercionFake() {}

    /** Extract the genuine transcript from the voter's session after the vote has been cast. */
    public static Transcript real(VoterSession session) {
        return new Transcript(
                session.candidate(),
                session.round3().ct(),
                session.commitment(),
                session.pedersen().h(),
                session.round3().sigmaA(),
                session.challenge(),
                session.responseZ(),
                session.randomness()
        );
    }

    /** Produce a fake transcript claiming the voter voted for {@code targetCandidate}. */
    public static Transcript fake(VoterSession session, int targetCandidate) {
        ECPoint targetM = Group.mulG(BigInteger.valueOf(targetCandidate));
        SigmaDLEq.Statement fakeStmt = EncryptionRelation.build(
                targetM, session.round3().ct(), session.context().ecEncryptionPk());

        BigInteger fakeE = SigmaDLEq.randomChallenge();
        SigmaDLEq.Transcript fakeSigma = SigmaDLEq.simulate(fakeStmt, fakeE);

        Pedersen.Opening fakeOpening = Pedersen.equivocate(
                session.challenge(), session.randomness(), fakeE, session.pedersen());

        return new Transcript(
                targetCandidate,
                session.round3().ct(),
                session.commitment(),
                session.pedersen().h(),
                fakeSigma.first(),
                fakeE,
                fakeSigma.response(),
                fakeOpening.r()
        );
    }

    /** Coercer-side verification: commitment opens to (e, r̂) AND Σ-transcript verifies on (v, Ci). */
    public static boolean verify(Transcript t, CramerShoup.PublicKey ecEncryptionPk) {
        Pedersen.VerifierParams vp = new Pedersen.VerifierParams(t.pedersenH());
        if (!Pedersen.open(t.commitment(), t.sigmaE(), t.pedersenR(), vp)) return false;
        ECPoint m = Group.mulG(BigInteger.valueOf(t.candidate()));
        SigmaDLEq.Statement stmt = EncryptionRelation.build(m, t.ct(), ecEncryptionPk);
        return SigmaDLEq.verify(stmt, t.sigmaA(), t.sigmaE(), t.sigmaZ());
    }
}
