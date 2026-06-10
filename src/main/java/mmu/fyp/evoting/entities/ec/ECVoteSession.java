package mmu.fyp.evoting.entities.ec;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.crypto.pedersen.Pedersen;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.protocol.EncryptionRelation;
import mmu.fyp.evoting.protocol.MessageEncoding;
import mmu.fyp.evoting.protocol.Messages;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Per-vote EC-side state machine. Runs steps 3 and 5 of the Vote protocol.
 *
 * <p>The per-ciphertext signature σ on Cᵢ is a {@link MuSig2.Signature}
 * produced by a fresh ceremony across the EC's {@code n}-party MuSig2
 * committee (Nick-Ruffing-Seurin 2021; BIP 327).
 */
public final class ECVoteSession {

    private final ElectionCommittee ec;
    private final byte[] vid;
    private Messages.Round2 round2;
    private CramerShoup.Ciphertext ciphertext;
    private SigmaDLEq.Session sigmaSession;

    ECVoteSession(ElectionCommittee ec, byte[] vid) {
        this.ec = ec;
        this.vid = vid;
    }

    public Messages.Round3 processStep2(Messages.Round2 r2) {
        if (r2.candidate() < 1 || r2.candidate() > ec.candidateCount()) {
            throw new IllegalArgumentException("invalid candidate: " + r2.candidate());
        }
        this.round2 = r2;

        ECPoint m = Group.mulG(BigInteger.valueOf(r2.candidate()));
        BigInteger r = Group.randomScalar();
        this.ciphertext = CramerShoup.encrypt(m, r, ec.encryptionPk());

        byte[] ctBytes = MessageEncoding.serializeCiphertext(ciphertext);
        // Kho et al. (2025) §6.1 Vote step 3: σ ← MS.Sign on Ci by the n-party EC.
        MuSig2.Signature sig = ec.sign(ctBytes);

        SigmaDLEq.Statement stmt = EncryptionRelation.build(m, ciphertext, ec.encryptionPk());
        this.sigmaSession = SigmaDLEq.commit(stmt, r);

        return new Messages.Round3(ciphertext, sig, sigmaSession.firstMessage());
    }

    public Messages.Round5 processStep4(Messages.Round4 r4) {
        if (!SigmaDLEq.isInChallengeSpace(r4.e())) {
            throw new IllegalArgumentException("challenge out of range");
        }
        Pedersen.VerifierParams params = new Pedersen.VerifierParams(round2.pedersenH());
        if (!Pedersen.open(round2.commitment(), r4.e(), r4.rHat(), params)) {
            throw new IllegalArgumentException("commitment does not open to the supplied (e, r̂)");
        }
        BigInteger z = SigmaDLEq.respond(sigmaSession, r4.e());
        return new Messages.Round5(z);
    }

    public CramerShoup.Ciphertext ciphertext() {
        return ciphertext;
    }

    public byte[] vid() {
        return vid;
    }
}
