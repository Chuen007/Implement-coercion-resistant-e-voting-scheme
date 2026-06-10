package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.crypto.pedersen.Pedersen;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.protocol.EncryptionRelation;
import mmu.fyp.evoting.protocol.MessageEncoding;
import mmu.fyp.evoting.protocol.Messages;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

/** Per-vote voter-side state machine. Runs steps 2, 4, and 6 of the Vote protocol. */
public final class VoterSession {

    private final Voter voter;
    private final VotingContext ctx;
    private final int candidate;
    private final Pedersen.CommitterParams pedersen;
    private final BigInteger e;
    private final BigInteger rHat;
    private final ECPoint commitment;
    private Messages.Round3 round3;
    private Messages.Round5 round5;

    VoterSession(Voter voter, VotingContext ctx, int candidate) {
        // Verify the EC's EOLTAA authentication on the vid before participating
        // (Kho et al. 2025 §6.1 Vote step 1 — voter checks Φ.Verify on the
        // vid notice, treating the EC as the sole signer in a singleton directory).
        byte[] vidMsg = MessageEncoding.vidMessage(ctx.vidNotice().vid(), ctx.ecUpk());
        if (!EOLTAA.verify(vidMsg, ctx.vidNotice().ecAuth(),
                List.of(ctx.ecUpk()), ctx.caMasterPublicKey())) {
            throw new IllegalStateException("EC authentication on vid notice is invalid");
        }

        this.voter = voter;
        this.ctx = ctx;
        this.candidate = candidate;
        this.pedersen = Pedersen.setup();
        this.e = SigmaDLEq.randomChallenge();
        this.rHat = Group.randomScalar();
        this.commitment = Pedersen.commit(e, rHat, pedersen);
    }

    public Messages.Round2 step2() {
        return new Messages.Round2(candidate, commitment, pedersen.h());
    }

    public Messages.Round4 processStep3(Messages.Round3 r3) {
        byte[] ctBytes = MessageEncoding.serializeCiphertext(r3.ct());
        // Vote step 3 voter-side check: σ is a valid MuSig2 aggregate signature
        // by the EC committee under the aggregated public key X̃.
        if (!MuSig2.verify(r3.ecSig(), ctx.ecAggregateSigningPk(), ctBytes)) {
            throw new IllegalStateException("EC multi-signature on ciphertext is invalid");
        }
        this.round3 = r3;
        return new Messages.Round4(e, rHat);
    }

    public Ballot finalize(Messages.Round5 r5, BulletinBoard bb) {
        this.round5 = r5;
        ECPoint m = Group.mulG(BigInteger.valueOf(candidate));
        SigmaDLEq.Statement stmt = EncryptionRelation.build(m, round3.ct(), ctx.ecEncryptionPk());
        if (!SigmaDLEq.verify(stmt, round3.sigmaA(), e, r5.z())) {
            throw new IllegalStateException("Σ-protocol verification failed (EC may have encrypted the wrong candidate)");
        }
        byte[] msg = MessageEncoding.ballotMessage(ctx.vidNotice().vid(), round3.ct());
        // Kho et al. (2025) Vote step 6: π_i = Auth(vid ‖ Ci, upk_i, usk_i, Cert_i, MPK).
        EOLTAA.AuthToken token = EOLTAA.auth(
                msg, ctx.vidNotice().vid(),
                voter.upk(), voter.usk(), voter.certificate(),
                ctx.directory(), ctx.caMasterPublicKey());
        Ballot ballot = new Ballot(round3.ct(), token);
        bb.append(ballot);
        return ballot;
    }

    // Accessors used by M7 (coercion fakes).
    public Pedersen.CommitterParams pedersen() { return pedersen; }
    public BigInteger challenge() { return e; }
    public BigInteger randomness() { return rHat; }
    public ECPoint commitment() { return commitment; }
    public int candidate() { return candidate; }
    public Messages.Round3 round3() { return round3; }
    public BigInteger responseZ() { return round5.z(); }
    public VotingContext context() { return ctx; }
}
