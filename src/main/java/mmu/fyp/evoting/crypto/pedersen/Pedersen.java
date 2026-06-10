package mmu.fyp.evoting.crypto.pedersen;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/** Pedersen commitment: C = m·G + r·H where H = α·G. */
public final class Pedersen {

    /** Committer holds both H and the trapdoor α. Required to commit and to equivocate. */
    public record CommitterParams(ECPoint h, BigInteger trapdoor) {
        public CommitterParams {
            if (h == null) throw new IllegalArgumentException("h must be non-null");
            if (trapdoor == null) throw new IllegalArgumentException("trapdoor must be non-null");
        }

        public VerifierParams asVerifier() {
            return new VerifierParams(h);
        }
    }

    /** Verifier holds only H. Cannot equivocate. */
    public record VerifierParams(ECPoint h) {
        public VerifierParams {
            if (h == null) throw new IllegalArgumentException("h must be non-null");
        }
    }

    public record Opening(BigInteger m, BigInteger r) {}

    private Pedersen() {}

    public static CommitterParams setup() {
        BigInteger alpha = Group.randomScalar();
        return new CommitterParams(Group.mulG(alpha), alpha);
    }

    public static ECPoint commit(BigInteger m, BigInteger r, CommitterParams p) {
        return commitInternal(m, r, p.h());
    }

    public static boolean open(ECPoint cmt, BigInteger m, BigInteger r, VerifierParams p) {
        return commitInternal(m, r, p.h()).equals(cmt);
    }

    /** Given (m, r) and α, returns r* such that the same commitment opens to (targetM, r*). */
    public static Opening equivocate(BigInteger m, BigInteger r, BigInteger targetM, CommitterParams p) {
        BigInteger alphaInv = p.trapdoor().modInverse(Group.N);
        BigInteger delta = m.subtract(targetM).mod(Group.N);
        BigInteger targetR = r.add(alphaInv.multiply(delta)).mod(Group.N);
        return new Opening(targetM.mod(Group.N), targetR);
    }

    private static ECPoint commitInternal(BigInteger m, BigInteger r, ECPoint h) {
        return Group.add(Group.mulG(m.mod(Group.N)), Group.mul(h, r.mod(Group.N)));
    }
}
