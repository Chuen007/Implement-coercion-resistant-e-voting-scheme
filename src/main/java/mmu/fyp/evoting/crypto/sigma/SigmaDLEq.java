package mmu.fyp.evoting.crypto.sigma;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** Schnorr Σ-protocol for DL-equality: prove ∃ r. ∀i. P_i = r·G_i. Challenge space Chl = [0, N). */
public final class SigmaDLEq {

    public record Statement(List<ECPoint> bases, List<ECPoint> points) {
        public Statement {
            if (bases == null || points == null) throw new IllegalArgumentException("null");
            if (bases.size() != points.size()) throw new IllegalArgumentException("size");
            if (bases.isEmpty()) throw new IllegalArgumentException("empty");
            bases = List.copyOf(bases);
            points = List.copyOf(points);
        }

        public int n() {
            return bases.size();
        }
    }

    public record FirstMessage(List<ECPoint> a) {
        public FirstMessage {
            a = List.copyOf(a);
        }
    }

    public record Transcript(FirstMessage first, BigInteger challenge, BigInteger response) {}

    public static final class Session {
        private final Statement stmt;
        private final BigInteger witness;
        private final BigInteger k;
        private final FirstMessage first;

        private Session(Statement stmt, BigInteger witness, BigInteger k, FirstMessage first) {
            this.stmt = stmt;
            this.witness = witness;
            this.k = k;
            this.first = first;
        }

        public FirstMessage firstMessage() {
            return first;
        }
    }

    private SigmaDLEq() {}

    /** Challenge space Chl = [0, N). Mcom = [0, N), so Chl ⊆ Mcom holds. */
    public static boolean isInChallengeSpace(BigInteger e) {
        return e != null && e.signum() >= 0 && e.compareTo(Group.N) < 0;
    }

    public static Session commit(Statement stmt, BigInteger witness) {
        BigInteger k = Group.randomScalar();
        List<ECPoint> a = new ArrayList<>(stmt.n());
        for (ECPoint g : stmt.bases()) {
            a.add(Group.mul(g, k));
        }
        return new Session(stmt, witness, k, new FirstMessage(a));
    }

    public static BigInteger respond(Session session, BigInteger challenge) {
        if (!isInChallengeSpace(challenge)) {
            throw new IllegalArgumentException("challenge outside Chl = [0, N)");
        }
        return session.k.add(challenge.multiply(session.witness)).mod(Group.N);
    }

    public static boolean verify(Statement stmt, FirstMessage first,
                                 BigInteger challenge, BigInteger response) {
        if (!isInChallengeSpace(challenge)) return false;
        if (response == null || response.signum() < 0 || response.compareTo(Group.N) >= 0) return false;
        if (first.a().size() != stmt.n()) return false;
        for (int i = 0; i < stmt.n(); i++) {
            ECPoint lhs = Group.mul(stmt.bases().get(i), response);
            ECPoint eP = Group.mul(stmt.points().get(i), challenge);
            ECPoint rhs = Group.add(first.a().get(i), eP);
            if (!lhs.equals(rhs)) return false;
        }
        return true;
    }

    /** HVZK simulator: produces a verifying transcript for any challenge without the witness. */
    public static Transcript simulate(Statement stmt, BigInteger challenge) {
        if (!isInChallengeSpace(challenge)) {
            throw new IllegalArgumentException("challenge outside Chl = [0, N)");
        }
        BigInteger z = Group.randomScalar();
        BigInteger negE = challenge.negate().mod(Group.N);
        List<ECPoint> a = new ArrayList<>(stmt.n());
        for (int i = 0; i < stmt.n(); i++) {
            ECPoint zG = Group.mul(stmt.bases().get(i), z);
            ECPoint negEP = Group.mul(stmt.points().get(i), negE);
            a.add(Group.add(zG, negEP));
        }
        return new Transcript(new FirstMessage(a), challenge, z);
    }

    /** Uniform challenge in Chl. */
    public static BigInteger randomChallenge() {
        return Group.randomScalar();
    }
}
