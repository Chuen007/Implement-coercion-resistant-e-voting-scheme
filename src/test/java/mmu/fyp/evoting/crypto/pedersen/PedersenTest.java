package mmu.fyp.evoting.crypto.pedersen;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class PedersenTest {

    @Test
    void honestCommitAndOpenAccepts() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(42);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);
        assertTrue(Pedersen.open(cmt, m, r, p.asVerifier()));
    }

    @Test
    void openFailsForWrongMessage() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(42);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);
        assertFalse(Pedersen.open(cmt, m.add(BigInteger.ONE), r, p.asVerifier()));
    }

    @Test
    void openFailsForWrongRandomness() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(42);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);
        BigInteger rOther = r.add(BigInteger.ONE).mod(Group.N);
        assertFalse(Pedersen.open(cmt, m, rOther, p.asVerifier()));
    }

    @Test
    void distinctRandomnessGivesDistinctCommitments() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(7);
        ECPoint c1 = Pedersen.commit(m, Group.randomScalar(), p);
        ECPoint c2 = Pedersen.commit(m, Group.randomScalar(), p);
        assertNotEquals(c1, c2);
    }

    @Test
    void distinctMessagesUsuallyDistinctCommitments() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger r = Group.randomScalar();
        ECPoint c1 = Pedersen.commit(BigInteger.ONE, r, p);
        ECPoint c2 = Pedersen.commit(BigInteger.TWO, r, p);
        assertNotEquals(c1, c2);
    }

    @Test
    void trapdoorEquivocationProducesValidSecondOpening() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(100);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);

        BigInteger targetM = BigInteger.valueOf(999);
        Pedersen.Opening fake = Pedersen.equivocate(m, r, targetM, p);

        assertEquals(targetM.mod(Group.N), fake.m());
        assertTrue(Pedersen.open(cmt, fake.m(), fake.r(), p.asVerifier()));
    }

    @Test
    void equivocationToSameMessageReturnsSameRandomness() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(5);
        BigInteger r = Group.randomScalar();
        Pedersen.Opening sameOpen = Pedersen.equivocate(m, r, m, p);
        assertEquals(r.mod(Group.N), sameOpen.r());
    }

    @Test
    void committerParamsRejectsNullTrapdoor() {
        assertThrows(IllegalArgumentException.class,
                () -> new Pedersen.CommitterParams(Group.G, null));
    }

    @Test
    void verifierParamsRejectsNullH() {
        assertThrows(IllegalArgumentException.class,
                () -> new Pedersen.VerifierParams(null));
    }

    @Test
    void bindingHoldsWithoutTrapdoor() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(13);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);

        for (int i = 0; i < 1000; i++) {
            BigInteger mPrime = Group.randomScalar();
            BigInteger rPrime = Group.randomScalar();
            if (mPrime.equals(m.mod(Group.N))) continue;
            assertFalse(Pedersen.open(cmt, mPrime, rPrime, p.asVerifier()),
                    "found a random collision — binding violated");
        }
    }

    @Test
    void setupProducesDistinctParameters() {
        Pedersen.CommitterParams a = Pedersen.setup();
        Pedersen.CommitterParams b = Pedersen.setup();
        assertNotEquals(a.h(), b.h());
        assertNotEquals(a.trapdoor(), b.trapdoor());
    }

    @Test
    void hParameterMatchesTrapdoor() {
        Pedersen.CommitterParams p = Pedersen.setup();
        assertEquals(Group.mulG(p.trapdoor()), p.h());
    }

    @Test
    void zeroMessageAndZeroRandomnessGivesIdentity() {
        Pedersen.CommitterParams p = Pedersen.setup();
        ECPoint cmt = Pedersen.commit(BigInteger.ZERO, BigInteger.ZERO, p);
        assertTrue(cmt.isInfinity());
    }

    @Test
    void equivocationRoundTripsRepeatedly() {
        Pedersen.CommitterParams p = Pedersen.setup();
        BigInteger m = BigInteger.valueOf(17);
        BigInteger r = Group.randomScalar();
        ECPoint cmt = Pedersen.commit(m, r, p);

        BigInteger mStar = BigInteger.valueOf(91);
        Pedersen.Opening forward = Pedersen.equivocate(m, r, mStar, p);
        Pedersen.Opening backward = Pedersen.equivocate(forward.m(), forward.r(), m, p);

        assertEquals(r.mod(Group.N), backward.r());
        assertTrue(Pedersen.open(cmt, backward.m(), backward.r(), p.asVerifier()));
    }
}
