package mmu.fyp.evoting.crypto.group;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class GroupSmokeTest {

    @Test
    void generatorTimesOrderIsIdentity() {
        ECPoint inf = Group.G.multiply(Group.N).normalize();
        assertTrue(inf.isInfinity());
    }

    @Test
    void scalarAdditivityHolds() {
        BigInteger a = Group.randomScalar();
        BigInteger b = Group.randomScalar();
        ECPoint left = Group.mulG(a.add(b).mod(Group.N));
        ECPoint right = Group.add(Group.mulG(a), Group.mulG(b));
        assertEquals(left, right);
    }

    @Test
    void scalarMultiplicativityHolds() {
        BigInteger a = Group.randomScalar();
        BigInteger b = Group.randomScalar();
        ECPoint left = Group.mulG(a.multiply(b).mod(Group.N));
        ECPoint right = Group.mul(Group.mulG(a), b);
        assertEquals(left, right);
    }

    @Test
    void encodeDecodeRoundTrip() {
        for (int i = 0; i < 16; i++) {
            BigInteger s = Group.randomScalar();
            ECPoint p = Group.mulG(s);
            byte[] encoded = Group.encode(p);
            ECPoint decoded = Group.decode(encoded);
            assertEquals(p, decoded);
        }
    }

    @Test
    void orderIsPrime() {
        assertTrue(Group.N.isProbablePrime(64));
    }

    @Test
    void randomScalarsAreInRange() {
        for (int i = 0; i < 256; i++) {
            BigInteger s = Group.randomScalar();
            assertTrue(s.signum() > 0);
            assertTrue(s.compareTo(Group.N) < 0);
        }
    }
}
