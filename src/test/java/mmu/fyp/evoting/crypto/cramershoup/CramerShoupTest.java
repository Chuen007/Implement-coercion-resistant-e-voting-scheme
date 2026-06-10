package mmu.fyp.evoting.crypto.cramershoup;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CramerShoupTest {

    @Test
    void roundTripSimple() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(42));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
        Optional<ECPoint> decrypted = CramerShoup.decrypt(ct, kp.sk());
        assertTrue(decrypted.isPresent());
        assertEquals(m, decrypted.get());
    }

    @Test
    void roundTripVariousMessages() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        for (int v = 1; v <= 20; v++) {
            ECPoint m = Group.mulG(BigInteger.valueOf(v));
            CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
            Optional<ECPoint> got = CramerShoup.decrypt(ct, kp.sk());
            assertTrue(got.isPresent());
            assertEquals(m, got.get(), "round-trip failed for v=" + v);
        }
    }

    @Test
    void roundTripWithExplicitRandomness() {
        // Deterministic mode: same (message, r, pk) → same ciphertext.
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(99));
        BigInteger r = Group.randomScalar();
        CramerShoup.Ciphertext ct1 = CramerShoup.encrypt(m, r, kp.pk());
        CramerShoup.Ciphertext ct2 = CramerShoup.encrypt(m, r, kp.pk());
        assertEquals(ct1, ct2);
        assertEquals(m, CramerShoup.decrypt(ct1, kp.sk()).orElseThrow());
    }

    @Test
    void encryptionIsProbabilistic() {
        // Different (internal) randomness → different ciphertext for same message.
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(7));
        CramerShoup.Ciphertext a = CramerShoup.encrypt(m, kp.pk());
        CramerShoup.Ciphertext b = CramerShoup.encrypt(m, kp.pk());
        assertNotEquals(a, b);
    }

    @Test
    void tamperedU1Rejected() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(3));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
        CramerShoup.Ciphertext bad = new CramerShoup.Ciphertext(
                Group.add(ct.u1(), Group.G), ct.u2(), ct.e(), ct.v());
        assertTrue(CramerShoup.decrypt(bad, kp.sk()).isEmpty());
    }

    @Test
    void tamperedU2Rejected() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(3));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
        CramerShoup.Ciphertext bad = new CramerShoup.Ciphertext(
                ct.u1(), Group.add(ct.u2(), Group.G), ct.e(), ct.v());
        assertTrue(CramerShoup.decrypt(bad, kp.sk()).isEmpty());
    }

    @Test
    void tamperedERejected() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(3));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
        CramerShoup.Ciphertext bad = new CramerShoup.Ciphertext(
                ct.u1(), ct.u2(), Group.add(ct.e(), Group.G), ct.v());
        assertTrue(CramerShoup.decrypt(bad, kp.sk()).isEmpty());
    }

    @Test
    void tamperedVRejected() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(3));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, kp.pk());
        CramerShoup.Ciphertext bad = new CramerShoup.Ciphertext(
                ct.u1(), ct.u2(), ct.e(), Group.add(ct.v(), Group.G));
        assertTrue(CramerShoup.decrypt(bad, kp.sk()).isEmpty());
    }

    @Test
    void completelyRandomCiphertextRejected() {
        // A random 4-tuple of group elements has negligible probability of satisfying the
        // CCA2 validity check.
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        for (int i = 0; i < 50; i++) {
            CramerShoup.Ciphertext garbage = new CramerShoup.Ciphertext(
                    Group.mulG(Group.randomScalar()),
                    Group.mulG(Group.randomScalar()),
                    Group.mulG(Group.randomScalar()),
                    Group.mulG(Group.randomScalar()));
            assertTrue(CramerShoup.decrypt(garbage, kp.sk()).isEmpty(),
                    "random ciphertext was unexpectedly accepted");
        }
    }

    @Test
    void identityMessageRoundtrips() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        ECPoint identity = Group.G.multiply(BigInteger.ZERO);  // point at infinity
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(identity, kp.pk());
        Optional<ECPoint> got = CramerShoup.decrypt(ct, kp.sk());
        assertTrue(got.isPresent());
        assertEquals(identity, got.get());
    }

    @Test
    void decryptWithWrongKeyRejects() {
        CramerShoup.KeyPair a = CramerShoup.keyGen();
        CramerShoup.KeyPair b = CramerShoup.keyGen();
        ECPoint m = Group.mulG(BigInteger.valueOf(5));
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, a.pk());
        // The validity check uses b's (x1, x2, y1, y2). Almost surely fails.
        assertTrue(CramerShoup.decrypt(ct, b.sk()).isEmpty());
    }

    @Test
    void hashToScalarIsDeterministic() {
        ECPoint p1 = Group.mulG(BigInteger.valueOf(11));
        ECPoint p2 = Group.mulG(BigInteger.valueOf(22));
        BigInteger h1 = CramerShoup.hashToScalar(p1, p2);
        BigInteger h2 = CramerShoup.hashToScalar(p1, p2);
        assertEquals(h1, h2);
    }

    @Test
    void hashToScalarDependsOnInputOrder() {
        ECPoint p1 = Group.mulG(BigInteger.valueOf(11));
        ECPoint p2 = Group.mulG(BigInteger.valueOf(22));
        assertNotEquals(CramerShoup.hashToScalar(p1, p2), CramerShoup.hashToScalar(p2, p1));
    }

    @Test
    void keyGenProducesDistinctKeys() {
        CramerShoup.KeyPair a = CramerShoup.keyGen();
        CramerShoup.KeyPair b = CramerShoup.keyGen();
        assertNotEquals(a.pk(), b.pk());
        assertNotEquals(a.sk(), b.sk());
    }

    @Test
    void publicKeyPiecesAreConsistentWithSecretKey() {
        CramerShoup.KeyPair kp = CramerShoup.keyGen();
        CramerShoup.PublicKey pk = kp.pk();
        CramerShoup.SecretKey sk = kp.sk();
        // c = G^x1 · g2^x2
        ECPoint expectedC = Group.add(Group.mulG(sk.x1()), Group.mul(pk.g2(), sk.x2()));
        assertEquals(expectedC, pk.c());
        // d = G^y1 · g2^y2
        ECPoint expectedD = Group.add(Group.mulG(sk.y1()), Group.mul(pk.g2(), sk.y2()));
        assertEquals(expectedD, pk.d());
        // h = G^z
        assertEquals(Group.mulG(sk.z()), pk.h());
    }
}
