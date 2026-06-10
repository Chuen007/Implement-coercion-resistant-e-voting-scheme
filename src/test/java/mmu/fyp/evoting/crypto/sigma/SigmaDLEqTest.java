package mmu.fyp.evoting.crypto.sigma;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SigmaDLEqTest {

    private static SigmaDLEq.Statement randomStatement(BigInteger witness, int numBases) {
        List<ECPoint> bases = new ArrayList<>(numBases);
        List<ECPoint> points = new ArrayList<>(numBases);
        for (int i = 0; i < numBases; i++) {
            ECPoint g = Group.mulG(Group.randomScalar());
            bases.add(g);
            points.add(Group.mul(g, witness));
        }
        return new SigmaDLEq.Statement(bases, points);
    }

    @Test
    void honestRunVerifies_singleBase() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);
        assertTrue(SigmaDLEq.verify(stmt, session.firstMessage(), e, z));
    }

    @Test
    void honestRunVerifies_multiBase() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 4);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);
        assertTrue(SigmaDLEq.verify(stmt, session.firstMessage(), e, z));
    }

    @Test
    void tamperedResponseFails() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 2);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);
        BigInteger zTampered = z.add(BigInteger.ONE).mod(Group.N);
        assertFalse(SigmaDLEq.verify(stmt, session.firstMessage(), e, zTampered));
    }

    @Test
    void tamperedFirstMessageFails() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);

        List<ECPoint> tampered = new ArrayList<>(session.firstMessage().a());
        tampered.set(0, Group.add(tampered.get(0), Group.G));
        SigmaDLEq.FirstMessage badFirst = new SigmaDLEq.FirstMessage(tampered);

        assertFalse(SigmaDLEq.verify(stmt, badFirst, e, z));
    }

    @Test
    void tamperedChallengeFails() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);
        BigInteger eTampered = e.add(BigInteger.ONE).mod(Group.N);
        assertFalse(SigmaDLEq.verify(stmt, session.firstMessage(), eTampered, z));
    }

    @Test
    void wrongWitnessFails() {
        BigInteger r = Group.randomScalar();
        BigInteger wrong = r.add(BigInteger.ONE).mod(Group.N);
        SigmaDLEq.Statement stmt = randomStatement(r, 2);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, wrong);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);
        assertFalse(SigmaDLEq.verify(stmt, session.firstMessage(), e, z));
    }

    @Test
    void inconsistentWitnessAcrossBasesFails() {
        BigInteger r = Group.randomScalar();
        BigInteger rPrime;
        do {
            rPrime = Group.randomScalar();
        } while (rPrime.equals(r));

        ECPoint g1 = Group.mulG(Group.randomScalar());
        ECPoint g2 = Group.mulG(Group.randomScalar());
        ECPoint p1 = Group.mul(g1, r);
        ECPoint p2 = Group.mul(g2, rPrime);
        SigmaDLEq.Statement stmt = new SigmaDLEq.Statement(List.of(g1, g2), List.of(p1, p2));

        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);

        assertFalse(SigmaDLEq.verify(stmt, session.firstMessage(), e, z));
    }

    @Test
    void simulatorProducesVerifyingTranscripts_singleBase() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        for (int i = 0; i < 50; i++) {
            BigInteger e = SigmaDLEq.randomChallenge();
            SigmaDLEq.Transcript tr = SigmaDLEq.simulate(stmt, e);
            assertTrue(SigmaDLEq.verify(stmt, tr.first(), tr.challenge(), tr.response()));
        }
    }

    @Test
    void simulatorProducesVerifyingTranscripts_multiBase() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 5);
        for (int i = 0; i < 50; i++) {
            BigInteger e = SigmaDLEq.randomChallenge();
            SigmaDLEq.Transcript tr = SigmaDLEq.simulate(stmt, e);
            assertTrue(SigmaDLEq.verify(stmt, tr.first(), tr.challenge(), tr.response()));
        }
    }

    @Test
    void simulatorRunsWithoutWitness() {
        ECPoint g = Group.G;
        ECPoint p = Group.mulG(BigInteger.valueOf(123456789));
        SigmaDLEq.Statement stmt = new SigmaDLEq.Statement(List.of(g), List.of(p));
        BigInteger e = SigmaDLEq.randomChallenge();
        SigmaDLEq.Transcript tr = SigmaDLEq.simulate(stmt, e);
        assertTrue(SigmaDLEq.verify(stmt, tr.first(), tr.challenge(), tr.response()));
    }

    @Test
    void specialSoundness_extractsWitnessFromTwoTranscripts() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);

        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e1 = SigmaDLEq.randomChallenge();
        BigInteger e2;
        do {
            e2 = SigmaDLEq.randomChallenge();
        } while (e2.equals(e1));
        BigInteger z1 = SigmaDLEq.respond(session, e1);
        BigInteger z2 = SigmaDLEq.respond(session, e2);

        BigInteger zDiff = z1.subtract(z2).mod(Group.N);
        BigInteger eDiff = e1.subtract(e2).mod(Group.N);
        BigInteger extracted = zDiff.multiply(eDiff.modInverse(Group.N)).mod(Group.N);

        assertEquals(r.mod(Group.N), extracted);
    }

    @Test
    void hvzkSanity_realAndSimulatedAllVerifyUnderSameChallenge() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 2);
        BigInteger e = SigmaDLEq.randomChallenge();

        for (int i = 0; i < 100; i++) {
            SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
            BigInteger z = SigmaDLEq.respond(session, e);
            assertTrue(SigmaDLEq.verify(stmt, session.firstMessage(), e, z));

            SigmaDLEq.Transcript tr = SigmaDLEq.simulate(stmt, e);
            assertTrue(SigmaDLEq.verify(stmt, tr.first(), tr.challenge(), tr.response()));
        }
    }

    @Test
    void verifyRejectsMismatchedFirstMessageSize() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 3);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);

        SigmaDLEq.FirstMessage truncated =
                new SigmaDLEq.FirstMessage(session.firstMessage().a().subList(0, 2));
        assertFalse(SigmaDLEq.verify(stmt, truncated, e, z));
    }

    @Test
    void challengeSpaceCheck_rejectsNegative() {
        assertFalse(SigmaDLEq.isInChallengeSpace(BigInteger.valueOf(-1)));
    }

    @Test
    void challengeSpaceCheck_rejectsAtOrAboveN() {
        assertFalse(SigmaDLEq.isInChallengeSpace(Group.N));
        assertFalse(SigmaDLEq.isInChallengeSpace(Group.N.add(BigInteger.ONE)));
    }

    @Test
    void challengeSpaceCheck_acceptsZeroAndNMinusOne() {
        assertTrue(SigmaDLEq.isInChallengeSpace(BigInteger.ZERO));
        assertTrue(SigmaDLEq.isInChallengeSpace(Group.N.subtract(BigInteger.ONE)));
    }

    @Test
    void verifyRejectsOutOfRangeChallenge() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);
        BigInteger e = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(session, e);

        assertFalse(SigmaDLEq.verify(stmt, session.firstMessage(), Group.N.add(BigInteger.ONE), z));
    }

    @Test
    void respondRejectsOutOfRangeChallenge() {
        BigInteger r = Group.randomScalar();
        SigmaDLEq.Statement stmt = randomStatement(r, 1);
        SigmaDLEq.Session session = SigmaDLEq.commit(stmt, r);

        assertThrows(IllegalArgumentException.class,
                () -> SigmaDLEq.respond(session, Group.N));
    }

    @Test
    void statementSizeMismatchThrows() {
        ECPoint g = Group.G;
        ECPoint p = Group.mulG(BigInteger.TEN);
        assertThrows(IllegalArgumentException.class,
                () -> new SigmaDLEq.Statement(List.of(g, g), List.of(p)));
    }

    @Test
    void emptyStatementThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new SigmaDLEq.Statement(List.of(), List.of()));
    }
}
