package mmu.fyp.evoting.crypto.eoltaa;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the EOLTAA scheme's Day 1 algorithms — CSetup, UKeyGen,
 * CertGen, certVerify. Σ-protocol-based instantiation per
 * {@code docs/eoltaa-design.md}, structured to match Kho et al. (2025) §6.1.
 */
class EOLTAATest {

    // ---------------- CSetup ----------------

    @Test
    void cSetupProducesNonInfinityMasterPublicKey() {
        EOLTAA.MasterKeyPair kp = EOLTAA.cSetup();
        assertNotNull(kp);
        assertNotNull(kp.mpk());
        assertNotNull(kp.msk());
        assertFalse(kp.mpk().V().isInfinity());
    }

    @Test
    void cSetupMasterSecretKeyIsInRange() {
        EOLTAA.MasterKeyPair kp = EOLTAA.cSetup();
        BigInteger alpha = kp.msk().alpha();
        assertTrue(alpha.signum() > 0, "α must be positive");
        assertTrue(alpha.compareTo(Group.N) < 0, "α must be in [1, N)");
    }

    @Test
    void cSetupPublicKeyMatchesSecret() {
        EOLTAA.MasterKeyPair kp = EOLTAA.cSetup();
        assertEquals(Group.mulG(kp.msk().alpha()), kp.mpk().V(),
                "MPK.V must equal α · G");
    }

    @Test
    void cSetupTwoCallsProduceIndependentKeys() {
        EOLTAA.MasterKeyPair kp1 = EOLTAA.cSetup();
        EOLTAA.MasterKeyPair kp2 = EOLTAA.cSetup();
        assertNotEquals(kp1.msk().alpha(), kp2.msk().alpha());
        assertNotEquals(kp1.mpk().V(), kp2.mpk().V());
    }

    // ---------------- UKeyGen ----------------

    @Test
    void uKeyGenProducesNonInfinityUserPublicKey() {
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        assertNotNull(kp);
        assertNotNull(kp.upk());
        assertNotNull(kp.usk());
        assertFalse(kp.upk().Y().isInfinity());
    }

    @Test
    void uKeyGenUserSecretKeyIsInRange() {
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        BigInteger x = kp.usk().x();
        assertTrue(x.signum() > 0, "x must be positive");
        assertTrue(x.compareTo(Group.N) < 0, "x must be in [1, N)");
    }

    @Test
    void uKeyGenPublicKeyMatchesSecret() {
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        assertEquals(Group.mulG(kp.usk().x()), kp.upk().Y(),
                "upk.Y must equal x · G");
    }

    @Test
    void uKeyGenManyCallsProduceIndependentKeys() {
        EOLTAA.UserKeyPair a = EOLTAA.uKeyGen();
        EOLTAA.UserKeyPair b = EOLTAA.uKeyGen();
        EOLTAA.UserKeyPair c = EOLTAA.uKeyGen();
        assertNotEquals(a.usk().x(), b.usk().x());
        assertNotEquals(b.usk().x(), c.usk().x());
        assertNotEquals(a.upk().Y(), b.upk().Y());
        assertNotEquals(b.upk().Y(), c.upk().Y());
    }

    // ---------------- CertGen + certVerify round-trip ----------------

    @Test
    void certGenProducesVerifiableCertificate() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
        assertTrue(EOLTAA.certVerify(cert, voter.upk(), ca.mpk()),
                "freshly issued certificate must verify");
    }

    @Test
    void certGenForManyVotersAllVerify() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        for (int i = 0; i < 16; i++) {
            EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
            EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
            assertTrue(EOLTAA.certVerify(cert, voter.upk(), ca.mpk()),
                    "certificate for voter " + i + " must verify");
        }
    }

    @Test
    void certGenSameUpkTwiceProducesDifferentCertificates() {
        // Because r is fresh per call, two certs over the same upk differ in (R, s).
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert1 = EOLTAA.certGen(ca.msk(), voter.upk());
        EOLTAA.Certificate cert2 = EOLTAA.certGen(ca.msk(), voter.upk());
        assertNotEquals(cert1.R(), cert2.R());
        assertNotEquals(cert1.s(), cert2.s());
        // Both still verify.
        assertTrue(EOLTAA.certVerify(cert1, voter.upk(), ca.mpk()));
        assertTrue(EOLTAA.certVerify(cert2, voter.upk(), ca.mpk()));
    }

    @Test
    void certGenSValueIsInRange() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
        BigInteger s = cert.s();
        assertTrue(s.signum() >= 0);
        assertTrue(s.compareTo(Group.N) < 0);
    }

    // ---------------- certVerify negative cases ----------------

    @Test
    void certVerifyRejectsTamperedS() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate good = EOLTAA.certGen(ca.msk(), voter.upk());
        EOLTAA.Certificate tampered = new EOLTAA.Certificate(
                good.R(), good.s().add(BigInteger.ONE).mod(Group.N));
        assertFalse(EOLTAA.certVerify(tampered, voter.upk(), ca.mpk()));
    }

    @Test
    void certVerifyRejectsTamperedR() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate good = EOLTAA.certGen(ca.msk(), voter.upk());
        EOLTAA.Certificate tampered = new EOLTAA.Certificate(
                Group.add(good.R(), Group.G), good.s());
        assertFalse(EOLTAA.certVerify(tampered, voter.upk(), ca.mpk()));
    }

    @Test
    void certVerifyRejectsWrongUpk() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair alice = EOLTAA.uKeyGen();
        EOLTAA.UserKeyPair bob   = EOLTAA.uKeyGen();
        EOLTAA.Certificate certForAlice = EOLTAA.certGen(ca.msk(), alice.upk());
        // Bob cannot present Alice's certificate as his own.
        assertFalse(EOLTAA.certVerify(certForAlice, bob.upk(), ca.mpk()));
    }

    @Test
    void certVerifyRejectsWrongMpk() {
        EOLTAA.MasterKeyPair caOriginal = EOLTAA.cSetup();
        EOLTAA.MasterKeyPair caImpostor = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(caOriginal.msk(), voter.upk());
        // The same cert verified under a different MPK must fail.
        assertFalse(EOLTAA.certVerify(cert, voter.upk(), caImpostor.mpk()));
    }

    @Test
    void certVerifyRejectsNullInputs() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
        assertFalse(EOLTAA.certVerify(null, voter.upk(), ca.mpk()));
        assertFalse(EOLTAA.certVerify(cert, null, ca.mpk()));
        assertFalse(EOLTAA.certVerify(cert, voter.upk(), null));
    }

    @Test
    void certVerifyRejectsOutOfRangeS() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
        EOLTAA.Certificate negS = new EOLTAA.Certificate(cert.R(), BigInteger.valueOf(-1));
        assertFalse(EOLTAA.certVerify(negS, voter.upk(), ca.mpk()));
        EOLTAA.Certificate bigS = new EOLTAA.Certificate(cert.R(), Group.N);
        assertFalse(EOLTAA.certVerify(bigS, voter.upk(), ca.mpk()));
    }

    // ---------------- Hash helpers ----------------

    @Test
    void h1IsDeterministic() {
        ECPoint R = Group.mulG(BigInteger.valueOf(42));
        ECPoint upk = Group.mulG(BigInteger.valueOf(7));
        assertEquals(EOLTAA.h1(R, upk), EOLTAA.h1(R, upk));
    }

    @Test
    void h1DiffersForDifferentInputs() {
        ECPoint R1 = Group.mulG(BigInteger.valueOf(11));
        ECPoint R2 = Group.mulG(BigInteger.valueOf(13));
        ECPoint upk = Group.mulG(BigInteger.valueOf(7));
        assertNotEquals(EOLTAA.h1(R1, upk), EOLTAA.h1(R2, upk));
        assertNotEquals(EOLTAA.h1(R1, Group.mulG(BigInteger.valueOf(8))),
                        EOLTAA.h1(R1, Group.mulG(BigInteger.valueOf(9))));
    }

    @Test
    void hashEventToPointIsDeterministicAndOnCurve() {
        byte[] eid = "election-2026".getBytes(StandardCharsets.UTF_8);
        ECPoint p1 = EOLTAA.hashEventToPoint(eid);
        ECPoint p2 = EOLTAA.hashEventToPoint(eid);
        assertEquals(p1, p2);
        assertFalse(p1.isInfinity());
        assertTrue(p1.isValid());
    }

    @Test
    void hashEventToPointDiffersForDifferentEvents() {
        ECPoint a = EOLTAA.hashEventToPoint("event-A".getBytes(StandardCharsets.UTF_8));
        ECPoint b = EOLTAA.hashEventToPoint("event-B".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(a, b);
    }

    @Test
    void hashChallengeIsDeterministic() {
        byte[] a = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] b = "world".getBytes(StandardCharsets.UTF_8);
        assertEquals(EOLTAA.hashChallenge(a, b), EOLTAA.hashChallenge(a, b));
    }

    // ====================================================================
    // Day 2: Auth + Verify (Σ-OR-proof)
    // ====================================================================

    /** Generates a CA, n voters all certified, and the directory of their upks. */
    private record Setup(EOLTAA.MasterKeyPair ca,
                         java.util.List<EOLTAA.UserKeyPair> voters,
                         java.util.List<EOLTAA.Certificate> certs,
                         java.util.List<EOLTAA.UserPublicKey> directory) {}

    private static Setup setupElection(int n) {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        java.util.List<EOLTAA.UserKeyPair> voters = new java.util.ArrayList<>();
        java.util.List<EOLTAA.Certificate> certs = new java.util.ArrayList<>();
        java.util.List<EOLTAA.UserPublicKey> dir = new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            EOLTAA.UserKeyPair v = EOLTAA.uKeyGen();
            voters.add(v);
            certs.add(EOLTAA.certGen(ca.msk(), v.upk()));
            dir.add(v.upk());
        }
        return new Setup(ca, voters, certs, java.util.List.copyOf(dir));
    }

    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test
    void authVerifyRoundTrip_singletonRing() {
        Setup s = setupElection(1);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("ballot"), bytes("election-A"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        assertTrue(EOLTAA.verify(bytes("ballot"), tok, s.directory, s.ca.mpk()));
    }

    @Test
    void authVerifyRoundTrip_ringOf3_allSignersValid() {
        Setup s = setupElection(3);
        for (int i = 0; i < 3; i++) {
            EOLTAA.AuthToken tok = EOLTAA.auth(bytes("ballot"), bytes("e"),
                    s.voters.get(i).upk(), s.voters.get(i).usk(),
                    s.certs.get(i), s.directory, s.ca.mpk());
            assertTrue(EOLTAA.verify(bytes("ballot"), tok, s.directory, s.ca.mpk()),
                    "verify must accept token from signer at index " + i);
        }
    }

    @Test
    void authVerifyRoundTrip_ringOf10() {
        Setup s = setupElection(10);
        for (int signer : new int[]{0, 1, 4, 7, 9}) {
            EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                    s.voters.get(signer).upk(), s.voters.get(signer).usk(),
                    s.certs.get(signer), s.directory, s.ca.mpk());
            assertTrue(EOLTAA.verify(bytes("m"), tok, s.directory, s.ca.mpk()),
                    "verify failed for signer " + signer);
        }
    }

    @Test
    void verifyRejectsTamperedMessage() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("original"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        assertFalse(EOLTAA.verify(bytes("tampered"), tok, s.directory, s.ca.mpk()));
    }

    @Test
    void verifyRejectsTamperedEvent() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("event-A"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        EOLTAA.AuthToken tampered = new EOLTAA.AuthToken(
                tok.linkingTag(), tok.challenges(), tok.responses(), bytes("event-B"));
        assertFalse(EOLTAA.verify(bytes("m"), tampered, s.directory, s.ca.mpk()));
    }

    @Test
    void verifyRejectsTamperedLinkingTag() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        EOLTAA.AuthToken tampered = new EOLTAA.AuthToken(
                Group.add(tok.linkingTag(), Group.G),
                tok.challenges(), tok.responses(), tok.event());
        assertFalse(EOLTAA.verify(bytes("m"), tampered, s.directory, s.ca.mpk()));
    }

    @Test
    void verifyRejectsTamperedChallenge() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        java.util.List<BigInteger> badCs = new java.util.ArrayList<>(tok.challenges());
        badCs.set(2, badCs.get(2).add(BigInteger.ONE).mod(Group.N));
        EOLTAA.AuthToken tampered = new EOLTAA.AuthToken(
                tok.linkingTag(), badCs, tok.responses(), tok.event());
        assertFalse(EOLTAA.verify(bytes("m"), tampered, s.directory, s.ca.mpk()));
    }

    @Test
    void verifyRejectsTamperedResponse() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        java.util.List<BigInteger> badSs = new java.util.ArrayList<>(tok.responses());
        badSs.set(3, badSs.get(3).add(BigInteger.ONE).mod(Group.N));
        EOLTAA.AuthToken tampered = new EOLTAA.AuthToken(
                tok.linkingTag(), tok.challenges(), badSs, tok.event());
        assertFalse(EOLTAA.verify(bytes("m"), tampered, s.directory, s.ca.mpk()));
    }

    @Test
    void verifyRejectsWrongDirectorySize() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        // Drop one entry from the directory; ring mismatch.
        java.util.List<EOLTAA.UserPublicKey> shrunk = s.directory.subList(0, 4);
        assertFalse(EOLTAA.verify(bytes("m"), tok, shrunk, s.ca.mpk()));
    }

    @Test
    void linkingTagIsDeterministicSameSignerSameEvent() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m1"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m2"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        assertEquals(a.linkingTag(), b.linkingTag(),
                "same signer + same event ⇒ identical linking tag");
    }

    @Test
    void linkingTagDiffersAcrossEvents() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("event-A"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("event-B"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        assertNotEquals(a.linkingTag(), b.linkingTag(),
                "same signer + different events ⇒ different linking tags");
    }

    @Test
    void linkingTagDiffersAcrossSigners() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(3).upk(), s.voters.get(3).usk(),
                s.certs.get(3), s.directory, s.ca.mpk());
        assertNotEquals(a.linkingTag(), b.linkingTag());
    }

    @Test
    void authIsProbabilistic() {
        // Two auths by the same signer should differ in (c, s) but not in linkingTag.
        Setup s = setupElection(5);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        assertEquals(a.linkingTag(), b.linkingTag(), "linking tag is deterministic");
        assertNotEquals(a.challenges(), b.challenges(), "challenges must be randomised");
        assertNotEquals(a.responses(), b.responses(), "responses must be randomised");
    }

    @Test
    void authRejectsOutsiderNotInDirectory() {
        Setup s = setupElection(4);
        EOLTAA.UserKeyPair outsider = EOLTAA.uKeyGen();
        EOLTAA.Certificate outsiderCert = EOLTAA.certGen(s.ca.msk(), outsider.upk());
        // The outsider has a valid cert from the same CA but is NOT in the directory.
        assertThrows(IllegalArgumentException.class,
                () -> EOLTAA.auth(bytes("m"), bytes("e"),
                        outsider.upk(), outsider.usk(),
                        outsiderCert, s.directory, s.ca.mpk()));
    }

    @Test
    void authRejectsInvalidCertificate() {
        Setup s = setupElection(4);
        // Tampered cert: change s by +1.
        EOLTAA.Certificate good = s.certs.get(0);
        EOLTAA.Certificate bad = new EOLTAA.Certificate(good.R(), good.s().add(BigInteger.ONE).mod(Group.N));
        assertThrows(IllegalArgumentException.class,
                () -> EOLTAA.auth(bytes("m"), bytes("e"),
                        s.voters.get(0).upk(), s.voters.get(0).usk(),
                        bad, s.directory, s.ca.mpk()));
    }

    @Test
    void authRejectsMismatchedSecret() {
        Setup s = setupElection(4);
        // Use voter 0's upk and cert but voter 1's secret.
        assertThrows(IllegalArgumentException.class,
                () -> EOLTAA.auth(bytes("m"), bytes("e"),
                        s.voters.get(0).upk(), s.voters.get(1).usk(),
                        s.certs.get(0), s.directory, s.ca.mpk()));
    }

    @Test
    void authRejectsEmptyDirectory() {
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());
        assertThrows(IllegalArgumentException.class,
                () -> EOLTAA.auth(bytes("m"), bytes("e"),
                        voter.upk(), voter.usk(),
                        cert, java.util.List.of(), ca.mpk()));
    }

    @Test
    void verifyRejectsTokenForWrongDirectory() {
        Setup s1 = setupElection(5);
        Setup s2 = setupElection(5);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s1.voters.get(2).upk(), s1.voters.get(2).usk(),
                s1.certs.get(2), s1.directory, s1.ca.mpk());
        // Verify against an entirely different directory; the signer's upk is not in s2.directory.
        assertFalse(EOLTAA.verify(bytes("m"), tok, s2.directory, s2.ca.mpk()));
    }

    // ====================================================================
    // Day 3: Link + Trace + integration
    // ====================================================================

    @Test
    void linkAcceptsSameSignerSameEventDifferentMessages() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("ballot-1"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("ballot-2"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        assertTrue(EOLTAA.link(a, b),
                "two authentications by the same signer for the same event must link");
    }

    @Test
    void linkRejectsDifferentSignersSameEvent() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(3).upk(), s.voters.get(3).usk(),
                s.certs.get(3), s.directory, s.ca.mpk());
        assertFalse(EOLTAA.link(a, b),
                "different signers must NOT link");
    }

    @Test
    void linkRejectsSameSignerDifferentEvents() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("event-A"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("event-B"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        assertFalse(EOLTAA.link(a, b),
                "same signer in different events must NOT link");
    }

    @Test
    void linkHandlesNullsGracefully() {
        Setup s = setupElection(2);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        assertFalse(EOLTAA.link(null, tok));
        assertFalse(EOLTAA.link(tok, null));
        assertFalse(EOLTAA.link(null, null));
    }

    @Test
    void traceRecoversCorrectVoterFromKnownLinkingTag() {
        Setup s = setupElection(7);
        int signerIdx = 4;
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(signerIdx).upk(), s.voters.get(signerIdx).usk(),
                s.certs.get(signerIdx), s.directory, s.ca.mpk());

        Optional<EOLTAA.UserPublicKey> traced =
                EOLTAA.trace(tok.linkingTag(), bytes("e"), s.voters);
        assertTrue(traced.isPresent(), "trace must find the signer");
        assertEquals(s.voters.get(signerIdx).upk(), traced.get(),
                "trace must return the actual signer's upk");
    }

    @Test
    void traceFindsCorrectVoterAcrossAllPositions() {
        Setup s = setupElection(5);
        for (int signer = 0; signer < 5; signer++) {
            EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                    s.voters.get(signer).upk(), s.voters.get(signer).usk(),
                    s.certs.get(signer), s.directory, s.ca.mpk());
            Optional<EOLTAA.UserPublicKey> traced =
                    EOLTAA.trace(tok.linkingTag(), bytes("e"), s.voters);
            assertTrue(traced.isPresent(), "trace failed for signer " + signer);
            assertEquals(s.voters.get(signer).upk(), traced.get(),
                    "trace returned wrong upk for signer " + signer);
        }
    }

    @Test
    void traceReturnsEmptyForUnknownLinkingTag() {
        Setup s = setupElection(5);
        // Construct a linking tag from an outsider's secret.
        EOLTAA.UserKeyPair outsider = EOLTAA.uKeyGen();
        ECPoint h_eid = EOLTAA.hashEventToPoint(bytes("e"));
        ECPoint outsiderTag = Group.mul(h_eid, outsider.usk().x());
        Optional<EOLTAA.UserPublicKey> traced =
                EOLTAA.trace(outsiderTag, bytes("e"), s.voters);
        assertTrue(traced.isEmpty(), "trace must not match an unregistered signer");
    }

    @Test
    void traceReturnsEmptyForWrongEvent() {
        Setup s = setupElection(5);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("event-A"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        Optional<EOLTAA.UserPublicKey> traced =
                EOLTAA.trace(tok.linkingTag(), bytes("event-B"), s.voters);
        assertTrue(traced.isEmpty(),
                "linking tag from event A must not trace under event B");
    }

    @Test
    void traceHandlesNullInputs() {
        Setup s = setupElection(3);
        EOLTAA.AuthToken tok = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        assertTrue(EOLTAA.trace(null, bytes("e"), s.voters).isEmpty());
        assertTrue(EOLTAA.trace(tok.linkingTag(), null, s.voters).isEmpty());
        assertTrue(EOLTAA.trace(tok.linkingTag(), bytes("e"), null).isEmpty());
    }

    @Test
    void traceFromLinkedTokensReturnsOffender() {
        Setup s = setupElection(6);
        int doubleVoter = 3;
        EOLTAA.AuthToken first = EOLTAA.auth(bytes("ballot-1"), bytes("e"),
                s.voters.get(doubleVoter).upk(), s.voters.get(doubleVoter).usk(),
                s.certs.get(doubleVoter), s.directory, s.ca.mpk());
        EOLTAA.AuthToken second = EOLTAA.auth(bytes("ballot-2"), bytes("e"),
                s.voters.get(doubleVoter).upk(), s.voters.get(doubleVoter).usk(),
                s.certs.get(doubleVoter), s.directory, s.ca.mpk());

        Optional<EOLTAA.UserPublicKey> traced = EOLTAA.trace(first, second, s.voters);
        assertTrue(traced.isPresent());
        assertEquals(s.voters.get(doubleVoter).upk(), traced.get());
    }

    @Test
    void traceFromUnlinkedTokensReturnsEmpty() {
        Setup s = setupElection(4);
        EOLTAA.AuthToken a = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(1).upk(), s.voters.get(1).usk(),
                s.certs.get(1), s.directory, s.ca.mpk());
        EOLTAA.AuthToken b = EOLTAA.auth(bytes("m"), bytes("e"),
                s.voters.get(2).upk(), s.voters.get(2).usk(),
                s.certs.get(2), s.directory, s.ca.mpk());
        // Different signers — tokens are not linked.
        assertTrue(EOLTAA.trace(a, b, s.voters).isEmpty());
    }

    // ---------------- End-to-end integration ----------------

    @Test
    void endToEnd_registerVoteTallyTraceForFiveVoters() {
        // Full life-cycle mirroring the Vote / Tally pipeline:
        // 1. CA runs CSetup.
        // 2. Five voters register (UKeyGen + CertGen).
        // 3. Three honest voters cast distinct ballots under event "election-2026".
        // 4. One voter (index 2) double-votes by casting two ballots.
        // 5. EC verifies every token, groups by linking tag, detects the duplicate,
        //    and asks the CA to trace the offender.
        Setup s = setupElection(5);
        byte[] event = bytes("election-2026");
        byte[][] ballots = {
                bytes("vote-Alice"),
                bytes("vote-Bob"),
                bytes("vote-Carol"),
                bytes("vote-Alice"),    // double-vote first attempt
                bytes("vote-Bob")       // double-vote second attempt
        };
        int[] signers = {0, 1, 2, 2, 4};   // voter 2 is the offender

        java.util.List<EOLTAA.AuthToken> tokens = new java.util.ArrayList<>();
        for (int i = 0; i < ballots.length; i++) {
            EOLTAA.AuthToken tok = EOLTAA.auth(ballots[i], event,
                    s.voters.get(signers[i]).upk(), s.voters.get(signers[i]).usk(),
                    s.certs.get(signers[i]), s.directory, s.ca.mpk());
            tokens.add(tok);
        }

        // Every token verifies on its own.
        for (int i = 0; i < tokens.size(); i++) {
            assertTrue(EOLTAA.verify(ballots[i], tokens.get(i), s.directory, s.ca.mpk()),
                    "token " + i + " must verify");
        }

        // Group by linking tag — find collisions.
        java.util.Map<ECPoint, java.util.List<Integer>> byTag = new java.util.LinkedHashMap<>();
        for (int i = 0; i < tokens.size(); i++) {
            byTag.computeIfAbsent(tokens.get(i).linkingTag(), k -> new java.util.ArrayList<>()).add(i);
        }

        java.util.List<EOLTAA.UserPublicKey> traced = new java.util.ArrayList<>();
        int duplicateGroups = 0;
        for (var entry : byTag.entrySet()) {
            if (entry.getValue().size() > 1) {
                duplicateGroups++;
                EOLTAA.trace(entry.getKey(), event, s.voters).ifPresent(traced::add);
            }
        }

        assertEquals(1, duplicateGroups, "exactly one collision group expected");
        assertEquals(1, traced.size(), "exactly one offender expected");
        assertEquals(s.voters.get(2).upk(), traced.get(0),
                "the traced offender must be voter 2");
    }

    @Test
    void endToEnd_crossEventUnlinkability() {
        // A voter who participates in two unrelated events under the same
        // credentials must produce un-linkable tokens — even though they
        // use the same usk, the two T1 values must differ.
        Setup s = setupElection(3);
        EOLTAA.AuthToken inEventA = EOLTAA.auth(bytes("m"), bytes("event-A"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());
        EOLTAA.AuthToken inEventB = EOLTAA.auth(bytes("m"), bytes("event-B"),
                s.voters.get(0).upk(), s.voters.get(0).usk(),
                s.certs.get(0), s.directory, s.ca.mpk());

        assertFalse(EOLTAA.link(inEventA, inEventB),
                "cross-event tokens by the same voter must NOT link");
        // And neither linking tag can be traced under the wrong event.
        assertTrue(EOLTAA.trace(inEventA.linkingTag(), bytes("event-B"), s.voters).isEmpty());
        assertTrue(EOLTAA.trace(inEventB.linkingTag(), bytes("event-A"), s.voters).isEmpty());
    }

    @Test
    void endToEnd_allKhoApiAlgorithmsExposed() {
        // Sanity check: all seven Kho 2025 §6.1 EOLTAA algorithms are
        // reachable via the EOLTAA public API.
        EOLTAA.MasterKeyPair ca = EOLTAA.cSetup();                          // 1
        EOLTAA.UserKeyPair voter = EOLTAA.uKeyGen();                        // 2
        EOLTAA.Certificate cert = EOLTAA.certGen(ca.msk(), voter.upk());    // 3
        assertTrue(EOLTAA.certVerify(cert, voter.upk(), ca.mpk()));         // 4
        EOLTAA.AuthToken tok = EOLTAA.auth(                                 // 5
                bytes("m"), bytes("e"),
                voter.upk(), voter.usk(), cert,
                java.util.List.of(voter.upk()), ca.mpk());
        assertTrue(EOLTAA.verify(bytes("m"), tok,                           // 6 (verify)
                java.util.List.of(voter.upk()), ca.mpk()));
        assertTrue(EOLTAA.link(tok, tok));                                  // 7a (link)
        assertEquals(voter.upk(),                                            // 7b (trace)
                EOLTAA.trace(tok.linkingTag(), bytes("e"),
                        java.util.List.of(voter)).orElseThrow());
    }
}
