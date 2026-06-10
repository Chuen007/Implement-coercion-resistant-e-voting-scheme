package mmu.fyp.evoting.crypto.multisig;

import mmu.fyp.evoting.crypto.group.Group;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the MuSig2 multi-signature (Nick-Ruffing-Seurin 2021 / BIP327),
 * realising the Kho et al. (2025) §3.3 MS (multi-signature) interface.
 */
class MuSig2Test {

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static List<MuSig2.KeyPair> committee(int n) {
        List<MuSig2.KeyPair> ks = new ArrayList<>(n);
        for (int i = 0; i < n; i++) ks.add(MuSig2.keyGen());
        return ks;
    }

    private static List<MuSig2.PublicKey> pubKeys(List<MuSig2.KeyPair> kps) {
        List<MuSig2.PublicKey> out = new ArrayList<>(kps.size());
        for (MuSig2.KeyPair kp : kps) out.add(kp.pk());
        return out;
    }

    // ---------------- Setup / KeyGen ----------------

    @Test
    void setupReturnsCurveParams() {
        MuSig2.Params p = MuSig2.setup();
        assertNotNull(p);
        assertEquals("secp256k1", p.curve());
    }

    @Test
    void keyGenProducesConsistentKeypair() {
        MuSig2.KeyPair kp = MuSig2.keyGen();
        assertFalse(kp.pk().X().isInfinity());
        assertEquals(Group.mulG(kp.sk().x()), kp.pk().X(), "X must equal x · G");
    }

    @Test
    void keyGenProducesIndependentKeys() {
        MuSig2.KeyPair a = MuSig2.keyGen();
        MuSig2.KeyPair b = MuSig2.keyGen();
        assertNotEquals(a.sk().x(), b.sk().x());
        assertNotEquals(a.pk().X(), b.pk().X());
    }

    // ---------------- Key aggregation ----------------

    @Test
    void aggregateKeysIsDeterministic() {
        List<MuSig2.KeyPair> ks = committee(3);
        MuSig2.AggregatePublicKey a1 = MuSig2.aggregateKeys(pubKeys(ks));
        MuSig2.AggregatePublicKey a2 = MuSig2.aggregateKeys(pubKeys(ks));
        assertEquals(a1.X_tilde(), a2.X_tilde());
    }

    @Test
    void aggregateKeysIsOrderSensitive() {
        // Because we do not sort L, a different ordering yields a different X̃
        // (the coefficients a_i depend on the encoding of the full ordered list).
        List<MuSig2.KeyPair> ks = committee(3);
        List<MuSig2.PublicKey> forward = pubKeys(ks);
        List<MuSig2.PublicKey> reversed = new ArrayList<>(forward);
        java.util.Collections.reverse(reversed);
        assertNotEquals(MuSig2.aggregateKeys(forward).X_tilde(),
                        MuSig2.aggregateKeys(reversed).X_tilde());
    }

    @Test
    void aggregateSingleKeyEqualsCoefficientTimesKey() {
        MuSig2.KeyPair kp = MuSig2.keyGen();
        MuSig2.AggregatePublicKey agg = MuSig2.aggregateKeys(List.of(kp.pk()));
        assertFalse(agg.X_tilde().isInfinity());
        // X̃ for a singleton is a_1 · X_1, which is generally NOT equal to X_1.
        // We only assert it is a well-formed non-infinity point and is reproducible.
        assertEquals(agg.X_tilde(), MuSig2.aggregateKeys(List.of(kp.pk())).X_tilde());
    }

    @Test
    void aggregateKeysRejectsEmptyList() {
        assertThrows(IllegalArgumentException.class,
                () -> MuSig2.aggregateKeys(List.of()));
    }

    // ---------------- Nonce generation ----------------

    @Test
    void genNonceProducesTwoDistinctNonces() {
        MuSig2.NoncePair np = MuSig2.genNonce();
        assertNotEquals(np.sec().r1(), np.sec().r2());
        assertEquals(Group.mulG(np.sec().r1()), np.pub().R1());
        assertEquals(Group.mulG(np.sec().r2()), np.pub().R2());
    }

    @Test
    void genNonceIsFreshEachCall() {
        MuSig2.NoncePair a = MuSig2.genNonce();
        MuSig2.NoncePair b = MuSig2.genNonce();
        assertNotEquals(a.sec().r1(), b.sec().r1());
        assertNotEquals(a.pub().R1(), b.pub().R1());
    }

    // ---------------- Sign + Verify round trips ----------------

    @Test
    void signVerifyRoundTrip_singleSigner() {
        List<MuSig2.KeyPair> ks = committee(1);
        byte[] m = bytes("ciphertext-Ci");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertTrue(MuSig2.verify(sig, pubKeys(ks), m));
    }

    @Test
    void signVerifyRoundTrip_twoSigners() {
        List<MuSig2.KeyPair> ks = committee(2);
        byte[] m = bytes("ciphertext-Ci");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertTrue(MuSig2.verify(sig, pubKeys(ks), m));
    }

    @Test
    void signVerifyRoundTrip_threeSigners() {
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("ciphertext-Ci");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertTrue(MuSig2.verify(sig, pubKeys(ks), m));
    }

    @Test
    void signVerifyRoundTrip_fiveSigners() {
        List<MuSig2.KeyPair> ks = committee(5);
        byte[] m = bytes("ciphertext-Ci");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertTrue(MuSig2.verify(sig, pubKeys(ks), m));
    }

    @Test
    void verifyViaAggregateKeyOverloadMatchesListOverload() {
        List<MuSig2.KeyPair> ks = committee(4);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        MuSig2.AggregatePublicKey agg = MuSig2.aggregateKeys(pubKeys(ks));
        assertTrue(MuSig2.verify(sig, agg, m));
        assertTrue(MuSig2.verify(sig, pubKeys(ks), m));
    }

    // ---------------- Negative cases ----------------

    @Test
    void verifyRejectsTamperedMessage() {
        List<MuSig2.KeyPair> ks = committee(3);
        MuSig2.Signature sig = MuSig2.sign(ks, bytes("original"));
        assertFalse(MuSig2.verify(sig, pubKeys(ks), bytes("tampered")));
    }

    @Test
    void verifyRejectsTamperedR() {
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        MuSig2.Signature bad = new MuSig2.Signature(Group.add(sig.R(), Group.G), sig.s());
        assertFalse(MuSig2.verify(bad, pubKeys(ks), m));
    }

    @Test
    void verifyRejectsTamperedS() {
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        MuSig2.Signature bad = new MuSig2.Signature(
                sig.R(), sig.s().add(BigInteger.ONE).mod(Group.N));
        assertFalse(MuSig2.verify(bad, pubKeys(ks), m));
    }

    @Test
    void verifyRejectsOutOfRangeS() {
        List<MuSig2.KeyPair> ks = committee(2);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertFalse(MuSig2.verify(new MuSig2.Signature(sig.R(), BigInteger.valueOf(-1)),
                pubKeys(ks), m));
        assertFalse(MuSig2.verify(new MuSig2.Signature(sig.R(), Group.N),
                pubKeys(ks), m));
    }

    @Test
    void verifyRejectsWrongSignerSet() {
        List<MuSig2.KeyPair> ksA = committee(3);
        List<MuSig2.KeyPair> ksB = committee(3);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ksA, m);
        // Same message, but verified under a different committee.
        assertFalse(MuSig2.verify(sig, pubKeys(ksB), m));
    }

    @Test
    void verifyRejectsMissingSigner() {
        // A signature produced by a 3-member committee must not verify under a
        // 2-member subset (the aggregate key X̃ differs).
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        List<MuSig2.PublicKey> subset = pubKeys(ks).subList(0, 2);
        assertFalse(MuSig2.verify(sig, subset, m));
    }

    @Test
    void verifyHandlesNullsGracefully() {
        List<MuSig2.KeyPair> ks = committee(2);
        byte[] m = bytes("m");
        MuSig2.Signature sig = MuSig2.sign(ks, m);
        assertFalse(MuSig2.verify(null, pubKeys(ks), m));
        assertFalse(MuSig2.verify(sig, (List<MuSig2.PublicKey>) null, m));
        assertFalse(MuSig2.verify(sig, pubKeys(ks), null));
        assertFalse(MuSig2.verify(sig, List.of(), m));
    }

    // ---------------- Probabilistic / structural ----------------

    @Test
    void signatureIsProbabilistic() {
        // Two signings of the same message by the same committee differ in
        // (R, s) because nonces are fresh, but both verify.
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("m");
        MuSig2.Signature a = MuSig2.sign(ks, m);
        MuSig2.Signature b = MuSig2.sign(ks, m);
        assertNotEquals(a.R(), b.R());
        assertNotEquals(a.s(), b.s());
        assertTrue(MuSig2.verify(a, pubKeys(ks), m));
        assertTrue(MuSig2.verify(b, pubKeys(ks), m));
    }

    @Test
    void manualThreeStepSigningMatchesConvenienceWrapper() {
        // Exercise the explicit round structure: genNonce -> partialSign ->
        // aggregateSignatures, and confirm the result verifies.
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("ciphertext");
        MuSig2.AggregatePublicKey agg = MuSig2.aggregateKeys(pubKeys(ks));

        // Round 1
        List<MuSig2.NoncePair> nonces = new ArrayList<>();
        List<MuSig2.PublicNonce> pubNonces = new ArrayList<>();
        for (int i = 0; i < ks.size(); i++) {
            MuSig2.NoncePair np = MuSig2.genNonce();
            nonces.add(np);
            pubNonces.add(np.pub());
        }
        // Round 2
        List<MuSig2.PartialSignature> partials = new ArrayList<>();
        for (int i = 0; i < ks.size(); i++) {
            partials.add(MuSig2.partialSign(
                    ks.get(i).sk(), nonces.get(i).sec(), agg, pubNonces, m));
        }
        MuSig2.Signature sig = MuSig2.aggregateSignatures(agg, pubNonces, partials, m);
        assertTrue(MuSig2.verify(sig, agg, m));
    }

    @Test
    void incompletePartialSetProducesInvalidSignature() {
        // If one signer withholds its partial signature, aggregation over the
        // remaining partials must NOT verify — no single member can sign alone.
        List<MuSig2.KeyPair> ks = committee(3);
        byte[] m = bytes("m");
        MuSig2.AggregatePublicKey agg = MuSig2.aggregateKeys(pubKeys(ks));

        List<MuSig2.NoncePair> nonces = new ArrayList<>();
        List<MuSig2.PublicNonce> pubNonces = new ArrayList<>();
        for (int i = 0; i < ks.size(); i++) {
            MuSig2.NoncePair np = MuSig2.genNonce();
            nonces.add(np);
            pubNonces.add(np.pub());
        }
        // Only the first two signers contribute partials; the third withholds.
        List<MuSig2.PartialSignature> partials = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            partials.add(MuSig2.partialSign(
                    ks.get(i).sk(), nonces.get(i).sec(), agg, pubNonces, m));
        }
        MuSig2.Signature sig = MuSig2.aggregateSignatures(agg, pubNonces, partials, m);
        assertFalse(MuSig2.verify(sig, agg, m),
                "aggregate over an incomplete partial set must not verify");
    }

    @Test
    void rogueKeyResistance_coefficientBindsToFullList() {
        // A signer's aggregation coefficient depends on the full ordered list,
        // so the same key in two different committees aggregates differently.
        MuSig2.KeyPair shared = MuSig2.keyGen();
        MuSig2.KeyPair other1 = MuSig2.keyGen();
        MuSig2.KeyPair other2 = MuSig2.keyGen();
        MuSig2.AggregatePublicKey aggA =
                MuSig2.aggregateKeys(List.of(shared.pk(), other1.pk()));
        MuSig2.AggregatePublicKey aggB =
                MuSig2.aggregateKeys(List.of(shared.pk(), other2.pk()));
        assertNotEquals(aggA.X_tilde(), aggB.X_tilde());
    }
}
