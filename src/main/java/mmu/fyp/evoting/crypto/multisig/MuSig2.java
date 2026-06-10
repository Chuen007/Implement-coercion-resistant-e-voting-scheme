package mmu.fyp.evoting.crypto.multisig;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * MuSig2 multi-signature (Nick, Ruffing &amp; Seurin, CRYPTO 2021; standardised
 * as BIP&nbsp;327). Realises the four-algorithm multi-signature interface
 * required by <b>Kho et al. (2025) §3.3</b>:
 *
 * <ul>
 *   <li>{@link #setup}    — {@code MS.Setup(1^λ) → params}</li>
 *   <li>{@link #keyGen}   — {@code MS.KeyGen(params) → (pk_i, sk_i)}</li>
 *   <li>{@code MS.Sign}   — interactive; exposed as the three-step round
 *       structure {@link #genNonce} → {@link #partialSign} →
 *       {@link #aggregateSignatures}, plus the in-process convenience
 *       wrapper {@link #sign}</li>
 *   <li>{@link #verify}   — {@code MS.Verify(L, σ, m) → 1/0}</li>
 * </ul>
 *
 * <h2>Why MuSig2</h2>
 *
 * In the Kho 2025 Vote protocol the election committee jointly signs every
 * ciphertext {@code C_i} so the voter is convinced "all n committee members
 * jointly endorsed (v, r)". MuSig2 is the concrete realisation of the
 * required {@code n}-party multi-signature:
 *
 * <ul>
 *   <li><b>Compact</b> — the multi-signature {@code (R, s)} is the same size as
 *       a single Schnorr signature regardless of {@code n}, and verification is
 *       ordinary Schnorr verification under the aggregate key {@code X̃}.</li>
 *   <li><b>Distributed trust</b> — no single committee member can produce a
 *       valid signature alone; all members must contribute a partial signature.</li>
 *   <li><b>Concurrently secure</b> — MuSig2 uses {@code ν = 2} nonces per signer,
 *       which defeats the Drijvers/Wagner attack that breaks naive two-round
 *       multi-signatures under concurrent sessions.</li>
 *   <li><b>Rogue-key resistant</b> — each signer's key-aggregation coefficient
 *       {@code a_i = H_agg(L ‖ X_i)} binds to the full ordered key list {@code L},
 *       so a malicious member cannot choose a key that cancels the honest ones.</li>
 * </ul>
 *
 * <h2>Scheme</h2>
 *
 * <p><b>Key aggregation.</b> For an ordered list {@code L = [X_1, …, X_n]}:
 * <pre>
 *     a_i = H_agg(L ‖ X_i)            (aggregation coefficient)
 *     X̃   = Σ_i a_i · X_i             (aggregate public key)
 * </pre>
 *
 * <p><b>Signing (two rounds, ν = 2 nonces).</b>
 * <pre>
 *   Round 1 (per signer i):
 *     r_{i,1}, r_{i,2} ← Z_N
 *     R_{i,1} = r_{i,1}·G ,  R_{i,2} = r_{i,2}·G   (published)
 *
 *   Round 2 (after collecting all public nonces):
 *     R_1 = Σ_i R_{i,1} ,  R_2 = Σ_i R_{i,2}        (aggregate nonces)
 *     b   = H_non(X̃ ‖ R_1 ‖ R_2 ‖ m)
 *     R   = R_1 + b·R_2                              (effective nonce)
 *     c   = H_sig(X̃ ‖ R ‖ m)                        (challenge)
 *     s_i = c·a_i·x_i + r_{i,1} + b·r_{i,2}  (mod N) (partial signature)
 *     s   = Σ_i s_i  (mod N)
 *   Signature = (R, s)
 * </pre>
 *
 * <p><b>Verification.</b> Ordinary Schnorr under the aggregate key:
 * <pre>
 *     c = H_sig(X̃ ‖ R ‖ m)
 *     accept iff  s·G == R + c·X̃
 * </pre>
 *
 * <p>Correctness:
 * {@code s·G = Σ_i (c·a_i·x_i + r_{i,1} + b·r_{i,2})·G
 *            = c·Σ_i a_i·X_i + Σ_i R_{i,1} + b·Σ_i R_{i,2}
 *            = c·X̃ + R_1 + b·R_2 = R + c·X̃}.
 *
 * <p>This implementation works over the prime-order secp256k1 group with full
 * compressed-point encoding; it deliberately omits BIP&nbsp;327's x-only /
 * even-Y key normalisation, which is a Bitcoin serialisation optimisation, not
 * a security requirement of the MuSig2 scheme itself.
 */
public final class MuSig2 {

    private static final String H_AGG = "MuSig2/agg";
    private static final String H_NON = "MuSig2/non";
    private static final String H_SIG = "MuSig2/sig";

    private static final int NONCE_COUNT = 2;   // ν = 2

    private MuSig2() {}

    // ====================================================================
    // Record types
    // ====================================================================

    /** Public parameters returned by {@link #setup}. The group is fixed (secp256k1). */
    public record Params(String curve) {}

    /** A signer's public key {@code X_i = x_i · G}. */
    public record PublicKey(ECPoint X) {
        public PublicKey {
            Objects.requireNonNull(X, "X");
        }
    }

    /** A signer's secret key {@code x_i}. */
    public record SecretKey(BigInteger x) {
        public SecretKey {
            Objects.requireNonNull(x, "x");
        }
    }

    /** A signer's keypair returned by {@link #keyGen}. */
    public record KeyPair(PublicKey pk, SecretKey sk) {}

    /**
     * The aggregate public key {@code X̃} together with the ordered list of
     * signer public keys {@code L} it was derived from. Both are needed to
     * recompute aggregation coefficients during signing and verification.
     */
    public record AggregatePublicKey(ECPoint X_tilde, List<PublicKey> signers) {
        public AggregatePublicKey {
            Objects.requireNonNull(X_tilde, "X_tilde");
            signers = List.copyOf(signers);
        }
    }

    /** One signer's two public nonces {@code (R_{i,1}, R_{i,2})} from round 1. */
    public record PublicNonce(ECPoint R1, ECPoint R2) {
        public PublicNonce {
            Objects.requireNonNull(R1, "R1");
            Objects.requireNonNull(R2, "R2");
        }
    }

    /** One signer's two secret nonces {@code (r_{i,1}, r_{i,2})}; kept private. */
    public record SecretNonce(BigInteger r1, BigInteger r2) {
        public SecretNonce {
            Objects.requireNonNull(r1, "r1");
            Objects.requireNonNull(r2, "r2");
        }
    }

    /** A signer's round-1 nonce output: the public nonce and the matching secret nonce. */
    public record NoncePair(PublicNonce pub, SecretNonce sec) {}

    /** A single signer's partial signature {@code s_i}. */
    public record PartialSignature(BigInteger s) {
        public PartialSignature {
            Objects.requireNonNull(s, "s");
        }
    }

    /** The final aggregated multi-signature {@code (R, s)}. */
    public record Signature(ECPoint R, BigInteger s) {
        public Signature {
            Objects.requireNonNull(R, "R");
            Objects.requireNonNull(s, "s");
        }
    }

    // ====================================================================
    // MS.Setup / MS.KeyGen
    // ====================================================================

    /** {@code MS.Setup(1^λ)}. The group is the fixed secp256k1 curve. */
    public static Params setup() {
        return new Params("secp256k1");
    }

    /** {@code MS.KeyGen(params) → (pk, sk)} with {@code pk = sk · G}. */
    public static KeyPair keyGen() {
        BigInteger x = Group.randomScalar();
        return new KeyPair(new PublicKey(Group.mulG(x)), new SecretKey(x));
    }

    // ====================================================================
    // Key aggregation
    // ====================================================================

    /**
     * Aggregate an ordered list of signer public keys into {@code X̃ = Σ a_i·X_i},
     * where {@code a_i = H_agg(L ‖ X_i)} binds to the full ordered list {@code L}.
     *
     * @throws IllegalArgumentException if {@code signers} is empty
     */
    public static AggregatePublicKey aggregateKeys(List<PublicKey> signers) {
        Objects.requireNonNull(signers, "signers");
        if (signers.isEmpty()) {
            throw new IllegalArgumentException("signer list must be non-empty");
        }
        byte[] L = encodeKeyList(signers);
        ECPoint acc = null;
        for (PublicKey pk : signers) {
            BigInteger a_i = aggCoefficient(L, pk.X());
            ECPoint term = Group.mul(pk.X(), a_i);
            acc = (acc == null) ? term : Group.add(acc, term);
        }
        return new AggregatePublicKey(acc, signers);
    }

    /** Aggregation coefficient {@code a_i = H_agg(L ‖ X_i) mod N}. */
    private static BigInteger aggCoefficient(byte[] encodedKeyList, ECPoint X_i) {
        return hashToScalar(H_AGG, encodedKeyList, Group.encode(X_i));
    }

    // ====================================================================
    // MS.Sign — round 1: nonce generation
    // ====================================================================

    /**
     * Round 1 of {@code MS.Sign}: a signer draws {@code ν = 2} fresh nonces and
     * publishes the two corresponding nonce points.
     *
     * <p>The returned {@link SecretNonce} must be kept private and used exactly
     * once, in the matching {@link #partialSign} call. Re-using a secret nonce
     * across two signing sessions leaks the secret key.
     */
    public static NoncePair genNonce() {
        BigInteger r1 = Group.randomScalar();
        BigInteger r2 = Group.randomScalar();
        PublicNonce pub = new PublicNonce(Group.mulG(r1), Group.mulG(r2));
        return new NoncePair(pub, new SecretNonce(r1, r2));
    }

    // ====================================================================
    // MS.Sign — round 2: partial signing
    // ====================================================================

    /**
     * Round 2 of {@code MS.Sign}: a signer produces its partial signature.
     *
     * <pre>
     *     X_i = x_i·G ;  a_i = H_agg(L ‖ X_i)
     *     R_1 = Σ_j R_{j,1} ;  R_2 = Σ_j R_{j,2}
     *     b   = H_non(X̃ ‖ R_1 ‖ R_2 ‖ m)
     *     R   = R_1 + b·R_2
     *     c   = H_sig(X̃ ‖ R ‖ m)
     *     s_i = c·a_i·x_i + r_{i,1} + b·r_{i,2}   (mod N)
     * </pre>
     *
     * @param sk               this signer's secret key
     * @param secNonce         this signer's secret nonce from {@link #genNonce}
     * @param aggPk            the aggregate key (carries the ordered key list L)
     * @param allPublicNonces  the public nonces of <i>all</i> signers (this signer's included)
     * @param message          the message being signed
     */
    public static PartialSignature partialSign(SecretKey sk,
                                               SecretNonce secNonce,
                                               AggregatePublicKey aggPk,
                                               List<PublicNonce> allPublicNonces,
                                               byte[] message) {
        Objects.requireNonNull(sk, "sk");
        Objects.requireNonNull(secNonce, "secNonce");
        Objects.requireNonNull(aggPk, "aggPk");
        Objects.requireNonNull(allPublicNonces, "allPublicNonces");
        Objects.requireNonNull(message, "message");
        if (allPublicNonces.isEmpty()) {
            throw new IllegalArgumentException("public nonce list must be non-empty");
        }

        ECPoint X_i = Group.mulG(sk.x());
        BigInteger a_i = aggCoefficient(encodeKeyList(aggPk.signers()), X_i);

        ECPoint[] agg = aggregateNonces(allPublicNonces);
        ECPoint R1 = agg[0];
        ECPoint R2 = agg[1];
        BigInteger b = nonceCoefficient(aggPk.X_tilde(), R1, R2, message);
        ECPoint R = effectiveNonce(R1, R2, b);
        BigInteger c = challenge(aggPk.X_tilde(), R, message);

        BigInteger s_i = c.multiply(a_i).mod(Group.N).multiply(sk.x()).mod(Group.N)
                .add(secNonce.r1())
                .add(b.multiply(secNonce.r2()))
                .mod(Group.N);
        return new PartialSignature(s_i);
    }

    // ====================================================================
    // MS.Sign — aggregation of partial signatures
    // ====================================================================

    /**
     * Combine the signers' partial signatures into the final multi-signature
     * {@code (R, s)} where {@code R = R_1 + b·R_2} and {@code s = Σ_i s_i (mod N)}.
     */
    public static Signature aggregateSignatures(AggregatePublicKey aggPk,
                                                List<PublicNonce> allPublicNonces,
                                                List<PartialSignature> partials,
                                                byte[] message) {
        Objects.requireNonNull(aggPk, "aggPk");
        Objects.requireNonNull(allPublicNonces, "allPublicNonces");
        Objects.requireNonNull(partials, "partials");
        Objects.requireNonNull(message, "message");
        if (allPublicNonces.isEmpty() || partials.isEmpty()) {
            throw new IllegalArgumentException("nonce and partial lists must be non-empty");
        }

        ECPoint[] agg = aggregateNonces(allPublicNonces);
        BigInteger b = nonceCoefficient(aggPk.X_tilde(), agg[0], agg[1], message);
        ECPoint R = effectiveNonce(agg[0], agg[1], b);

        BigInteger s = BigInteger.ZERO;
        for (PartialSignature p : partials) {
            s = s.add(p.s()).mod(Group.N);
        }
        return new Signature(R, s);
    }

    // ====================================================================
    // MS.Sign — in-process convenience wrapper
    // ====================================================================

    /**
     * Run the full two-round MuSig2 signing protocol in-process across all
     * supplied signers and return the aggregate signature. This is the form the
     * election committee uses in the single-process prototype, where one
     * principal controls every committee member's key share.
     *
     * <p>The lower-level {@link #genNonce} / {@link #partialSign} /
     * {@link #aggregateSignatures} entry points remain available so the rounds
     * can be split across processes in a networked deployment.
     *
     * @throws IllegalArgumentException if {@code signers} is empty
     */
    public static Signature sign(List<KeyPair> signers, byte[] message) {
        Objects.requireNonNull(signers, "signers");
        Objects.requireNonNull(message, "message");
        if (signers.isEmpty()) {
            throw new IllegalArgumentException("signer list must be non-empty");
        }

        List<PublicKey> pubKeys = new ArrayList<>(signers.size());
        for (KeyPair kp : signers) pubKeys.add(kp.pk());
        AggregatePublicKey aggPk = aggregateKeys(pubKeys);

        // Round 1: every signer draws a nonce pair.
        List<NoncePair> nonces = new ArrayList<>(signers.size());
        List<PublicNonce> publicNonces = new ArrayList<>(signers.size());
        for (int i = 0; i < signers.size(); i++) {
            NoncePair np = genNonce();
            nonces.add(np);
            publicNonces.add(np.pub());
        }

        // Round 2: every signer produces a partial signature.
        List<PartialSignature> partials = new ArrayList<>(signers.size());
        for (int i = 0; i < signers.size(); i++) {
            partials.add(partialSign(
                    signers.get(i).sk(), nonces.get(i).sec(),
                    aggPk, publicNonces, message));
        }

        return aggregateSignatures(aggPk, publicNonces, partials, message);
    }

    // ====================================================================
    // MS.Verify
    // ====================================================================

    /**
     * {@code MS.Verify(L, σ, m)}: ordinary Schnorr verification under the
     * aggregate key. Accepts iff {@code s·G == R + c·X̃} with
     * {@code c = H_sig(X̃ ‖ R ‖ m)}.
     */
    public static boolean verify(Signature sig, AggregatePublicKey aggPk, byte[] message) {
        if (sig == null || aggPk == null || message == null) return false;
        BigInteger s = sig.s();
        if (s == null || s.signum() < 0 || s.compareTo(Group.N) >= 0) return false;
        if (sig.R() == null || sig.R().isInfinity()) return false;
        if (aggPk.X_tilde().isInfinity()) return false;

        BigInteger c = challenge(aggPk.X_tilde(), sig.R(), message);
        ECPoint lhs = Group.mulG(s);
        ECPoint rhs = Group.add(sig.R(), Group.mul(aggPk.X_tilde(), c));
        return lhs.equals(rhs);
    }

    /** Convenience overload that aggregates {@code signers} before verifying. */
    public static boolean verify(Signature sig, List<PublicKey> signers, byte[] message) {
        if (signers == null || signers.isEmpty()) return false;
        return verify(sig, aggregateKeys(signers), message);
    }

    // ====================================================================
    // Internal helpers
    // ====================================================================

    /** Aggregate per-signer nonces: returns {@code [R_1, R_2]} with {@code R_j = Σ_i R_{i,j}}. */
    private static ECPoint[] aggregateNonces(List<PublicNonce> nonces) {
        ECPoint R1 = null;
        ECPoint R2 = null;
        for (PublicNonce n : nonces) {
            R1 = (R1 == null) ? n.R1() : Group.add(R1, n.R1());
            R2 = (R2 == null) ? n.R2() : Group.add(R2, n.R2());
        }
        return new ECPoint[]{R1, R2};
    }

    /** Nonce coefficient {@code b = H_non(X̃ ‖ R_1 ‖ R_2 ‖ m) mod N}. */
    private static BigInteger nonceCoefficient(ECPoint X_tilde, ECPoint R1, ECPoint R2, byte[] m) {
        return hashToScalar(H_NON, Group.encode(X_tilde), Group.encode(R1), Group.encode(R2), m);
    }

    /** Effective nonce {@code R = R_1 + b·R_2}. */
    private static ECPoint effectiveNonce(ECPoint R1, ECPoint R2, BigInteger b) {
        return Group.add(R1, Group.mul(R2, b));
    }

    /** Schnorr challenge {@code c = H_sig(X̃ ‖ R ‖ m) mod N}. */
    private static BigInteger challenge(ECPoint X_tilde, ECPoint R, byte[] m) {
        return hashToScalar(H_SIG, Group.encode(X_tilde), Group.encode(R), m);
    }

    /** Encode an ordered key list {@code L} as the concatenation of compressed points. */
    private static byte[] encodeKeyList(List<PublicKey> signers) {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        try {
            for (PublicKey pk : signers) baos.write(Group.encode(pk.X()));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    /** Domain-separated SHA-256 hash of the given parts, reduced mod {@code N}. */
    private static BigInteger hashToScalar(String domain, byte[]... parts) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(domain.getBytes(StandardCharsets.US_ASCII));
            for (byte[] p : parts) sha.update(p);
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
