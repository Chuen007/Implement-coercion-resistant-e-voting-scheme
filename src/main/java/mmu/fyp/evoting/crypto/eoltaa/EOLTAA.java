package mmu.fyp.evoting.crypto.eoltaa;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Event-Oriented Linkable and Traceable Anonymous Authentication (EOLTAA).
 *
 * <p>Σ-protocol-based instantiation following <b>Li, Lai &amp; Wu (2021) §5.3</b>
 * <i>Practical Instantiation</i>, structured to match the seven-algorithm
 * interface required by <b>Kho et al. (2025) §6.1</b>:
 *
 * <ol>
 *   <li>{@link #cSetup}      — CA generates master keypair (MPK, MSK)</li>
 *   <li>{@link #uKeyGen}     — voter / EC generates user keypair (upk, usk)</li>
 *   <li>{@link #certGen}     — CA issues Schnorr certificate over upk</li>
 *   <li>{@link #certVerify}  — anyone can publicly verify a certificate</li>
 *   <li>{@code auth}         — voter produces an authentication token on (eid ‖ message) — Day 2</li>
 *   <li>{@code verify}       — verifier checks an authentication token — Day 2</li>
 *   <li>{@code link} / {@code trace} — detect and identify double-authentications — Day 3</li>
 * </ol>
 *
 * <h2>Difference from the original Li 2021 §5.4 implementation</h2>
 *
 * Li 2021 instantiates the NIZK proof inside {@code Auth} using a zk-SNARK
 * (libsnark, Ben-Sasson et al.). We replace the SNARK with a Σ-OR-protocol
 * made non-interactive via Fiat-Shamir. This:
 *
 * <ul>
 *   <li>preserves <b>unforgeability, anonymity, linkability</b> and (CA-assisted)
 *       <b>traceability</b>,</li>
 *   <li>retains the {@code Special HVZK} property used in Kho 2025 Lemma 3,</li>
 *   <li>removes the trusted-setup requirement of the SNARK,</li>
 *   <li>trades the constant-size SNARK proof for an O(n)-size Σ-OR transcript
 *       (≈ 32n bytes), and</li>
 *   <li>downgrades public traceability to CA-assisted traceability —
 *       documented as a prototype simplification in
 *       {@code docs/chapter3_deviations.md}.</li>
 * </ul>
 *
 * See {@code docs/eoltaa-design.md} for the full design rationale and the
 * mapping between paper notation and the symbols used in this class.
 *
 * <h2>Cryptographic primitives</h2>
 *
 * All operations are on the secp256k1 elliptic-curve group via Bouncy Castle
 * (see {@link Group}). Hash functions:
 *
 * <ul>
 *   <li>{@code H1} (used in {@link #certGen}, {@link #certVerify}):
 *       SHA-256 of {@code (R ‖ upk)} reduced mod {@code Group.N}.</li>
 *   <li>{@code H_eid} (used in {@code auth}/{@code verify}/{@code trace}):
 *       try-and-increment hash-to-curve on the event identifier.</li>
 *   <li>{@code H_chl} (used in {@code auth}/{@code verify}): Fiat-Shamir
 *       challenge over the Σ-protocol transcript.</li>
 * </ul>
 */
public final class EOLTAA {

    private EOLTAA() {}

    // ====================================================================
    // Record types
    // ====================================================================

    /** CA master public key: {@code V = α · G}. Published to the bulletin board at registration time. */
    public record MasterPublicKey(ECPoint V) {
        public MasterPublicKey {
            Objects.requireNonNull(V, "V");
        }
    }

    /** CA master secret key: {@code α} such that {@code V = α · G}. Held by the CA only. */
    public record MasterSecretKey(BigInteger alpha) {
        public MasterSecretKey {
            Objects.requireNonNull(alpha, "alpha");
        }
    }

    /** CA master keypair returned by {@link #cSetup}. */
    public record MasterKeyPair(MasterPublicKey mpk, MasterSecretKey msk) {}

    /** User public key: {@code upk = x · G} for some secret {@code x}. */
    public record UserPublicKey(ECPoint Y) {
        public UserPublicKey {
            Objects.requireNonNull(Y, "Y");
        }
    }

    /** User secret key: {@code x} such that {@code upk = x · G}. */
    public record UserSecretKey(BigInteger x) {
        public UserSecretKey {
            Objects.requireNonNull(x, "x");
        }
    }

    /** User keypair returned by {@link #uKeyGen}. */
    public record UserKeyPair(UserPublicKey upk, UserSecretKey usk) {}

    /**
     * CA-issued certificate over a user public key. Schnorr-style:
     * {@code R = r · G}, {@code s = α + r · H1(R ‖ upk)}.
     */
    public record Certificate(ECPoint R, BigInteger s) {
        public Certificate {
            Objects.requireNonNull(R, "R");
            Objects.requireNonNull(s, "s");
        }
    }

    /**
     * Authentication token produced by {@code Auth}. Contains the linking tag
     * {@code T1 = x · H_eid(eid)} and a Σ-OR-proof transcript over the public
     * directory of certified user keys. (Full content defined in Day 2.)
     */
    public record AuthToken(ECPoint linkingTag,
                            List<BigInteger> challenges,
                            List<BigInteger> responses,
                            byte[] event) {
        public AuthToken {
            Objects.requireNonNull(linkingTag, "linkingTag");
            challenges = List.copyOf(challenges);
            responses  = List.copyOf(responses);
            event = event.clone();
        }

        @Override public byte[] event() { return event.clone(); }
    }

    // ====================================================================
    // 1. CSetup — CA master keypair generation
    // ====================================================================

    /**
     * Φ.CSetup(1^λ) → (MPK, MSK). Generates the CA's master keypair.
     *
     * <p>Concretely:
     * <pre>
     *     α  ← Z_N \ {0}
     *     V  = α · G
     *     return MPK = V,  MSK = α
     * </pre>
     */
    public static MasterKeyPair cSetup() {
        BigInteger alpha = Group.randomScalar();
        ECPoint V = Group.mulG(alpha);
        return new MasterKeyPair(new MasterPublicKey(V), new MasterSecretKey(alpha));
    }

    // ====================================================================
    // 2. UKeyGen — voter / EC user keypair generation
    // ====================================================================

    /**
     * Φ.UKeyGen(1^λ) → (upk, usk). Each voter (and the EC) runs this to
     * obtain their own anonymous-authentication keypair.
     *
     * <pre>
     *     x   ← Z_N \ {0}
     *     upk = x · G
     *     return upk, usk = x
     * </pre>
     */
    public static UserKeyPair uKeyGen() {
        BigInteger x = Group.randomScalar();
        ECPoint Y = Group.mulG(x);
        return new UserKeyPair(new UserPublicKey(Y), new UserSecretKey(x));
    }

    // ====================================================================
    // 3. CertGen — CA issues a Schnorr certificate over upk
    // ====================================================================

    /**
     * Φ.CertGen(MSK, upk) → Cert. The CA signs {@code upk} with a Schnorr
     * signature using {@code MSK}. The certificate proves that {@code upk}
     * was admitted to the directory by the CA.
     *
     * <pre>
     *     r = Z_N \ {0}                       (fresh per-cert randomness)
     *     R = r · G
     *     a = H1(R ‖ upk)                     reduced mod N
     *     s = α + r · a                       (mod N)
     *     return Cert = (R, s)
     * </pre>
     *
     * <p>This is a Schnorr signature on {@code upk} verifiable by
     * {@link #certVerify}: {@code s · G == V + a · R}.
     */
    public static Certificate certGen(MasterSecretKey msk, UserPublicKey upk) {
        Objects.requireNonNull(msk, "msk");
        Objects.requireNonNull(upk, "upk");
        BigInteger r = Group.randomScalar();
        ECPoint R = Group.mulG(r);
        BigInteger a = h1(R, upk.Y());
        BigInteger s = msk.alpha().add(r.multiply(a)).mod(Group.N);
        return new Certificate(R, s);
    }

    // ====================================================================
    // 4. CertVerify — anyone can publicly verify a CA certificate
    // ====================================================================

    /**
     * Φ.Verify (certificate variant): given {@code upk}, {@code Cert = (R, s)},
     * and {@code MPK = V}, check that {@code Cert} is a valid Schnorr signature
     * on {@code upk}:
     *
     * <pre>
     *     a   = H1(R ‖ upk)
     *     OK  iff   s · G == V + a · R
     * </pre>
     *
     * <p>This check is performed by anyone holding the public directory and
     * MPK; no secret information is required.
     */
    public static boolean certVerify(Certificate cert, UserPublicKey upk, MasterPublicKey mpk) {
        if (cert == null || upk == null || mpk == null) return false;
        BigInteger s = cert.s();
        if (s == null || s.signum() < 0 || s.compareTo(Group.N) >= 0) return false;
        if (cert.R().isInfinity() || mpk.V().isInfinity() || upk.Y().isInfinity()) return false;

        BigInteger a = h1(cert.R(), upk.Y());
        ECPoint lhs = Group.mulG(s);
        ECPoint rhs = Group.add(mpk.V(), Group.mul(cert.R(), a));
        return lhs.equals(rhs);
    }

    // ====================================================================
    // Hash helpers
    // ====================================================================

    /**
     * H1: hash {@code (R ‖ upk)} (both as compressed points) into a scalar
     * mod {@code Group.N}. Used by {@link #certGen} and {@link #certVerify}.
     */
    static BigInteger h1(ECPoint R, ECPoint upk) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("EOLTAA-H1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            sha.update(Group.encode(R));
            sha.update(Group.encode(upk));
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * H_eid: hash an event identifier into a curve point using try-and-increment.
     * Each event yields its own independent generator, so linking tags
     * {@code T1 = x · H_eid(eid)} are event-bound — re-using the same secret
     * under different events gives unlinkable tags. Used by Day 2/3 algorithms.
     */
    static ECPoint hashEventToPoint(byte[] event) {
        BigInteger p = Group.CURVE.getField().getCharacteristic();
        BigInteger sqrtExp = p.add(BigInteger.ONE).shiftRight(2);  // (p+1)/4 since p ≡ 3 mod 4
        for (int counter = 0; counter < 1024; counter++) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sha.update("EOLTAA-H_eid".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                sha.update(event);
                sha.update(intToBytes(counter));
                BigInteger candidateX = new BigInteger(1, sha.digest()).mod(p);
                BigInteger ySquared = candidateX.modPow(BigInteger.valueOf(3), p)
                        .add(BigInteger.valueOf(7)).mod(p);
                BigInteger y = ySquared.modPow(sqrtExp, p);
                if (y.modPow(BigInteger.TWO, p).equals(ySquared)) {
                    ECPoint point = Group.CURVE.createPoint(candidateX, y);
                    if (!point.isInfinity() && point.isValid()) {
                        return point.normalize();
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        throw new IllegalStateException("hash-to-point failed after 1024 tries");
    }

    /**
     * H_chl: Fiat-Shamir challenge over the Σ-protocol transcript. Used by
     * Day 2 algorithms ({@code auth}, {@code verify}). Implementation deferred.
     */
    static BigInteger hashChallenge(byte[]... inputs) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("EOLTAA-H_chl".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            for (byte[] in : inputs) sha.update(in);
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    /**
     * Encodes a public directory of user keys as a single byte stream, for use
     * inside the Fiat-Shamir transcript. Used by Day 2 algorithms.
     */
    static byte[] encodeDirectory(List<UserPublicKey> directory) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            for (UserPublicKey upk : directory) {
                baos.write(Group.encode(upk.Y()));
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    // ====================================================================
    // 5. Auth — voter produces an anonymous, linkable authentication token
    // ====================================================================

    /**
     * Φ.Auth(m = eid ‖ payload, (upk, usk), Cert, MPK, directory) → π.
     *
     * <p>The voter produces an {@link AuthToken} demonstrating:
     * <ul>
     *   <li>knowledge of {@code usk} such that {@code upk = usk · G} for some
     *       {@code upk} in {@code directory}, and</li>
     *   <li>the linking tag {@code T1 = usk · H_eid(event)} is well-formed
     *       for the <i>same</i> secret used in the membership proof.</li>
     * </ul>
     *
     * <p>The proof is a non-interactive Σ-OR-proof made non-interactive via
     * Fiat-Shamir. Concretely, for the signer at unknown index {@code π} in
     * the directory and ring size {@code n}:
     *
     * <pre>
     *   h_eid = H_eid(event)
     *   T1    = usk · h_eid
     *
     *   k_π   ← Z_N \ {0}
     *   L_π   = k_π · G
     *   R_π   = k_π · h_eid
     *   for i ∈ {0..n-1} \ {π}:
     *       c_i ← Z_N,  s_i ← Z_N
     *       L_i = s_i · G       + c_i · directory[i].Y
     *       R_i = s_i · h_eid   + c_i · T1
     *
     *   c_total = H_chl(dir‖event‖m‖T1‖L_0..L_{n-1}‖R_0..R_{n-1}) mod N
     *   c_π     = c_total - Σ_{i≠π} c_i   (mod N)
     *   s_π     = k_π - c_π · usk         (mod N)
     *   return AuthToken(T1, [c_0..c_{n-1}], [s_0..s_{n-1}], event)
     * </pre>
     *
     * <p>{@code cert} and {@code mpk} are used only for a startup sanity
     * check ({@link #certVerify} must succeed); the directory itself is
     * assumed to contain only CA-certified upks, so the Σ-OR-proof does not
     * carry the cert chain inside the relation.
     *
     * @throws IllegalArgumentException if the signer's {@code upk} is not in
     *         {@code directory}, or if {@code certVerify} rejects {@code cert}.
     */
    public static AuthToken auth(byte[] message,
                                  byte[] event,
                                  UserPublicKey upk,
                                  UserSecretKey usk,
                                  Certificate cert,
                                  List<UserPublicKey> directory,
                                  MasterPublicKey mpk) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(upk, "upk");
        Objects.requireNonNull(usk, "usk");
        Objects.requireNonNull(cert, "cert");
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(mpk, "mpk");
        if (directory.isEmpty()) {
            throw new IllegalArgumentException("directory must be non-empty");
        }
        if (!certVerify(cert, upk, mpk)) {
            throw new IllegalArgumentException("invalid certificate for the supplied upk");
        }

        int n = directory.size();
        int signerIndex = indexOf(directory, upk);
        if (signerIndex < 0) {
            throw new IllegalArgumentException("signer's upk is not in the directory");
        }
        // Sanity: secret matches public key.
        if (!Group.mulG(usk.x()).equals(upk.Y())) {
            throw new IllegalArgumentException("usk does not match upk");
        }

        ECPoint h_eid = hashEventToPoint(event);
        ECPoint T1 = Group.mul(h_eid, usk.x());

        BigInteger k_pi = Group.randomScalar();
        ECPoint[] L = new ECPoint[n];
        ECPoint[] R = new ECPoint[n];
        BigInteger[] c = new BigInteger[n];
        BigInteger[] s = new BigInteger[n];

        // Simulated transcripts for i ≠ π.
        BigInteger c_sum_others = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            if (i == signerIndex) continue;
            c[i] = Group.randomScalar();
            s[i] = Group.randomScalar();
            L[i] = Group.mulAdd(Group.G, s[i], directory.get(i).Y(), c[i]);
            R[i] = Group.mulAdd(h_eid, s[i], T1, c[i]);
            c_sum_others = c_sum_others.add(c[i]).mod(Group.N);
        }

        // Real prover's first message at position π.
        L[signerIndex] = Group.mulG(k_pi);
        R[signerIndex] = Group.mul(h_eid, k_pi);

        // Fiat-Shamir challenge.
        BigInteger c_total = transcriptChallenge(directory, event, message, T1, L, R);

        // Close the OR-proof at position π.
        c[signerIndex] = c_total.subtract(c_sum_others).mod(Group.N);
        s[signerIndex] = k_pi.subtract(c[signerIndex].multiply(usk.x())).mod(Group.N);

        return new AuthToken(T1, Arrays.asList(c), Arrays.asList(s), event);
    }

    // ====================================================================
    // 6. Verify — anyone can publicly verify an AuthToken
    // ====================================================================

    /**
     * Φ.Verify(m, π, MPK, directory) → 0/1. Verifies an authentication token.
     *
     * <p>The verifier replays the Σ-OR-proof and checks that the per-index
     * challenges sum to the Fiat-Shamir digest:
     *
     * <pre>
     *   h_eid = H_eid(token.event)
     *   for i ∈ {0..n-1}:
     *       L_i = s_i · G       + c_i · directory[i].Y
     *       R_i = s_i · h_eid   + c_i · token.T1
     *   c_total = H_chl(dir‖event‖m‖T1‖L_0..L_{n-1}‖R_0..R_{n-1}) mod N
     *   accept iff  c_total == Σ_i c_i   (mod N)
     * </pre>
     *
     * <p>{@code mpk} is accepted for API symmetry with Kho 2025 §6.1 but is
     * not consulted inside the Σ-OR-proof check; the directory is assumed
     * to have been pre-validated against {@code mpk} via {@link #certVerify}.
     */
    public static boolean verify(byte[] message,
                                  AuthToken token,
                                  List<UserPublicKey> directory,
                                  MasterPublicKey mpk) {
        if (message == null || token == null || directory == null || mpk == null) return false;
        int n = directory.size();
        if (n == 0) return false;
        if (token.challenges().size() != n || token.responses().size() != n) return false;
        if (token.linkingTag().isInfinity()) return false;

        // Range checks on every scalar.
        for (int i = 0; i < n; i++) {
            BigInteger ci = token.challenges().get(i);
            BigInteger si = token.responses().get(i);
            if (ci == null || si == null) return false;
            if (ci.signum() < 0 || ci.compareTo(Group.N) >= 0) return false;
            if (si.signum() < 0 || si.compareTo(Group.N) >= 0) return false;
        }

        ECPoint h_eid;
        try {
            h_eid = hashEventToPoint(token.event());
        } catch (RuntimeException ex) {
            return false;
        }

        ECPoint[] L = new ECPoint[n];
        ECPoint[] R = new ECPoint[n];
        BigInteger c_sum = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            BigInteger ci = token.challenges().get(i);
            BigInteger si = token.responses().get(i);
            L[i] = Group.mulAdd(Group.G, si, directory.get(i).Y(), ci);
            R[i] = Group.mulAdd(h_eid, si, token.linkingTag(), ci);
            c_sum = c_sum.add(ci).mod(Group.N);
        }

        BigInteger c_total;
        try {
            c_total = transcriptChallenge(directory, token.event(), message, token.linkingTag(), L, R);
        } catch (RuntimeException ex) {
            return false;
        }
        return c_total.equals(c_sum);
    }

    // ====================================================================
    // Fiat-Shamir transcript helper (shared by auth and verify)
    // ====================================================================

    /**
     * Fiat-Shamir challenge for the Σ-OR-proof. The {@code (directory ‖ event ‖
     * message ‖ T1)} prefix is the same for both auth and verify and is hashed
     * once; only the {@code (L_0..L_{n-1} ‖ R_0..R_{n-1})} suffix varies.
     */
    private static BigInteger transcriptChallenge(List<UserPublicKey> directory,
                                                  byte[] event,
                                                  byte[] message,
                                                  ECPoint T1,
                                                  ECPoint[] L,
                                                  ECPoint[] R) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("EOLTAA-H_chl".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            sha.update(encodeDirectory(directory));
            sha.update(event);
            sha.update(message);
            sha.update(Group.encode(T1));
            for (ECPoint Li : L) sha.update(Group.encode(Li));
            for (ECPoint Ri : R) sha.update(Group.encode(Ri));
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static int indexOf(List<UserPublicKey> directory, UserPublicKey upk) {
        for (int i = 0; i < directory.size(); i++) {
            if (directory.get(i).Y().equals(upk.Y())) return i;
        }
        return -1;
    }

    // ====================================================================
    // 7a. Link — detect two authentications by the same signer / event
    // ====================================================================

    /**
     * Φ.Link((m_1, π_1), (m_2, π_2)) → 0/1. Two authentication tokens are
     * linked iff they share the <b>same event identifier</b> AND the
     * <b>same linking tag</b> T1. Because T1 = usk · H_eid(event) is a
     * deterministic function of (signer's secret, event), this is
     * equivalent to "same signer + same event".
     *
     * <p>Returns {@code false} if either token is {@code null}. Note that
     * Link does <i>not</i> re-verify the underlying Σ-OR-proofs — callers
     * are expected to have called {@link #verify} first.
     */
    public static boolean link(AuthToken token1, AuthToken token2) {
        if (token1 == null || token2 == null) return false;
        if (!Arrays.equals(token1.event(), token2.event())) return false;
        return token1.linkingTag().equals(token2.linkingTag());
    }

    // ====================================================================
    // 7b. Trace — CA recovers the identity behind a linking tag
    // ====================================================================

    /**
     * Φ.Trace(linkingTag, event, registry) → upk. Given a linking tag
     * known to belong to a double-voter, recovers the offender's user
     * public key by scanning the CA registry.
     *
     * <p>Concretely:
     * <pre>
     *     h_eid = H_eid(event)
     *     for each (upk_i, usk_i) ∈ registry:
     *         if usk_i · h_eid == linkingTag:
     *             return upk_i
     *     return None
     * </pre>
     *
     * <p>This is the <b>CA-assisted</b> tracing simplification documented
     * in {@code docs/chapter3_deviations.md}. A production deployment
     * would replace this with a publicly-verifiable zk-SNARK trace proof
     * (Li 2021 §5.4), eliminating the need for the CA to escrow voter
     * secret keys. See Chapter 5 future work.
     *
     * <p>Performance: {@code h_eid} is hoisted out of the loop, so a trace
     * over a registry of n entries costs n scalar multiplications + n
     * point comparisons — O(n) total.
     */
    public static Optional<UserPublicKey> trace(ECPoint linkingTag,
                                                 byte[] event,
                                                 Iterable<UserKeyPair> registry) {
        if (linkingTag == null || event == null || registry == null) return Optional.empty();
        if (linkingTag.isInfinity()) return Optional.empty();

        ECPoint h_eid = hashEventToPoint(event);
        for (UserKeyPair pair : registry) {
            if (pair == null || pair.usk() == null || pair.upk() == null) continue;
            ECPoint candidate = Group.mul(h_eid, pair.usk().x());
            if (candidate.equals(linkingTag)) {
                return Optional.of(pair.upk());
            }
        }
        return Optional.empty();
    }

    /**
     * Convenience overload: traces the offender behind two linked
     * authentication tokens. Returns empty if the tokens are not linked.
     */
    public static Optional<UserPublicKey> trace(AuthToken token1,
                                                 AuthToken token2,
                                                 Iterable<UserKeyPair> registry) {
        if (!link(token1, token2)) return Optional.empty();
        return trace(token1.linkingTag(), token1.event(), registry);
    }
}
