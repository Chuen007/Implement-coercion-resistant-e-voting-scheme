package mmu.fyp.evoting.crypto.cramershoup;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/** Cramer–Shoup public-key encryption (IND-CCA2 under DDH). */
public final class CramerShoup {

    public record PublicKey(ECPoint g2, ECPoint c, ECPoint d, ECPoint h) {}

    public record SecretKey(BigInteger x1, BigInteger x2, BigInteger y1, BigInteger y2, BigInteger z) {}

    public record KeyPair(PublicKey pk, SecretKey sk) {}

    public record Ciphertext(ECPoint u1, ECPoint u2, ECPoint e, ECPoint v) {}

    private CramerShoup() {}

    public static KeyPair keyGen() {
        ECPoint g2 = Group.mulG(Group.randomScalar());
        BigInteger x1 = Group.randomScalar();
        BigInteger x2 = Group.randomScalar();
        BigInteger y1 = Group.randomScalar();
        BigInteger y2 = Group.randomScalar();
        BigInteger z = Group.randomScalar();
        ECPoint c = Group.add(Group.mulG(x1), Group.mul(g2, x2));
        ECPoint d = Group.add(Group.mulG(y1), Group.mul(g2, y2));
        ECPoint h = Group.mulG(z);
        return new KeyPair(new PublicKey(g2, c, d, h), new SecretKey(x1, x2, y1, y2, z));
    }

    public static Ciphertext encrypt(ECPoint message, PublicKey pk) {
        return encrypt(message, Group.randomScalar(), pk);
    }

    /** Encrypt with externally-supplied randomness; the same r is the Σ-protocol witness in M6. */
    public static Ciphertext encrypt(ECPoint message, BigInteger r, PublicKey pk) {
        BigInteger rMod = r.mod(Group.N);
        ECPoint u1 = Group.mulG(rMod);
        ECPoint u2 = Group.mul(pk.g2(), rMod);
        ECPoint e = Group.add(Group.mul(pk.h(), rMod), message);
        BigInteger alpha = hashToScalar(u1, u2, e);
        ECPoint cdAlpha = Group.add(pk.c(), Group.mul(pk.d(), alpha));
        ECPoint v = Group.mul(cdAlpha, rMod);
        return new Ciphertext(u1, u2, e, v);
    }

    /** Returns the decrypted message, or empty if the ciphertext fails the CCA2 validity check. */
    public static Optional<ECPoint> decrypt(Ciphertext ct, SecretKey sk) {
        BigInteger alpha = hashToScalar(ct.u1(), ct.u2(), ct.e());
        BigInteger exp1 = sk.x1().add(alpha.multiply(sk.y1())).mod(Group.N);
        BigInteger exp2 = sk.x2().add(alpha.multiply(sk.y2())).mod(Group.N);
        ECPoint expected = Group.add(Group.mul(ct.u1(), exp1), Group.mul(ct.u2(), exp2));
        if (!expected.equals(ct.v())) {
            return Optional.empty();
        }
        ECPoint u1z = Group.mul(ct.u1(), sk.z());
        ECPoint m = Group.add(ct.e(), u1z.negate());
        return Optional.of(m.normalize());
    }

    /** SHA-256 of compressed encodings, reduced mod N. */
    public static BigInteger hashToScalar(ECPoint... points) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (ECPoint p : points) {
                sha.update(Group.encode(p));
            }
            return new BigInteger(1, sha.digest()).mod(Group.N);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
