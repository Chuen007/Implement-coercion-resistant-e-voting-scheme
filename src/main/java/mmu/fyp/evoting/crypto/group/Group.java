package mmu.fyp.evoting.crypto.group;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/** Prime-order elliptic-curve group (secp256k1). */
public final class Group {

    private static final X9ECParameters PARAMS = CustomNamedCurves.getByName("secp256k1");
    public static final ECCurve CURVE = PARAMS.getCurve();
    public static final ECPoint G = PARAMS.getG();
    public static final BigInteger N = PARAMS.getN();

    private static final SecureRandom RNG = new SecureRandom();

    private Group() {}

    public static BigInteger randomScalar() {
        BigInteger s;
        do {
            s = new BigInteger(N.bitLength(), RNG);
        } while (s.signum() == 0 || s.compareTo(N) >= 0);
        return s;
    }

    public static ECPoint mulG(BigInteger s) {
        return G.multiply(s).normalize();
    }

    public static ECPoint mul(ECPoint p, BigInteger s) {
        return p.multiply(s).normalize();
    }

    public static ECPoint add(ECPoint a, ECPoint b) {
        return a.add(b).normalize();
    }

    /**
     * Simultaneous double-scalar multiplication s_a·A + s_b·B via Shamir's trick
     * ({@link ECAlgorithms#sumOfTwoMultiplies}). Roughly 1.5–2× faster than two
     * separate scalar multiplications plus an add, and it normalizes once instead
     * of three times. This is the dominant cost in the EOLTAA Σ-OR proof,
     * where every directory round forms terms of the shape s·G + c·Y.
     */
    public static ECPoint mulAdd(ECPoint a, BigInteger sa, ECPoint b, BigInteger sb) {
        return ECAlgorithms.sumOfTwoMultiplies(a, sa, b, sb).normalize();
    }

    public static byte[] encode(ECPoint p) {
        return p.normalize().getEncoded(true);
    }

    public static ECPoint decode(byte[] bytes) {
        return CURVE.decodePoint(bytes).normalize();
    }
}
