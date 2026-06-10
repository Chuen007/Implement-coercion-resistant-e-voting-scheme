package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

/** Σ-protocol statement: ∃ r such that ct = CS.Encrypt(m, r) under pk. Four bases, one witness r. */
public final class EncryptionRelation {

    private EncryptionRelation() {}

    public static SigmaDLEq.Statement build(ECPoint m, CramerShoup.Ciphertext ct, CramerShoup.PublicKey pk) {
        BigInteger alpha = CramerShoup.hashToScalar(ct.u1(), ct.u2(), ct.e());
        ECPoint cdAlpha = Group.add(pk.c(), Group.mul(pk.d(), alpha));
        ECPoint eMinusM = Group.add(ct.e(), m.negate());
        return new SigmaDLEq.Statement(
                List.of(Group.G, pk.g2(), pk.h(), cdAlpha),
                List.of(ct.u1(), ct.u2(), eMinusM, ct.v())
        );
    }
}
