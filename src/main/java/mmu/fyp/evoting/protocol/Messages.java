package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Wire-level messages exchanged between Voter and EC during the 4-round
 * Vote protocol.
 *
 * <p>{@link Round3#ecSig} is a MuSig2 aggregated multi-signature
 * (Nick-Ruffing-Seurin 2021; BIP 327) produced by the EC's n-party committee.
 */
public final class Messages {

    private Messages() {}

    /** Voter → EC: (candidate v, commitment cmt, Pedersen base h_v). */
    public record Round2(int candidate, ECPoint commitment, ECPoint pedersenH) {}

    /** EC → Voter: (ciphertext Ci, EC's MuSig2 multi-signature σ on Ci, Σ-protocol first move a). */
    public record Round3(CramerShoup.Ciphertext ct, MuSig2.Signature ecSig, SigmaDLEq.FirstMessage sigmaA) {}

    /** Voter → EC: (Σ-challenge e, commitment randomness r̂). */
    public record Round4(BigInteger e, BigInteger rHat) {}

    /** EC → Voter: Σ-protocol response z. */
    public record Round5(BigInteger z) {}
}
