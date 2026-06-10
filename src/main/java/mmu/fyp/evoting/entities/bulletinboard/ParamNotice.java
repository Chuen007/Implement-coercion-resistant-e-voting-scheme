package mmu.fyp.evoting.entities.bulletinboard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Register-phase step 1 (Kho et al. 2025 §6.1): the Election Committee runs
 * {@code MS.Setup} and {@code Commitment.Setup} and publishes the resulting
 * public parameters to the bulletin board so every party (voter, CA, future
 * verifier) sees the same instantiation choices.
 *
 * <p>For our concrete instantiation most fields are constants
 * (secp256k1 + BIP 327 MuSig2 + Σ-DLEq over the secp256k1 scalar field), but
 * publishing them turns the implicit "everyone knows" convention into an
 * explicit, hash-chained record on D0.
 *
 * <p>Field meaning:
 * <ul>
 *   <li>{@code groupName} — the prime-order group all primitives live in (curve name).</li>
 *   <li>{@code musigScheme} — concrete multi-signature instantiation
 *       (e.g. "MuSig2-BIP327").</li>
 *   <li>{@code sigmaChallengeOrder} — the order {@code N} of the Σ-protocol
 *       challenge space {@code Chl = [0, N)}.</li>
 *   <li>{@code commitmentScheme} — concrete commitment instantiation. We use
 *       Pedersen with per-voter trapdoor (Finogina-Herranz 2023 §5.1 σ₁), so
 *       this field encodes the convention rather than a global {@code H}.</li>
 *   <li>{@code pkeScheme} — concrete IND-CCA2 PKE label
 *       (e.g. "Cramer-Shoup-1998 over secp256k1").</li>
 * </ul>
 */
public record ParamNotice(String groupName,
                          String musigScheme,
                          BigInteger sigmaChallengeOrder,
                          String commitmentScheme,
                          String pkeScheme) implements BBEntry {

    @Override
    public byte[] encodeForHash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(new byte[]{'P', 'A', 'R'});
            writeString(baos, groupName);
            writeString(baos, musigScheme);
            baos.write(sigmaChallengeOrder.toByteArray());
            writeString(baos, commitmentScheme);
            writeString(baos, pkeScheme);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    private static void writeString(ByteArrayOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        out.write(b.length);
        out.write(b);
    }
}
