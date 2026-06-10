package mmu.fyp.evoting.entities.bulletinboard;

import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Final result posted by the tally module (Kho et al. 2025 §6.1 Tally step 6).
 *
 * <p>Carries:
 * <ul>
 *   <li>{@code counts} — votes per candidate</li>
 *   <li>{@code tracedDoubleVoters} — identities the CA recovered from
 *       duplicate linking tags</li>
 *   <li>{@code decryptions} — for each counted ballot, the
 *       {@code (u1, plaintext)} pair the EC committed to</li>
 *   <li>{@code decryptionProof} — Fiat-Shamir NIZK over a Σ-DLEq
 *       statement proving the same EC secret {@code z} (where
 *       {@code h = z·G2} in the Cramer-Shoup public key) was used to
 *       decrypt every listed ballot — i.e. the EC didn't swap, omit, or
 *       fabricate any plaintext</li>
 * </ul>
 *
 * <p>Anyone holding {@link mmu.fyp.evoting.crypto.cramershoup.CramerShoup.PublicKey}
 * can verify the proof via {@code Tally.verifyTallyProof}.
 */
public record TallyResult(Map<Integer, Integer> counts,
                          List<String> tracedDoubleVoters,
                          List<DecryptionRecord> decryptions,
                          SigmaDLEq.Transcript decryptionProof) implements BBEntry {

    public TallyResult {
        counts = Map.copyOf(counts);
        tracedDoubleVoters = List.copyOf(tracedDoubleVoters);
        decryptions = List.copyOf(decryptions);
    }

    /** One ballot's contribution to the NIZK: the EC claims {@code u1} decrypts to {@code plaintext}. */
    public record DecryptionRecord(ECPoint u1, ECPoint e, ECPoint plaintext) {}

    @Override
    public byte[] encodeForHash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(new byte[]{'R', 'E', 'S'});
            for (var entry : new TreeMap<>(counts).entrySet()) {
                baos.write(entry.getKey().toString().getBytes(StandardCharsets.UTF_8));
                baos.write(':');
                baos.write(entry.getValue().toString().getBytes(StandardCharsets.UTF_8));
                baos.write(',');
            }
            baos.write('|');
            for (String v : tracedDoubleVoters) {
                baos.write(v.getBytes(StandardCharsets.UTF_8));
                baos.write(',');
            }
            baos.write('|');
            for (DecryptionRecord d : decryptions) {
                baos.write(Group.encode(d.u1()));
                baos.write(Group.encode(d.e()));
                baos.write(Group.encode(d.plaintext()));
            }
            baos.write('|');
            if (decryptionProof != null) {
                for (ECPoint p : decryptionProof.first().a()) baos.write(Group.encode(p));
                baos.write(decryptionProof.challenge().toByteArray());
                baos.write(decryptionProof.response().toByteArray());
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }
}
