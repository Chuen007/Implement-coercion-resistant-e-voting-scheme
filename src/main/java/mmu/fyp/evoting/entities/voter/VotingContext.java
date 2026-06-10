package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;

import java.util.List;

/**
 * Public election parameters seen by every voter. Fixed once the election is
 * set up.
 *
 * <p>Mirrors the Kho et al. (2025) §6.1 building blocks consumed during the
 * Vote phase:
 *
 * <ul>
 *   <li>{@code directory} + {@code caMasterPublicKey} — input to
 *       {@link EOLTAA#auth} (voter signs ballot) and {@link EOLTAA#verify}
 *       (tally verifies ballot).</li>
 *   <li>{@code ecUpk} — EC's own EOLTAA user public key, used by the voter
 *       to verify the vid-notice authentication
 *       {@link EOLTAA#verify}(vid_message, vid_notice.ecAuth(), [ecUpk], caMpk).</li>
 *   <li>{@code ecAggregateSigningPk} — the aggregated MuSig2 public key
 *       {@code X̃} of the EC's n-party committee, used to verify the σ on
 *       each ciphertext Cᵢ.</li>
 *   <li>{@code ecEncryptionPk} — Cramer-Shoup public key the EC encrypts
 *       votes under (unchanged).</li>
 * </ul>
 */
public record VotingContext(
        VidNotice vidNotice,
        List<EOLTAA.UserPublicKey> directory,
        EOLTAA.MasterPublicKey caMasterPublicKey,
        EOLTAA.UserPublicKey ecUpk,
        MuSig2.AggregatePublicKey ecAggregateSigningPk,
        CramerShoup.PublicKey ecEncryptionPk
) {
    public VotingContext {
        directory = List.copyOf(directory);
    }
}
