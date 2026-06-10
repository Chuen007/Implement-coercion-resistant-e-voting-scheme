package mmu.fyp.evoting.entities.bulletinboard;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Posted ballot: {@code (Ci, π_i)} where {@code π_i} is the voter's EOLTAA
 * authentication token on {@code (vid ‖ Ci)} — Kho et al. (2025) Vote step 6,
 * {@code π_i = Auth(vid ‖ Ci, upk_i, usk_i, Cert_i, MPK)}.
 *
 * <p>The token's {@code linkingTag()} is consumed by the tally to detect
 * double-voting: two ballots from the same voter under the same event have
 * identical linking tags, which lets the tally discard duplicates and submit
 * the tag to the CA for tracing.
 */
public record Ballot(CramerShoup.Ciphertext ct, EOLTAA.AuthToken voterAuth) implements BBEntry {

    @Override
    public byte[] encodeForHash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(new byte[]{'B', 'A', 'L'});
            baos.write(Group.encode(ct.u1()));
            baos.write(Group.encode(ct.u2()));
            baos.write(Group.encode(ct.e()));
            baos.write(Group.encode(ct.v()));
            baos.write(Group.encode(voterAuth.linkingTag()));
            for (BigInteger c : voterAuth.challenges()) baos.write(c.toByteArray());
            for (BigInteger s : voterAuth.responses())  baos.write(s.toByteArray());
            baos.write(voterAuth.event());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }
}
