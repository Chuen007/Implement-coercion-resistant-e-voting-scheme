package mmu.fyp.evoting.entities.bulletinboard;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Round 1 of the Vote protocol: EC announces the election ID and authenticates
 * it. The authentication is an {@link EOLTAA.AuthToken} produced by
 * {@code Φ.Auth} with the EC as the sole signer in a singleton directory
 * (the EC is publicly identified, so anonymity within a larger ring is not
 * needed here — only an unforgeable, CA-certified signature).
 */
public record VidNotice(byte[] vid, EOLTAA.AuthToken ecAuth) implements BBEntry {

    @Override
    public byte[] encodeForHash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(new byte[]{'V', 'I', 'D'});
            baos.write(vid);
            baos.write(Group.encode(ecAuth.linkingTag()));
            for (BigInteger c : ecAuth.challenges()) baos.write(c.toByteArray());
            for (BigInteger s : ecAuth.responses())  baos.write(s.toByteArray());
            baos.write(ecAuth.event());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }
}
