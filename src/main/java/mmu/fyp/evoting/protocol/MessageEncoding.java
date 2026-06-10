package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;

/** Byte-level encoding of protocol payloads used as input to signatures and hash chains. */
public final class MessageEncoding {

    private MessageEncoding() {}

    public static byte[] serializeCiphertext(CramerShoup.Ciphertext ct) {
        byte[] u1 = Group.encode(ct.u1());
        byte[] u2 = Group.encode(ct.u2());
        byte[] e = Group.encode(ct.e());
        byte[] v = Group.encode(ct.v());
        byte[] out = new byte[u1.length + u2.length + e.length + v.length];
        int o = 0;
        System.arraycopy(u1, 0, out, o, u1.length); o += u1.length;
        System.arraycopy(u2, 0, out, o, u2.length); o += u2.length;
        System.arraycopy(e, 0, out, o, e.length); o += e.length;
        System.arraycopy(v, 0, out, o, v.length);
        return out;
    }

    public static byte[] ballotMessage(byte[] vid, CramerShoup.Ciphertext ct) {
        byte[] ctBytes = serializeCiphertext(ct);
        byte[] out = new byte[vid.length + ctBytes.length];
        System.arraycopy(vid, 0, out, 0, vid.length);
        System.arraycopy(ctBytes, 0, out, vid.length, ctBytes.length);
        return out;
    }

    public static byte[] vidMessage(byte[] vid, EOLTAA.UserPublicKey ecUpk) {
        byte[] pkBytes = Group.encode(ecUpk.Y());
        byte[] out = new byte[vid.length + pkBytes.length];
        System.arraycopy(vid, 0, out, 0, vid.length);
        System.arraycopy(pkBytes, 0, out, vid.length, pkBytes.length);
        return out;
    }
}
