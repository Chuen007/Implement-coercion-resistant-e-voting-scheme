package mmu.fyp.evoting.entities.ec;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.multisig.MuSig2;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.ParamNotice;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.protocol.MessageEncoding;
import mmu.fyp.evoting.protocol.Tally;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Election Committee. Holds:
 *
 * <ul>
 *   <li>An <b>EOLTAA user keypair + certificate</b> (Kho et al. 2025 Register
 *       step 7 + step 10) so the EC can issue an authenticated
 *       {@code Φ.Auth} signature on the vid notice.</li>
 *   <li>A list of <b>MuSig2 member keypairs</b> (Nick-Ruffing-Seurin 2021;
 *       BIP&nbsp;327) modelling the EC as a genuine {@code n}-party
 *       multi-signature signer. Default n = 3.</li>
 *   <li>A <b>Cramer-Shoup keypair</b> for IND-CCA2 vote encryption.</li>
 * </ul>
 *
 * <p>The EC is the principal that performs the Tally phase. Per FYP 2 Chapter
 * 4 §4.3, Tally is logically a function of the EC; the {@link Tally} class is
 * the static helper this method delegates to.
 */
public final class ElectionCommittee {

    private static final int DEFAULT_MUSIG_MEMBERS = 3;
    private static final SecureRandom RNG = new SecureRandom();

    private final EOLTAA.UserKeyPair ecKey;
    private final List<MuSig2.KeyPair> musigMembers;
    private final MuSig2.AggregatePublicKey musigAggregateKey;
    private final CramerShoup.KeyPair pke;
    private final int candidateCount;

    private EOLTAA.Certificate ecCertificate;
    private List<EOLTAA.UserPublicKey> directory;
    private byte[] currentVid;

    public ElectionCommittee(int candidateCount) {
        this(candidateCount, DEFAULT_MUSIG_MEMBERS);
    }

    public ElectionCommittee(int candidateCount, int musigMemberCount) {
        if (musigMemberCount < 1) {
            throw new IllegalArgumentException("MuSig2 member count must be >= 1");
        }
        this.candidateCount = candidateCount;
        this.ecKey = EOLTAA.uKeyGen();
        this.musigMembers = generateMusigMembers(musigMemberCount);
        this.musigAggregateKey = MuSig2.aggregateKeys(musigPublicKeys());
        this.pke = CramerShoup.keyGen();
    }

    /**
     * Restoration constructor for the persistence layer: rebuilds an EC from
     * previously-generated keypairs, a previously-issued vid, and the
     * CA-issued certificate (so encrypted ballots from a prior session remain
     * decryptable, vid signatures still match, and the cert is still valid).
     */
    public ElectionCommittee(int candidateCount,
                             EOLTAA.UserKeyPair ecKey,
                             EOLTAA.Certificate ecCertificate,
                             List<MuSig2.KeyPair> musigMembers,
                             CramerShoup.KeyPair pke,
                             byte[] currentVid) {
        Objects.requireNonNull(ecKey, "ecKey");
        Objects.requireNonNull(musigMembers, "musigMembers");
        Objects.requireNonNull(pke, "pke");
        if (musigMembers.isEmpty()) {
            throw new IllegalArgumentException("MuSig2 member list must be non-empty");
        }
        this.candidateCount = candidateCount;
        this.ecKey = ecKey;
        this.ecCertificate = ecCertificate;
        this.musigMembers = List.copyOf(musigMembers);
        this.musigAggregateKey = MuSig2.aggregateKeys(musigPublicKeys());
        this.pke = pke;
        this.currentVid = currentVid;
    }

    private static List<MuSig2.KeyPair> generateMusigMembers(int n) {
        List<MuSig2.KeyPair> list = new ArrayList<>(n);
        for (int i = 0; i < n; i++) list.add(MuSig2.keyGen());
        return List.copyOf(list);
    }

    // ---------- EC's own EOLTAA identity ----------

    public EOLTAA.UserPublicKey upk() { return ecKey.upk(); }
    public EOLTAA.UserSecretKey usk() { return ecKey.usk(); }
    public EOLTAA.UserKeyPair ecKey() { return ecKey; }

    /** Set the CA-issued certificate over the EC's {@code upk}. Called once at setup. */
    public void setCertificate(EOLTAA.Certificate certificate) {
        this.ecCertificate = certificate;
    }

    public EOLTAA.Certificate certificate() { return ecCertificate; }

    // ---------- Multi-signature ----------

    public List<MuSig2.KeyPair> musigKeyPairs() { return musigMembers; }

    public List<MuSig2.PublicKey> musigPublicKeys() {
        List<MuSig2.PublicKey> out = new ArrayList<>(musigMembers.size());
        for (MuSig2.KeyPair kp : musigMembers) out.add(kp.pk());
        return List.copyOf(out);
    }

    /** The aggregated public key X̃ for {@link MuSig2#verify} of an EC multi-signature. */
    public MuSig2.AggregatePublicKey aggregateSigningKey() { return musigAggregateKey; }

    /** Run the full two-round MuSig2 protocol in-process across all EC members. */
    public MuSig2.Signature sign(byte[] message) {
        return MuSig2.sign(musigMembers, message);
    }

    // ---------- PKE ----------

    public CramerShoup.PublicKey encryptionPk() { return pke.pk(); }
    public CramerShoup.SecretKey encryptionSk() { return pke.sk(); }
    public CramerShoup.KeyPair encryptionKey() { return pke; }

    // ---------- Directory + vid state ----------

    public int candidateCount() { return candidateCount; }

    /**
     * Set the voter directory (the EOLTAA anonymity set) snapshot taken from
     * the CA when voting opens. Required input to {@link #publishVid} (only as
     * a defensive sanity check — the EC's own directory for vid signing is
     * {@code [ec.upk()]}) and consumed by tally-side verification.
     */
    public void setDirectory(List<EOLTAA.UserPublicKey> directory) {
        this.directory = List.copyOf(directory);
    }

    public List<EOLTAA.UserPublicKey> directory() {
        return directory;
    }

    public byte[] currentVid() { return currentVid; }

    // ---------- Register step 1: publish public parameters ----------

    /**
     * Register-phase step 1 (Kho et al. 2025 §6.1): runs the {@code Setup}
     * algorithms of the multi-signature and commitment schemes and posts the
     * resulting public parameters to the bulletin board. This must be called
     * before {@link #publishVid} so the {@link ParamNotice} sits at index 0 of
     * the hash chain (followed by the vid notice at index 1).
     *
     * <p>The concrete instantiation is fixed (secp256k1 + BIP 327 MuSig2 +
     * Σ-DLEq + per-voter Pedersen + Cramer-Shoup), so the notice records the
     * scheme identifiers rather than freshly-generated public parameters.
     */
    public ParamNotice publishParams(BulletinBoard bb) {
        MuSig2.Params musig = MuSig2.setup();
        ParamNotice notice = new ParamNotice(
                "secp256k1",
                "MuSig2-BIP327-n=" + musigMembers.size(),
                Group.N,
                "Pedersen-1991-with-per-voter-trapdoor (Finogina-Herranz 2023 §5.1 σ₁)",
                "Cramer-Shoup-1998 over " + musig.curve());
        bb.append(notice);
        return notice;
    }

    // ---------- Vote round 1: publish vid notice ----------

    /**
     * Round 1 of the Vote protocol: pick a random vid, authenticate it with
     * {@code Φ.Auth} under the EC's own EOLTAA credentials, and post to the
     * bulletin board. The EC's directory here is {@code [ec.upk()]} — the EC
     * is not anonymising itself.
     */
    public VidNotice publishVid(BulletinBoard bb, EOLTAA.MasterPublicKey caMpk) {
        if (ecCertificate == null) {
            throw new IllegalStateException("EC certificate not set — call ca.registerEc(ec.upk()) first");
        }
        byte[] vid = new byte[16];
        RNG.nextBytes(vid);
        byte[] msg = MessageEncoding.vidMessage(vid, ecKey.upk());
        EOLTAA.AuthToken token = EOLTAA.auth(
                msg, vid, ecKey.upk(), ecKey.usk(), ecCertificate,
                List.of(ecKey.upk()), caMpk);
        VidNotice notice = new VidNotice(vid, token);
        bb.append(notice);
        this.currentVid = vid;
        return notice;
    }

    public ECVoteSession beginVoteSession() {
        if (currentVid == null) throw new IllegalStateException("publishVid must be called first");
        return new ECVoteSession(this, currentVid);
    }

    /** Tally entry point — runs the verify / link / trace / decrypt / publish pipeline. */
    public TallyResult runTally(CertificateAuthority ca, BulletinBoard bb) {
        return Tally.run(this, ca, bb);
    }
}
