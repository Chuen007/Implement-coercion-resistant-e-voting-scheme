package mmu.fyp.evoting.entities.ca;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import org.bouncycastle.math.ec.ECPoint;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Certificate Authority. Holds the voter registry, the EC's EOLTAA user
 * public key (so it can issue the EC its own certificate), and an EOLTAA
 * master keypair {@code (MPK, MSK)} used to issue per-voter certificates.
 *
 * <p>Maps onto Kho et al. (2025) Register phase:
 * <ul>
 *   <li>{@link #CertificateAuthority()} performs
 *       {@code Φ.CSetup(1^λ) → (MPK, MSK)} via {@link EOLTAA#cSetup} — the
 *       EOLTAA master keypair (α, V = α·G) from Li, Lai &amp; Wu (2021) §5.1
 *       generic construction.</li>
 *   <li>{@link #processRegistrationRequest} performs
 *       {@code Φ.CertGen(MSK, upk) → Cert} via {@link EOLTAA#certGen}. The
 *       certificate is returned in {@link RegistrationResponse.Approved} and
 *       stored alongside the voter record so that anyone holding MPK can later
 *       verify "this voter was admitted to D1 by the CA".</li>
 * </ul>
 *
 * <p>Per §3.7.2 of the deviation notes, the prototype CA additionally escrows
 * each voter's {@link EOLTAA.UserSecretKey} so it can compute event-bound
 * linking tags during {@link #trace} — this is a deliberate engineering
 * simplification of the EOLTAA public-traceability property, which in the
 * Li 2021 §5.3 instantiation would require a zk-SNARK of identity.
 */
public final class CertificateAuthority {

    /**
     * One row of the CA's D1 ID database: voter identity, their EOLTAA user
     * keypair (the {@code usk} is escrowed per §3.7.2), and the CA-issued
     * EOLTAA certificate that the voter carries.
     */
    public record VoterRecord(String identity,
                              EOLTAA.UserPublicKey upk,
                              EOLTAA.UserSecretKey usk,
                              EOLTAA.Certificate certificate) {}

    private final Map<String, VoterRecord> voters = new LinkedHashMap<>();
    private final EligibilityChecker eligibilityChecker;
    private final EOLTAA.MasterKeyPair masterKey;
    private EOLTAA.UserPublicKey ecUpk;
    private EOLTAA.Certificate ecCertificate;

    /** Default constructor — accepts every identity (prototype). */
    public CertificateAuthority() {
        this(EligibilityChecker.ACCEPT_ALL);
    }

    /** Constructor with a custom eligibility checker; generates a fresh master keypair. */
    public CertificateAuthority(EligibilityChecker eligibilityChecker) {
        this(eligibilityChecker, EOLTAA.cSetup());
    }

    /**
     * Restoration constructor for the persistence layer: rebuilds a CA from a
     * previously-generated EOLTAA master keypair so that certificates issued
     * in earlier sessions remain verifiable across restarts.
     */
    public CertificateAuthority(EligibilityChecker eligibilityChecker,
                                EOLTAA.MasterKeyPair masterKey) {
        this.eligibilityChecker = eligibilityChecker;
        this.masterKey = masterKey;
    }

    /**
     * Register the EC as an EOLTAA user: issue a {@code Φ.CertGen} certificate
     * over the EC's {@link EOLTAA.UserPublicKey} and return it so the EC can
     * carry the cert for vid-notice authentication. The EC's upk + cert are
     * also retained by the CA so it can rebuild the singleton directory used
     * for verifying the vid notice during tally.
     */
    public EOLTAA.Certificate registerEc(EOLTAA.UserPublicKey ecUpk) {
        this.ecUpk = ecUpk;
        this.ecCertificate = EOLTAA.certGen(masterKey.msk(), ecUpk);
        return this.ecCertificate;
    }

    /** The EC's EOLTAA public key, available after {@link #registerEc}. */
    public EOLTAA.UserPublicKey ecUpk() { return ecUpk; }

    /** The CA-issued EC certificate, available after {@link #registerEc}. */
    public EOLTAA.Certificate ecCertificate() { return ecCertificate; }

    /**
     * The CA's master public key (MPK). Anyone can verify a voter's certificate
     * against this key via {@link EOLTAA#certVerify} to confirm the voter was
     * admitted to D1.
     */
    public EOLTAA.MasterPublicKey masterPublicKey() {
        return masterKey.mpk();
    }

    /** The full master keypair — exposed so the persistence layer can checkpoint it. */
    public EOLTAA.MasterKeyPair masterKeyPair() {
        return masterKey;
    }

    /**
     * Process a registration request. Returns {@link RegistrationResponse.Approved}
     * with the voter's allocated ring position and certificate on success, or
     * {@link RegistrationResponse.Rejected} with a reason on failure. This is the
     * canonical registration entry point and corresponds to process 1.0 in the
     * Chapter 4 §4.7 data-flow diagram.
     *
     * <p>On success the CA performs {@code Φ.CertGen(MSK, upk) → Cert} via
     * {@link EOLTAA#certGen} and stores the voter record in D1.
     */
    public RegistrationResponse processRegistrationRequest(RegistrationRequest request) {
        if (!eligibilityChecker.isEligible(request.identity())) {
            return new RegistrationResponse.Rejected(request.identity(), "ineligible");
        }
        if (voters.containsKey(request.identity())) {
            return new RegistrationResponse.Rejected(request.identity(), "duplicate identity");
        }
        EOLTAA.UserKeyPair creds = request.credentials();
        EOLTAA.Certificate certificate = issueCertificate(creds.upk());
        voters.put(request.identity(),
                new VoterRecord(request.identity(), creds.upk(), creds.usk(), certificate));
        int position = voters.size() - 1;
        return new RegistrationResponse.Approved(request.identity(), position, certificate);
    }

    /**
     * {@code Φ.CertGen(MSK, upk) → Cert}. Issues an EOLTAA certificate over the
     * supplied user public key using the CA's master secret key.
     */
    public EOLTAA.Certificate issueCertificate(EOLTAA.UserPublicKey upk) {
        return EOLTAA.certGen(masterKey.msk(), upk);
    }

    /** Verify an EOLTAA certificate against the CA's master public key. */
    public static boolean verifyCertificate(EOLTAA.UserPublicKey upk,
                                            EOLTAA.Certificate certificate,
                                            EOLTAA.MasterPublicKey mpk) {
        return EOLTAA.certVerify(certificate, upk, mpk);
    }

    /**
     * Convenience wrapper around {@link #processRegistrationRequest}. Throws
     * {@link IneligibleVoterException} if the identity fails the eligibility check,
     * and {@link IllegalArgumentException} if the identity is already registered.
     */
    public void registerVoter(String identity, EOLTAA.UserKeyPair credentials) {
        var response = processRegistrationRequest(new RegistrationRequest(identity, credentials));
        if (response instanceof RegistrationResponse.Rejected rejected) {
            if ("ineligible".equals(rejected.reason())) {
                throw new IneligibleVoterException(identity);
            }
            throw new IllegalArgumentException("duplicate voter: " + identity);
        }
    }

    /** D1 view from the FYP 2 Chapter 4 §4.7 data-flow diagram: registered identities. */
    public Set<String> registeredIdentities() {
        return Set.copyOf(voters.keySet());
    }

    /**
     * The EOLTAA directory: the ordered list of certified user public keys. This
     * is the "voter ring" of the system and the input to {@link EOLTAA#auth}
     * and {@link EOLTAA#verify}.
     */
    public List<EOLTAA.UserPublicKey> directory() {
        List<EOLTAA.UserPublicKey> dir = new ArrayList<>();
        for (var r : voters.values()) dir.add(r.upk());
        return List.copyOf(dir);
    }

    /** Retrieve a voter's certificate by identity, or {@code null} if no such voter. */
    public EOLTAA.Certificate certificateOf(String identity) {
        VoterRecord r = voters.get(identity);
        return r == null ? null : r.certificate();
    }

    public int positionOf(String identity) {
        int i = 0;
        for (var entry : voters.entrySet()) {
            if (entry.getKey().equals(identity)) return i;
            i++;
        }
        return -1;
    }

    public int registeredVoterCount() {
        return voters.size();
    }

    /**
     * CA-assisted trace (EOLTAA-native). Given a linking tag known to belong to
     * a double-voter, recovers the offender's identity by delegating to
     * {@link EOLTAA#trace}, which recomputes {@code usk_i · H_eid(event)} for
     * every escrowed user secret key and matches against the supplied tag.
     *
     * <p>This is the {@code Φ.Trace} algorithm of Kho et al. (2025) §6.1, run in
     * its CA-assisted (escrow) form per the §3.7.2 deviation note. The linking
     * tag is the event-bound EOLTAA tag {@code T1 = usk · H_eid(vid)} produced by
     * {@link EOLTAA#auth} during voting.
     */
    public Optional<String> trace(ECPoint linkingTag, byte[] event) {
        List<EOLTAA.UserKeyPair> registry = new ArrayList<>();
        Map<EOLTAA.UserPublicKey, String> identityByUpk = new LinkedHashMap<>();
        for (var r : voters.values()) {
            registry.add(new EOLTAA.UserKeyPair(r.upk(), r.usk()));
            identityByUpk.put(r.upk(), r.identity());
        }
        return EOLTAA.trace(linkingTag, event, registry).map(identityByUpk::get);
    }

    /** Raised when the eligibility checker rejects a registration attempt. */
    public static final class IneligibleVoterException extends RuntimeException {
        public IneligibleVoterException(String identity) {
            super("voter ineligible: " + identity);
        }
    }
}
