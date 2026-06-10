package mmu.fyp.evoting.entities.voter;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ca.RegistrationRequest;
import mmu.fyp.evoting.entities.ca.RegistrationResponse;

import java.util.Optional;

/**
 * A registered voter.
 *
 * <p>State held: (a) the voter's identity string, (b) the voter's EOLTAA user
 * keypair {@code (upk_i, usk_i) ← Φ.UKeyGen(1^λ)} from Kho et al. (2025)
 * Register step 7, (c) the voter's position in the public voter directory, and
 * (d) the CA-issued EOLTAA certificate
 * {@code Cert_i ← Φ.CertGen(MSK, upk_i)} which the voter carries as proof of
 * admission to D1 (Register step 10). The certificate is verifiable against
 * the CA's master public key via
 * {@link CertificateAuthority#verifyCertificate}.
 *
 * <p>External callers must construct voters via {@link #register} to enforce
 * the FYP 2 Chapter 4 §4.4 use case ordering: "Register identity" must succeed
 * before any other voter action. The package-private constructor exists only
 * for internal collaborators in the same package (e.g. CoercionFake test
 * helpers).
 *
 */
public final class Voter {

    private final String identity;
    private final EOLTAA.UserKeyPair eoltaaKey;
    private final EOLTAA.Certificate certificate;
    private final int directoryPosition;

    /** Package-private. External code must use {@link #register}. */
    Voter(String identity, EOLTAA.UserKeyPair eoltaaKey,
          EOLTAA.Certificate certificate, int directoryPosition) {
        this.identity = identity;
        this.eoltaaKey = eoltaaKey;
        this.certificate = certificate;
        this.directoryPosition = directoryPosition;
    }

    /**
     * Submit a registration request to the CA and, on approval, return a Voter
     * positioned at the allocated ring index and carrying the CA-issued
     * EOLTAA certificate. Throws {@link RegistrationRejectedException} if the
     * CA rejects the request (ineligible or duplicate identity).
     *
     * <p>This is the only supported way to construct a Voter from outside the
     * {@code mmu.fyp.evoting.entities.voter} package.
     */
    public static Voter register(CertificateAuthority ca, String identity,
                                 EOLTAA.UserKeyPair credentials) {
        RegistrationResponse response = ca.processRegistrationRequest(
                new RegistrationRequest(identity, credentials));
        return switch (response) {
            case RegistrationResponse.Approved a ->
                    new Voter(identity, credentials, a.certificate(), a.directoryPosition());
            case RegistrationResponse.Rejected r ->
                    throw new RegistrationRejectedException(identity, r.reason());
        };
    }

    public String identity() { return identity; }

    /** The voter's EOLTAA user public key {@code upk_i = x_i · G}. */
    public EOLTAA.UserPublicKey upk() { return eoltaaKey.upk(); }

    /** The voter's EOLTAA user secret key {@code usk_i = x_i}. Package-private. */
    EOLTAA.UserSecretKey usk() { return eoltaaKey.usk(); }

    int directoryPosition() { return directoryPosition; }

    /** The CA-issued EOLTAA certificate this voter carries (Register step 10). */
    public EOLTAA.Certificate certificate() { return certificate; }

    public VoterSession beginVote(VotingContext ctx, int candidate) {
        return new VoterSession(this, ctx, candidate);
    }

    /**
     * "Check Result" use case from FYP 2 Chapter 4 §4.4 — queries the bulletin
     * board for the published tally. Returns empty until the EC has run the
     * tally and posted the result.
     */
    public Optional<TallyResult> checkResult(BulletinBoard bb) {
        return bb.result();
    }

    /** Raised when the CA rejects a registration request. */
    public static final class RegistrationRejectedException extends RuntimeException {
        private final String reason;

        public RegistrationRejectedException(String identity, String reason) {
            super("registration rejected for " + identity + ": " + reason);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }
}
