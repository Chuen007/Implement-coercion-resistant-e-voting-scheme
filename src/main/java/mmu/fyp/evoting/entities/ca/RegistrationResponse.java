package mmu.fyp.evoting.entities.ca;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;

/**
 * Outcome of a registration request. The CA returns this after running the
 * "Verify Eligibility" use case from FYP 2 Chapter 4 §4.4. On approval the
 * voter is stored in the ID database (D1), a ring position is allocated, and
 * the CA-issued certificate (EOLTAA {@code Cert ← Φ.CertGen(MSK, upk)}) is
 * returned so the voter can carry proof of registration — corresponding to
 * step 10 of the Kho et al. (2025) Register phase.
 */
public sealed interface RegistrationResponse {

    String identity();

    /**
     * Approved. Voter is now in the ID database, has the supplied ring position,
     * and holds the supplied {@code certificate} (an EOLTAA Schnorr-style
     * certificate over the voter's {@code upk}, verifiable against the CA's
     * EOLTAA master public key via
     * {@link EOLTAA#certVerify(EOLTAA.Certificate, EOLTAA.UserPublicKey, EOLTAA.MasterPublicKey)}).
     */
    record Approved(String identity, int directoryPosition, EOLTAA.Certificate certificate)
            implements RegistrationResponse {}

    /** Rejected with a human-readable reason. */
    record Rejected(String identity, String reason) implements RegistrationResponse {}
}
