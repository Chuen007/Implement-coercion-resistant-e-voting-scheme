package mmu.fyp.evoting.entities.ca;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;

/**
 * Voter registration request submitted to the CA. Matches the "Register identity"
 * use case from FYP 2 Chapter 4 §4.4 and the "Register" arrow from Voter to
 * process 1.0 in the data-flow diagram §4.7.
 *
 * <p>The {@code credentials} are the voter's EOLTAA user keypair
 * {@code (upk, usk) ← Φ.UKeyGen(1^λ)} from Kho et al. (2025) Register step 7.
 * The CA verifies eligibility against the citizen registry and, on approval,
 * issues an {@link mmu.fyp.evoting.crypto.eoltaa.EOLTAA.Certificate} over
 * {@code upk} via {@code Φ.CertGen(MSK, upk)} (Register step 10).
 */
public record RegistrationRequest(String identity, EOLTAA.UserKeyPair credentials) {}
