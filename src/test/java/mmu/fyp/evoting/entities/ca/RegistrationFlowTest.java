package mmu.fyp.evoting.entities.ca;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import mmu.fyp.evoting.protocol.VoteProtocol;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the FYP 2 Chapter 4 use-case sequencing: a voter must register
 * before voting, and may check the result after the tally is posted.
 *
 * <p>The CA identity layer uses the EOLTAA scheme (Kho et al. 2025 §6.1
 * Register phase): the CA's master keypair is {@code Φ.CSetup → (MPK, MSK)},
 * voter credentials are {@link EOLTAA.UserKeyPair}, and the certificate
 * returned by the CA is {@link EOLTAA.Certificate}.
 */
class RegistrationFlowTest {

    @Test
    void requestApprovedForEligibleNewVoter() {
        CertificateAuthority ca = new CertificateAuthority();
        var response = ca.processRegistrationRequest(
                new RegistrationRequest("voter-Alice", EOLTAA.uKeyGen()));
        assertInstanceOf(RegistrationResponse.Approved.class, response);
        assertEquals("voter-Alice", response.identity());
        assertEquals(0, ((RegistrationResponse.Approved) response).directoryPosition());
    }

    @Test
    void requestRejectedForIneligibleVoter() {
        CertificateAuthority ca = new CertificateAuthority(
                EligibilityChecker.fromAllowList(Set.of("voter-Alice")));
        var response = ca.processRegistrationRequest(
                new RegistrationRequest("voter-Eve", EOLTAA.uKeyGen()));
        assertInstanceOf(RegistrationResponse.Rejected.class, response);
        assertEquals("ineligible", ((RegistrationResponse.Rejected) response).reason());
    }

    @Test
    void requestRejectedForDuplicateIdentity() {
        CertificateAuthority ca = new CertificateAuthority();
        ca.processRegistrationRequest(
                new RegistrationRequest("voter-Alice", EOLTAA.uKeyGen()));
        var response = ca.processRegistrationRequest(
                new RegistrationRequest("voter-Alice", EOLTAA.uKeyGen()));
        assertInstanceOf(RegistrationResponse.Rejected.class, response);
        assertEquals("duplicate identity", ((RegistrationResponse.Rejected) response).reason());
    }

    @Test
    void registeredIdentitiesExposesD1View() {
        CertificateAuthority ca = new CertificateAuthority();
        ca.processRegistrationRequest(new RegistrationRequest("voter-Alice", EOLTAA.uKeyGen()));
        ca.processRegistrationRequest(new RegistrationRequest("voter-Bob",   EOLTAA.uKeyGen()));
        Set<String> ids = ca.registeredIdentities();
        assertEquals(Set.of("voter-Alice", "voter-Bob"), ids);
    }

    @Test
    void voterRegisterFactoryCreatesUsableVoter() {
        CertificateAuthority ca = new CertificateAuthority();
        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        assertEquals("voter-Alice", alice.identity());
        assertEquals(1, ca.registeredVoterCount());
    }

    @Test
    void voterRegisterFactoryThrowsOnIneligibility() {
        CertificateAuthority ca = new CertificateAuthority(identity -> false);
        var ex = assertThrows(Voter.RegistrationRejectedException.class,
                () -> Voter.register(ca, "voter-Eve", EOLTAA.uKeyGen()));
        assertEquals("ineligible", ex.reason());
    }

    @Test
    void voterRegisterFactoryThrowsOnDuplicate() {
        CertificateAuthority ca = new CertificateAuthority();
        Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        var ex = assertThrows(Voter.RegistrationRejectedException.class,
                () -> Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen()));
        assertEquals("duplicate identity", ex.reason());
    }

    @Test
    void voterCheckResultReturnsEmptyBeforeTally() {
        CertificateAuthority ca = new CertificateAuthority();
        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        BulletinBoard bb = new BulletinBoard();
        assertTrue(alice.checkResult(bb).isEmpty());
    }

    @Test
    void voterCheckResultReturnsResultAfterTally() {
        // Full end-to-end: register, vote, tally, then voter queries the result.
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));
        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        VoteProtocol.run(alice, ctx, ec, bb, 2);
        ec.runTally(ca, bb);

        var result = alice.checkResult(bb);
        assertTrue(result.isPresent());
        assertEquals(Integer.valueOf(1), result.get().counts().get(2));
    }

    @Test
    void bulletinBoardBallotsAndResultViewsMatchTheDFD() {
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));
        Voter alice = Voter.register(ca, "voter-Alice", EOLTAA.uKeyGen());
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        assertEquals(0, bb.ballots().size(), "D2 empty before voting");
        assertTrue(bb.result().isEmpty(), "D3 empty before tally");

        VoteProtocol.run(alice, ctx, ec, bb, 1);
        assertEquals(1, bb.ballots().size(), "D2 contains the one cast ballot");
        assertTrue(bb.result().isEmpty(), "D3 still empty before tally");

        ec.runTally(ca, bb);
        assertTrue(bb.result().isPresent(), "D3 populated after tally");
        assertEquals(Integer.valueOf(1), bb.result().get().counts().get(1));
    }

    // ===== Kho et al. (2025) Register phase: Φ.CSetup + Φ.CertGen =====

    @Test
    void caHasMasterKeypair_phiCSetup() {
        // Kho et al. (2025) Register step 4: CA runs Φ.CSetup(1^λ) -> (MPK, MSK).
        CertificateAuthority ca = new CertificateAuthority();
        assertNotNull(ca.masterPublicKey(), "MPK must be available for verifying certificates");
        assertNotNull(ca.masterKeyPair(),   "MSK must be available so CA can issue certificates");
        // Two CAs constructed back-to-back must have independent master keypairs.
        CertificateAuthority other = new CertificateAuthority();
        assertNotEquals(ca.masterPublicKey().V(), other.masterPublicKey().V());
    }

    @Test
    void approvalReturnsCertificate_phiCertGen() {
        // Kho et al. (2025) Register step 10: Cert <- Φ.CertGen(MSK, upk).
        CertificateAuthority ca = new CertificateAuthority();
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        var response = ca.processRegistrationRequest(new RegistrationRequest("voter-Alice", kp));
        assertInstanceOf(RegistrationResponse.Approved.class, response);
        var approved = (RegistrationResponse.Approved) response;
        assertNotNull(approved.certificate(), "Approved response carries the CA-issued certificate");
        // Voter, once constructed via register(), also holds the certificate.
        Voter alice = Voter.register(ca, "voter-Bob", EOLTAA.uKeyGen());
        assertNotNull(alice.certificate());
    }

    @Test
    void issuedCertificateVerifiesAgainstMpk() {
        // Verification: anyone with MPK can check the certificate binds (upk, CA-approved).
        CertificateAuthority ca = new CertificateAuthority();
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        Voter alice = Voter.register(ca, "voter-Alice", kp);
        EOLTAA.MasterPublicKey mpk = ca.masterPublicKey();
        assertTrue(CertificateAuthority.verifyCertificate(kp.upk(), alice.certificate(), mpk),
                "Certificate must verify against the issuing CA's master public key");
    }

    @Test
    void certificateDoesNotVerifyUnderDifferentMpk() {
        // Soundness: a certificate from one CA must NOT verify under another CA's MPK.
        CertificateAuthority caA = new CertificateAuthority();
        CertificateAuthority caB = new CertificateAuthority();
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        Voter aliceFromA = Voter.register(caA, "voter-Alice", kp);
        assertFalse(CertificateAuthority.verifyCertificate(kp.upk(), aliceFromA.certificate(),
                        caB.masterPublicKey()),
                "Certificate from caA must not verify under caB's master public key");
    }

    @Test
    void certificateDoesNotVerifyForTamperedPublicKey() {
        // Unforgeability: substituting a different upk must break the certificate.
        CertificateAuthority ca = new CertificateAuthority();
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        EOLTAA.UserKeyPair other = EOLTAA.uKeyGen();
        Voter alice = Voter.register(ca, "voter-Alice", kp);
        assertFalse(CertificateAuthority.verifyCertificate(other.upk(), alice.certificate(),
                        ca.masterPublicKey()),
                "Certificate must not verify when the public key is swapped for another voter's");
    }
}
