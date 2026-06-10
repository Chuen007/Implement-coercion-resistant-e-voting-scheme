package mmu.fyp.evoting.entities.ca;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class EligibilityCheckerTest {

    @Test
    void defaultAcceptsAllIdentities() {
        EligibilityChecker checker = EligibilityChecker.ACCEPT_ALL;
        assertTrue(checker.isEligible("alice"));
        assertTrue(checker.isEligible(""));
        assertTrue(checker.isEligible("anyone-at-all"));
    }

    @Test
    void allowListAcceptsOnlyListedIdentities() {
        EligibilityChecker checker = EligibilityChecker.fromAllowList(Set.of("alice", "bob"));
        assertTrue(checker.isEligible("alice"));
        assertTrue(checker.isEligible("bob"));
        assertFalse(checker.isEligible("eve"));
        assertFalse(checker.isEligible(""));
    }

    @Test
    void customCheckerCanImplementArbitraryPolicy() {
        EligibilityChecker rejectShort = identity -> identity != null && identity.length() >= 4;
        assertTrue(rejectShort.isEligible("alice"));
        assertFalse(rejectShort.isEligible("xx"));
    }

    @Test
    void caWithDefaultCheckerAcceptsAnyIdentity() {
        CertificateAuthority ca = new CertificateAuthority();
        ca.registerVoter("voter-Alice", EOLTAA.uKeyGen());
        ca.registerVoter("voter-Bob", EOLTAA.uKeyGen());
        assertEquals(2, ca.registeredVoterCount());
    }

    @Test
    void caWithAllowListRejectsUnlistedIdentities() {
        CertificateAuthority ca = new CertificateAuthority(
                EligibilityChecker.fromAllowList(Set.of("voter-Alice", "voter-Bob")));
        ca.registerVoter("voter-Alice", EOLTAA.uKeyGen());
        assertThrows(CertificateAuthority.IneligibleVoterException.class,
                () -> ca.registerVoter("voter-Eve", EOLTAA.uKeyGen()));
        assertEquals(1, ca.registeredVoterCount());
    }

    @Test
    void duplicateRegistrationStillRejected() {
        CertificateAuthority ca = new CertificateAuthority();
        ca.registerVoter("voter-Alice", EOLTAA.uKeyGen());
        assertThrows(IllegalArgumentException.class,
                () -> ca.registerVoter("voter-Alice", EOLTAA.uKeyGen()));
    }

    @Test
    void ineligibleExceptionCarriesIdentity() {
        CertificateAuthority ca = new CertificateAuthority(identity -> false);
        var ex = assertThrows(CertificateAuthority.IneligibleVoterException.class,
                () -> ca.registerVoter("voter-Eve", EOLTAA.uKeyGen()));
        assertTrue(ex.getMessage().contains("voter-Eve"));
    }
}
