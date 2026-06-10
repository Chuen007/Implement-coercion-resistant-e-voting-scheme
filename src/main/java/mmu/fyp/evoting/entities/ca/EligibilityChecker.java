package mmu.fyp.evoting.entities.ca;

/**
 * Eligibility predicate consulted by the CA at registration time. Matches the
 * "verify eligibility" decision node in the registration flowchart of FYP 2
 * Chapter 4. For the prototype the default implementation accepts every
 * identity; a production deployment would replace this with a lookup against
 * an external voter roll service.
 */
@FunctionalInterface
public interface EligibilityChecker {

    /** Returns true iff the supplied identity is eligible to register and vote. */
    boolean isEligible(String identity);

    /** Prototype default — accept every identity. */
    EligibilityChecker ACCEPT_ALL = identity -> true;

    /** Allow only identities present in the supplied {@link java.util.Set}. */
    static EligibilityChecker fromAllowList(java.util.Set<String> allowed) {
        return allowed::contains;
    }
}
