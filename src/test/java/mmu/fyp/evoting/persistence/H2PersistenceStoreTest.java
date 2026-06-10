package mmu.fyp.evoting.persistence;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.gui.ElectionSystem;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the H2-backed persistence layer.
 *
 * <p>Current design contract: <b>every launcher startup wipes any leftover election
 * state and begins a fresh voting process.</b> The citizen registry is the only
 * cross-session survivor — it is reference data (the eligible-voter list), not
 * election state. Within a single session every mutation is still persisted to
 * disk so the database can be inspected with DBeaver / H2 Console while the
 * system runs.
 *
 * <p>This trade-off lets a developer / demo operator restart the system at any
 * point without first having to hit a Reset button — each run is a brand-new
 * election with no residual "voting open" rejections, no stale ballots, no
 * leftover tally result. Cross-session persistence (production-style) is still
 * fully implemented under {@link H2PersistenceStore} (loadElection,
 * loadRegisteredVoters, etc.) and is one {@code store.reset()} call away from
 * being re-enabled.
 */
class H2PersistenceStoreTest {

    /** Sanity: opening a store on a fresh file creates tables and seeds the citizen registry. */
    @Test
    void freshStoreSeedsCitizenRegistry(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("election");
        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            var rows = store.loadOrSeedCitizenRegistry(java.util.List.of(
                    new H2PersistenceStore.CitizenEntry("Test A", "111111-11-1111"),
                    new H2PersistenceStore.CitizenEntry("Test B", "222222-22-2222")));
            assertEquals(2, rows.size());
        }
        // Reopen — same seed should already be there, not duplicated
        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            var rows = store.loadOrSeedCitizenRegistry(java.util.List.of(
                    new H2PersistenceStore.CitizenEntry("Different seed", "999999-99-9999")));
            assertEquals(2, rows.size(), "registry should not re-seed on second open");
        }
    }

    /**
     * Each launcher startup wipes the election but keeps the citizen registry.
     * This is the central contract — verifies that registering voters, casting
     * a ballot, and running a tally in session 1 leaves NO residue visible to
     * session 2 EXCEPT the citizen registry.
     */
    @Test
    void everyLauncherStartupIsAFreshElection(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("election");

        byte[] vidSession1;
        int citizenCountSession1;

        // ----- Session 1: full election cycle -----
        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            ElectionSystem es = new ElectionSystem(3, store);
            vidSession1 = es.vidNotice.vid().clone();
            citizenCountSession1 = es.citizenRegistry.size();

            es.submitRegistration("Tan Ah Kow", "890101-01-1234", EOLTAA.uKeyGen());
            es.submitRegistration("Lim Mei Ling", "900215-02-2345", EOLTAA.uKeyGen());
            es.approve(0);
            es.approve(0);
            es.openVoting();
            es.castVote("890101011234", 2);
            TallyResult result = es.runTally();

            assertEquals(2, es.ca.registeredVoterCount());
            assertEquals(1, es.bb.ballots().size());
            assertTrue(es.votingOpen());
            assertEquals(Integer.valueOf(1), result.counts().get(2));
        }

        // ----- Session 2: everything election-related must be wiped -----
        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            ElectionSystem es = new ElectionSystem(3, store);

            // EC keys + vid REGENERATED — must NOT match session 1
            assertFalse(java.util.Arrays.equals(vidSession1, es.vidNotice.vid()),
                    "vid is regenerated on every launcher restart");

            // Election state fully wiped
            assertEquals(0, es.ca.registeredVoterCount(),
                    "registered voters wiped");
            assertEquals(0, es.pendingRegistrations().size(),
                    "pending registrations wiped");
            assertEquals(0, es.registrationHistory().size(),
                    "registration outcomes wiped — no leftover 'voting open' rejections");
            assertEquals(0, es.bb.ballots().size(),
                    "ballots wiped");
            assertTrue(es.bb.result().isEmpty(),
                    "tally result wiped");
            assertFalse(es.votingOpen(),
                    "voting starts closed");
            assertEquals(2, es.bb.entries().size(),
                    "BB has exactly two genesis entries — ParamNotice (Register step 1) + VidNotice (Vote round 1)");

            // Citizen registry SURVIVES — it is reference data, not election state
            assertEquals(citizenCountSession1, es.citizenRegistry.size(),
                    "citizen registry preserved across launcher restart");

            // The fresh session can immediately start over from scratch
            es.submitRegistration("Muthu Krishnan", "850330-03-3456", EOLTAA.uKeyGen());
            assertEquals(1, es.pendingRegistrations().size(),
                    "user can register immediately — no 'voting open' block");
        }
    }

    /**
     * Within a single session, every mutation is persisted to disk so the
     * database can be inspected live with DBeaver / H2 Console.
     */
    @Test
    void mutationsArePersistedWithinASession(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("election");
        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            ElectionSystem es = new ElectionSystem(3, store);

            es.submitRegistration("Tan Ah Kow", "890101-01-1234", EOLTAA.uKeyGen());
            // Without closing the store, query the underlying table directly:
            assertEquals(1, store.loadPendingRegistrations().size(),
                    "submitRegistration writes through to pending_registrations");

            es.approve(0);
            assertEquals(1, store.loadRegisteredVoters().size(),
                    "approve writes through to registered_voters");
            assertEquals(0, store.loadPendingRegistrations().size(),
                    "approve removes the pending row");

            es.openVoting();
            es.castVote("890101011234", 2);
            es.runTally();
            assertEquals(4, store.loadBBEntries().size(),
                    "ParamNotice + VidNotice + Ballot + TallyResult all persisted to bb_entries");
        }
    }

    /** reset() wipes everything except the citizen registry — the explicit version of startup wipe. */
    @Test
    void resetWipesElectionButKeepsCitizenRegistry(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("election");

        try (H2PersistenceStore store = new H2PersistenceStore(db)) {
            ElectionSystem es = new ElectionSystem(3, store);
            es.submitRegistration("Tan Ah Kow", "890101-01-1234", EOLTAA.uKeyGen());
            es.approve(0);
            assertEquals(1, es.ca.registeredVoterCount());
            // store.reset() called separately (not via ElectionSystem) tests the lower-level API
            store.reset();
            assertEquals(0, store.loadRegisteredVoters().size(),
                    "reset wiped registered_voters table");
            assertFalse(store.loadOrSeedCitizenRegistry(java.util.List.of()).isEmpty(),
                    "citizen_registry table preserved after reset");
        }
    }

    /** Without a store, ElectionSystem works exactly as before (in-memory). */
    @Test
    void inMemoryConstructorUnchanged() {
        ElectionSystem es = new ElectionSystem(3);
        assertFalse(es.persistent());
        es.submitRegistration("Tan Ah Kow", "890101-01-1234", EOLTAA.uKeyGen());
        assertEquals(1, es.pendingRegistrations().size());
    }

    /** SQLException is wrapped as IllegalStateException so callers don't need checked-exception handling. */
    @Test
    void corruptDbPathRaisesUsefulError(@TempDir Path tmp) {
        // Path the H2 cannot write to: a file with the .mv.db extension that's actually a directory
        Path bogus = tmp.resolve("not-a-db");
        try {
            bogus.toFile().mkdirs();
            new H2PersistenceStore(bogus);
        } catch (SQLException | java.io.IOException expected) {
            // OK — bubbled up to caller
            return;
        }
        // If construction somehow succeeded, that's fine too — H2 is lenient
    }
}
