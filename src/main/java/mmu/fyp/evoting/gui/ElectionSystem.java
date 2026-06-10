package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VoterSession;
import mmu.fyp.evoting.entities.voter.VotingContext;
import mmu.fyp.evoting.persistence.H2PersistenceStore;
import mmu.fyp.evoting.protocol.Messages;
import mmu.fyp.evoting.protocol.Tally;
import org.bouncycastle.math.ec.ECPoint;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Shared in-process model for the three-window GUI demo. One ElectionSystem is created
 * by the {@link Launcher} and passed to the Voter, CA, and EC windows.
 *
 * <p>Lifecycle (matches the FYP 2 Chapter 4 §4.7 data-flow diagram):
 * <ol>
 *   <li>Constructor: CA (with pre-loaded {@link CitizenRegistry}), EC, BB exist.
 *       VidNotice posted. No voters yet. Voting closed.</li>
 *   <li>Voters submit registration requests carrying (name, IC) — queued.</li>
 *   <li>CA approves: verifies (name, IC) against its citizen registry; if matched,
 *       allocates a directory position and stores the voter in D1; otherwise auto-rejects.</li>
 *   <li>EC closes registration with {@link #openVoting()} — this freezes the voter
 *       directory (the EOLTAA anonymity set) used to authenticate ballots.</li>
 *   <li>Approved voters cast ballots (D2). The ballot is anonymous: it contains an EOLTAA
 *       authentication token and a Cramer-Shoup ciphertext, but no name or IC. Only the CA,
 *       via the linking tag at tally time, can re-identify a double-voter.</li>
 *   <li>EC runs tally; result posted to D3.</li>
 * </ol>
 *
 * <p>Identity convention: the CA stores each registered voter under their (normalised)
 * IC number. Names are kept here in a parallel map for display only — they never enter
 * the EOLTAA directory, the bulletin board, or the EC's view.
 *
 * <p>Persistence: when constructed with an {@link H2PersistenceStore}, every mutation
 * (submit, approve, reject, openVoting, castVote, runTally) writes through to the DB,
 * and the next launcher startup restores the exact same state — addressing the
 * "feasibility for real-world deployment" objective. Constructed without a store, the
 * system behaves exactly as before (in-memory only), preserving backward compatibility
 * with the in-memory test scenarios and the CLI benchmark.
 */
public final class ElectionSystem {

    public final CertificateAuthority ca;
    public final ElectionCommittee ec;
    public final BulletinBoard bb;
    public final VidNotice vidNotice;
    public final CitizenRegistry citizenRegistry;

    /** Nullable: when null, state is in-memory only (used by tests / scenarios / bench). */
    private final H2PersistenceStore store;

    private final List<PendingRegistration> pending = new ArrayList<>();
    private final Map<String, RegistrationOutcome> outcomes = new LinkedHashMap<>();
    private final Map<String, Voter> votersByIdentity = new LinkedHashMap<>();
    private final Map<String, VoterSession> sessionsByIdentity = new LinkedHashMap<>();
    /** ic → declared name, kept separately so the CA log can show the human name. */
    private final Map<String, String> nameByIc = new LinkedHashMap<>();

    private boolean votingOpen;

    // ---------- constructors ----------

    public ElectionSystem(int candidateCount) {
        this(candidateCount, CitizenRegistry.defaultSeeded(), null);
    }

    public ElectionSystem(int candidateCount, CitizenRegistry citizenRegistry) {
        this(candidateCount, citizenRegistry, null);
    }

    /**
     * Persistence-backed constructor. If the store already contains an election,
     * the entire state (EC keys, vid, voting flag, voters, pending, outcomes, BB)
     * is restored from disk. Otherwise a fresh election is generated and an initial
     * snapshot is written.
     */
    public ElectionSystem(int candidateCount, H2PersistenceStore store) {
        this(candidateCount, null, store);
    }

    private ElectionSystem(int candidateCount, CitizenRegistry suppliedRegistry, H2PersistenceStore store) {
        this.store = store;

        // ----- 1. Resolve citizen registry -----
        CitizenRegistry resolvedRegistry;
        if (store != null) {
            try {
                List<CitizenRecord> defaultSeed = (suppliedRegistry != null ? suppliedRegistry
                        : CitizenRegistry.defaultSeeded()).all();
                List<H2PersistenceStore.CitizenEntry> seedRows = defaultSeed.stream()
                        .map(c -> new H2PersistenceStore.CitizenEntry(c.name(), c.icNumber()))
                        .toList();
                List<H2PersistenceStore.CitizenEntry> rows = store.loadOrSeedCitizenRegistry(seedRows);
                List<CitizenRecord> records = rows.stream()
                        .map(r -> new CitizenRecord(r.name(), r.icNumber()))
                        .toList();
                resolvedRegistry = new CitizenRegistry(records);
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to load citizen registry from store", e);
            }
        } else {
            resolvedRegistry = suppliedRegistry != null ? suppliedRegistry : CitizenRegistry.defaultSeeded();
        }
        this.citizenRegistry = resolvedRegistry;

        // ----- 2. Initialise election state (fresh or restored) -----
        if (store == null) {
            // In-memory only path (backward compatible with tests / scenarios)
            this.ca = new CertificateAuthority();
            this.ec = new ElectionCommittee(candidateCount);
            ec.setCertificate(ca.registerEc(ec.upk()));
            // directory is locked in openVoting() via ec.setDirectory(ca.directory()).
            this.bb = new BulletinBoard();
            ec.publishParams(bb);                                       // Register step 1
            this.vidNotice = ec.publishVid(bb, ca.masterPublicKey());   // Vote round 1
            this.votingOpen = false;
            return;
        }

        // ----- Persistence path: ALWAYS wipe + fresh-init on every launcher startup -----
        //
        // Each launcher run is treated as a brand-new voting process: any election state
        // left from previous runs (registered voters, pending requests, registration
        // outcomes, ballots, tally results, EC keys, vid, voting-open flag) is cleared
        // and regenerated. ONLY the citizen_registry table survives — it is reference
        // data (the eligible-voter list), not election state.
        //
        // Within a single session, every mutation is still persisted to disk so the
        // database can be inspected with DBeaver / H2 Console while the system runs.
        // For inter-session persistence (e.g. real production deployment that survives
        // server restarts), simply skip the store.reset() call below — all the
        // restoration plumbing is still in place under H2PersistenceStore.loadElection /
        // loadRegisteredVoters / etc.
        try {
            store.reset();   // wipes everything except citizen_registry

            this.ca = new CertificateAuthority();
            this.ec = new ElectionCommittee(candidateCount);
            ec.setCertificate(ca.registerEc(ec.upk()));
            // directory is locked in openVoting() via ec.setDirectory(ca.directory()).
            this.bb = new BulletinBoard();
            ec.publishParams(bb);                                       // Register step 1
            this.vidNotice = ec.publishVid(bb, ca.masterPublicKey());   // Vote round 1
            this.votingOpen = false;

            store.saveElection(candidateCount, ec.currentVid(), false,
                    ec.ecKey(), ec.certificate(), ec.musigKeyPairs(), ec.encryptionKey());
            // Persist the two genesis entries (ParamNotice at idx 0, VidNotice at idx 1).
            for (BulletinBoard.Entry e : bb.entries()) {
                store.appendBBEntry(e.index(), e.content(), e.prevHash(), e.hash());
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to initialise ElectionSystem from store", e);
        }
    }

    // ---------- persistence helpers ----------

    @FunctionalInterface
    private interface SqlAction { void run() throws SQLException; }

    private void persist(SqlAction action) {
        if (store == null) return;
        try {
            action.run();
        } catch (SQLException e) {
            throw new IllegalStateException("Persistence write failed", e);
        }
    }

    private void persistLastBBEntry() {
        if (store == null) return;
        List<BulletinBoard.Entry> entries = bb.entries();
        BulletinBoard.Entry last = entries.get(entries.size() - 1);
        persist(() -> store.appendBBEntry(last.index(), last.content(), last.prevHash(), last.hash()));
    }

    // ---------- registration ----------

    /**
     * Register step 4 (Kho et al. 2025 §6.1) — voter has already run
     * {@code Φ.UKeyGen} client-side and now submits {@code (name, IC, upk)}
     * along with the matching {@code usk} for CA-assisted tracing escrow.
     * The keypair MUST be generated by the voter (in VoterGui) before
     * calling this — the system never produces voter keys on the voter's
     * behalf, matching the paper's separation of duties.
     */
    public synchronized void submitRegistration(String name, String icNumber,
                                                EOLTAA.UserKeyPair kp) {
        String ic = CitizenRecord.normaliseIc(icNumber);
        if (votingOpen) {
            RegistrationOutcome o = new RegistrationOutcome(name, ic, -1,
                    "voting open — registration closed", null);
            outcomes.put(ic, o);
            persist(() -> store.upsertRegistrationOutcome(ic, name, -1, o.status(), false));
            return;
        }
        if (outcomes.containsKey(ic)) return;
        if (pending.stream().anyMatch(p -> p.icNumber().equals(ic))) return;

        long submittedAt = System.currentTimeMillis();
        pending.add(new PendingRegistration(name, ic, kp, submittedAt));
        persist(() -> store.insertPendingRegistration(ic, name, kp, submittedAt));
    }

    public synchronized List<PendingRegistration> pendingRegistrations() {
        return List.copyOf(pending);
    }

    public synchronized RegistrationOutcome approve(int pendingIndex) {
        PendingRegistration req = pending.remove(pendingIndex);
        persist(() -> store.deletePendingRegistration(req.icNumber()));

        Optional<CitizenRecord> registryHit = citizenRegistry.verify(req.name(), req.icNumber());
        if (registryHit.isEmpty()) {
            RegistrationOutcome outcome = new RegistrationOutcome(
                    req.name(), req.icNumber(), -1,
                    "rejected: (name, IC) not in citizen registry", null);
            outcomes.put(req.icNumber(), outcome);
            persist(() -> store.upsertRegistrationOutcome(req.icNumber(), req.name(),
                    -1, outcome.status(), false));
            return outcome;
        }
        try {
            Voter voter = Voter.register(ca, req.icNumber(), req.credentials());
            int pos = ca.positionOf(req.icNumber());
            votersByIdentity.put(req.icNumber(), voter);
            nameByIc.put(req.icNumber(), req.name());
            RegistrationOutcome outcome = new RegistrationOutcome(
                    req.name(), req.icNumber(), pos, "approved", voter);
            outcomes.put(req.icNumber(), outcome);
            persist(() -> {
                store.insertRegisteredVoter(req.icNumber(), req.name(), pos, req.credentials());
                store.upsertRegistrationOutcome(req.icNumber(), req.name(), pos, "approved", true);
            });
            return outcome;
        } catch (Voter.RegistrationRejectedException e) {
            RegistrationOutcome outcome = new RegistrationOutcome(
                    req.name(), req.icNumber(), -1, e.reason(), null);
            outcomes.put(req.icNumber(), outcome);
            persist(() -> store.upsertRegistrationOutcome(req.icNumber(), req.name(),
                    -1, e.reason(), false));
            return outcome;
        }
    }

    public synchronized RegistrationOutcome reject(int pendingIndex, String reason) {
        PendingRegistration req = pending.remove(pendingIndex);
        persist(() -> store.deletePendingRegistration(req.icNumber()));
        RegistrationOutcome outcome = new RegistrationOutcome(
                req.name(), req.icNumber(), -1, "CA rejected: " + reason, null);
        outcomes.put(req.icNumber(), outcome);
        persist(() -> store.upsertRegistrationOutcome(req.icNumber(), req.name(),
                -1, outcome.status(), false));
        return outcome;
    }

    public synchronized Optional<RegistrationOutcome> findOutcome(String icNumber) {
        return Optional.ofNullable(outcomes.get(CitizenRecord.normaliseIc(icNumber)));
    }

    public synchronized boolean isPending(String icNumber) {
        String ic = CitizenRecord.normaliseIc(icNumber);
        return pending.stream().anyMatch(p -> p.icNumber().equals(ic));
    }

    public synchronized List<RegistrationOutcome> registrationHistory() {
        return List.copyOf(outcomes.values());
    }

    public synchronized String nameOf(String icNumber) {
        return nameByIc.get(CitizenRecord.normaliseIc(icNumber));
    }

    // ---------- voting ----------

    public synchronized boolean votingOpen() {
        return votingOpen;
    }

    public synchronized void openVoting() {
        if (votingOpen) return;
        ec.setDirectory(ca.directory());
        votingOpen = true;
        persist(() -> store.setVotingOpen(true));
    }

    public synchronized VotingContext votingContext() {
        return new VotingContext(vidNotice, ca.directory(), ca.masterPublicKey(),
                ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());
    }

    public synchronized Ballot castVote(String icNumber, int candidate) {
        if (!votingOpen) throw new IllegalStateException("voting is not open yet");
        String ic = CitizenRecord.normaliseIc(icNumber);
        Voter voter = votersByIdentity.get(ic);
        if (voter == null) throw new IllegalStateException("voter not registered: " + ic);

        VotingContext ctx = votingContext();
        VoterSession session = voter.beginVote(ctx, candidate);
        ECVoteSession ecs = ec.beginVoteSession();

        Messages.Round2 r2 = session.step2();
        Messages.Round3 r3 = ecs.processStep2(r2);
        Messages.Round4 r4 = session.processStep3(r3);
        Messages.Round5 r5 = ecs.processStep4(r4);
        Ballot ballot = session.finalize(r5, bb);
        sessionsByIdentity.put(ic, session);
        persistLastBBEntry();
        return ballot;
    }

    public synchronized Optional<VoterSession> sessionOf(String icNumber) {
        return Optional.ofNullable(sessionsByIdentity.get(CitizenRecord.normaliseIc(icNumber)));
    }

    public synchronized Optional<Integer> revealEncryptedVote(String icNumber) {
        VoterSession s = sessionsByIdentity.get(CitizenRecord.normaliseIc(icNumber));
        if (s == null) return Optional.empty();
        Optional<ECPoint> m = CramerShoup.decrypt(s.round3().ct(), ec.encryptionSk());
        return m.flatMap(p -> Tally.decodeVote(p, ec.candidateCount()));
    }

    public synchronized boolean hasVoted(String icNumber) {
        return sessionsByIdentity.containsKey(CitizenRecord.normaliseIc(icNumber));
    }

    // ---------- tally ----------

    public synchronized TallyResult runTally() {
        TallyResult result = ec.runTally(ca, bb);
        persistLastBBEntry();
        return result;
    }

    // ---------- accessors ----------

    public int candidateCount() {
        return ec.candidateCount();
    }

    public Voter voter(String icNumber) {
        return votersByIdentity.get(CitizenRecord.normaliseIc(icNumber));
    }

    /** True iff this ElectionSystem is backed by a persistent store. */
    public boolean persistent() {
        return store != null;
    }
}
