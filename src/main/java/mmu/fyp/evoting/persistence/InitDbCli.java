package mmu.fyp.evoting.persistence;

import mmu.fyp.evoting.gui.ElectionSystem;

import java.util.HexFormat;

/**
 * Tiny headless CLI that opens (and if necessary creates) the H2 database at the
 * default location, builds an {@link ElectionSystem} against it, prints a one-shot
 * status summary, and exits cleanly.
 *
 * <p>Use this when you want to (a) confirm the DB file exists on disk without
 * opening the GUI, or (b) pre-create the {@code db/election.mv.db} file before
 * inspecting it with DBeaver / the H2 Console.
 *
 * <pre>
 *   java -cp ... mmu.fyp.evoting.persistence.InitDbCli
 * </pre>
 */
public final class InitDbCli {

    private InitDbCli() {}

    public static void main(String[] args) throws Exception {
        try (H2PersistenceStore store = new H2PersistenceStore(H2PersistenceStore.resolveDefaultDbPath())) {
            ElectionSystem es = new ElectionSystem(3, store);
            System.out.println();
            System.out.println("=== H2 election database initialised ===");
            System.out.println("DB file:           " + store.dbPath().toAbsolutePath() + ".mv.db");
            System.out.println("Election state:");
            System.out.println("  candidate count:        " + es.candidateCount());
            System.out.println("  vid (election id):      "
                    + HexFormat.of().formatHex(es.vidNotice.vid()));
            System.out.println("  voting open:            " + es.votingOpen());
            System.out.println("  registered voters (D1): " + es.ca.registeredVoterCount());
            System.out.println("  pending registrations:  " + es.pendingRegistrations().size());
            System.out.println("  BB entries (D2+D3):     " + es.bb.entries().size()
                    + "  (1 = the initial VidNotice)");
            System.out.println("  citizen registry size:  " + es.citizenRegistry.size()
                    + "  (pre-seeded eligible voters)");
            System.out.println();
            System.out.println("Tables created in the H2 file:");
            System.out.println("  election, registered_voters, pending_registrations,");
            System.out.println("  registration_outcomes, bb_entries, citizen_registry");
            System.out.println();
            System.out.println("Inspect with DBeaver / H2 Console using JDBC URL:");
            System.out.println("  jdbc:h2:file:" + store.dbPath().toAbsolutePath());
            System.out.println("  user=sa  password=(empty)");
            System.out.println();
        }
    }
}
