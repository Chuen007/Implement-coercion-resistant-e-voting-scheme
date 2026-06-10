package mmu.fyp.evoting.bench;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;
import mmu.fyp.evoting.entities.ca.CertificateAuthority;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VotingContext;
import mmu.fyp.evoting.protocol.EncryptionRelation;
import mmu.fyp.evoting.protocol.Tally;
import mmu.fyp.evoting.protocol.VoteProtocol;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Performance benchmark for the e-voting scheme. Records per-operation latency at
 * several voter scales and writes a CSV + a human-readable summary.
 *
 * <p>Default sizes: 10, 100, 1000 voters. Run with --quick to use 10 and 100 only
 * (handy during development).
 */
public final class Benchmark {

    public record Row(
            int n,
            double encryptMs,
            double sigmaGenMs,
            double sigmaVerMs,
            double fullVoteMs,
            double tallyTotalMs,
            double tallyPerBallotMs
    ) {}

    private Benchmark() {}

    public static void run(String[] args) {
        boolean quick = args.length > 0 && args[0].equalsIgnoreCase("--quick");
        int[] sizes = quick ? new int[]{10, 100} : new int[]{10, 100, 1000};

        System.out.println("=== Performance benchmark ===");
        System.out.printf("Voter scales: %s%n", Arrays.toString(sizes));
        System.out.println("RNG: java.security.SecureRandom (no seed)");
        System.out.println("Single-threaded; one JVM; secp256k1 via Bouncy Castle.");
        System.out.println();

        List<Row> rows = new ArrayList<>();
        for (int n : sizes) {
            System.out.printf("--- n = %d voters ---%n", n);
            long start = System.nanoTime();
            Row row = benchmarkOne(n);
            long elapsed = System.nanoTime() - start;
            rows.add(row);
            printRow(row);
            System.out.printf("  wall-clock for this row: %.2f s%n", elapsed / 1e9);
            System.out.println();
        }

        writeCsv(rows, Path.of("bench-results.csv"));
        printSummary(rows);
    }

    private static Row benchmarkOne(int n) {
        // ----- Setup -----
        CertificateAuthority ca = new CertificateAuthority();
        ElectionCommittee ec = new ElectionCommittee(3);
        ec.setCertificate(ca.registerEc(ec.upk()));

        List<Voter> voters = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
            voters.add(Voter.register(ca, "voter-" + i, kp));
        }
        ec.setDirectory(ca.directory());

        BulletinBoard bb = new BulletinBoard();
        ec.publishParams(bb);
        VidNotice notice = ec.publishVid(bb, ca.masterPublicKey());
        VotingContext ctx = new VotingContext(
                notice, ca.directory(), ca.masterPublicKey(), ec.upk(), ec.aggregateSigningKey(), ec.encryptionPk());

        // ----- Cramer-Shoup encrypt (ring-size independent) -----
        ECPoint m = Group.mulG(BigInteger.ONE);
        warmup(() -> CramerShoup.encrypt(m, ec.encryptionPk()), 10);
        double encryptMs = timeMicroOp(() -> CramerShoup.encrypt(m, ec.encryptionPk()), 100);

        // ----- Sigma-protocol prover (commit + respond) -----
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, ec.encryptionPk());
        SigmaDLEq.Statement stmt = EncryptionRelation.build(m, ct, ec.encryptionPk());
        BigInteger witness = Group.randomScalar();
        warmup(() -> {
            SigmaDLEq.Session s = SigmaDLEq.commit(stmt, witness);
            SigmaDLEq.respond(s, SigmaDLEq.randomChallenge());
        }, 10);
        double sigmaGenMs = timeMicroOp(() -> {
            SigmaDLEq.Session s = SigmaDLEq.commit(stmt, witness);
            SigmaDLEq.respond(s, SigmaDLEq.randomChallenge());
        }, 100);

        // ----- Sigma-protocol verifier -----
        SigmaDLEq.Session preparedSession = SigmaDLEq.commit(stmt, witness);
        BigInteger challenge = SigmaDLEq.randomChallenge();
        BigInteger z = SigmaDLEq.respond(preparedSession, challenge);
        warmup(() -> SigmaDLEq.verify(stmt, preparedSession.firstMessage(), challenge, z), 10);
        double sigmaVerMs = timeMicroOp(
                () -> SigmaDLEq.verify(stmt, preparedSession.firstMessage(), challenge, z), 100);

        // ----- Full single vote (includes EOLTAA.Auth Σ-OR proof, directory-size dependent) -----
        // Use one fresh voter for timing; remaining voters are cast afterwards.
        int voteSamples = Math.min(n <= 100 ? 5 : 2, n);
        long voteTotalNs = 0;
        for (int i = 0; i < voteSamples; i++) {
            long t0 = System.nanoTime();
            VoteProtocol.run(voters.get(i), ctx, ec, bb, 1 + (i % 3));
            voteTotalNs += System.nanoTime() - t0;
        }
        double fullVoteMs = voteTotalNs / 1e6 / voteSamples;

        // ----- Cast remaining ballots so the tally has n entries -----
        for (int i = voteSamples; i < n; i++) {
            VoteProtocol.run(voters.get(i), ctx, ec, bb, 1 + (i % 3));
        }

        // ----- Tally -----
        long t0 = System.nanoTime();
        Tally.run(ec, ca, bb);
        long tallyNs = System.nanoTime() - t0;
        double tallyMs = tallyNs / 1e6;
        double tallyPerBallotMs = tallyMs / n;

        return new Row(n, encryptMs, sigmaGenMs, sigmaVerMs, fullVoteMs, tallyMs, tallyPerBallotMs);
    }

    private static void warmup(Runnable op, int iters) {
        for (int i = 0; i < iters; i++) op.run();
    }

    private static double timeMicroOp(Runnable op, int iters) {
        long t0 = System.nanoTime();
        for (int i = 0; i < iters; i++) op.run();
        long elapsed = System.nanoTime() - t0;
        return elapsed / 1e6 / iters;
    }

    private static void printRow(Row r) {
        System.out.printf("  CS encrypt:        %8.3f ms  (per ciphertext)%n", r.encryptMs());
        System.out.printf("  sigma-proof gen:   %8.3f ms  (commit + respond)%n", r.sigmaGenMs());
        System.out.printf("  sigma-proof verify:%8.3f ms%n", r.sigmaVerMs());
        System.out.printf("  full vote:         %8.3f ms  (4 rounds incl. EOLTAA.Auth + MuSig2 ceremony)%n", r.fullVoteMs());
        System.out.printf("  tally total:       %8.3f ms  (%d ballots)%n", r.tallyTotalMs(), r.n());
        System.out.printf("  tally per ballot:  %8.3f ms%n", r.tallyPerBallotMs());
    }

    private static void writeCsv(List<Row> rows, Path file) {
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(file))) {
            pw.println("n,encrypt_ms,sigma_gen_ms,sigma_ver_ms,full_vote_ms,tally_total_ms,tally_per_ballot_ms");
            for (Row r : rows) {
                pw.printf("%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f%n",
                        r.n(), r.encryptMs(), r.sigmaGenMs(), r.sigmaVerMs(),
                        r.fullVoteMs(), r.tallyTotalMs(), r.tallyPerBallotMs());
            }
            System.out.println("CSV written to " + file.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("failed to write CSV: " + e.getMessage());
        }
    }

    private static void printSummary(List<Row> rows) {
        System.out.println();
        System.out.println("=== Summary table ===");
        System.out.printf("%-8s %12s %12s %12s %14s %14s %14s%n",
                "n", "encrypt", "sigma-gen", "sigma-ver", "full-vote", "tally-total", "tally/ballot");
        for (Row r : rows) {
            System.out.printf("%-8d %10.3fms %10.3fms %10.3fms %12.3fms %12.3fms %12.3fms%n",
                    r.n(), r.encryptMs(), r.sigmaGenMs(), r.sigmaVerMs(),
                    r.fullVoteMs(), r.tallyTotalMs(), r.tallyPerBallotMs());
        }
        System.out.println();
        System.out.println("Note: full-vote and tally scale with the EOLTAA directory size (= electorate)");
        System.out.println("because the Σ-OR proof and Verify both walk every directory entry once;");
        System.out.println("encrypt and sigma operations are directory-size-independent.");
    }

    // Java's java.util.Arrays is referenced by name to avoid a top-of-file import that some
    // readers find noisy in benchmark code.
    private static final class Arrays {
        static String toString(int[] arr) { return java.util.Arrays.toString(arr); }
    }
}
