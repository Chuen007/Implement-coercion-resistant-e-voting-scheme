package mmu.fyp.evoting.bench;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.crypto.sigma.SigmaDLEq;
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
import mmu.fyp.evoting.persistence.Serialization;
import mmu.fyp.evoting.protocol.EncryptionRelation;
import mmu.fyp.evoting.protocol.MessageEncoding;
import mmu.fyp.evoting.protocol.Messages;
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
            double tallyPerBallotMs,
            // Communication / storage sizes in bytes (Dr Kho review, June 2026)
            int ballotBytes,        // serialized Ballot = Ci + EOLTAA token (O(n))
            int ciphertextBytes,    // Cramer-Shoup Ci alone (constant)
            int authTokenBytes,     // EOLTAA token alone (O(n) — Σ-OR over directory)
            int sigmaProofBytes,    // (a, e, z) transcript (constant)
            int musigSigBytes,      // MuSig2 (R, s) (constant regardless of committee size)
            int bbEntryBytes,       // ballot BB entry incl. hash-chain overhead
            int transcriptBytes,    // voter-held Trc = (v, C, a, e, z, cmt, h_v, r̂)
            int resultBytes         // TallyResult incl. decryption records + π_result (O(n))
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
        // The witness MUST be the same randomness used to produce the ciphertext,
        // otherwise the benchmarked instance is not a valid proof: verify() would
        // fail its first DLEq leg and early-exit, underestimating verification
        // time by ~4x (only 1 of 4 legs would be computed).
        BigInteger r = Group.randomScalar();
        CramerShoup.Ciphertext ct = CramerShoup.encrypt(m, r, ec.encryptionPk());
        SigmaDLEq.Statement stmt = EncryptionRelation.build(m, ct, ec.encryptionPk());
        BigInteger witness = r;
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
        if (!SigmaDLEq.verify(stmt, preparedSession.firstMessage(), challenge, z)) {
            throw new IllegalStateException(
                    "benchmark sigma instance is invalid — witness does not match ciphertext randomness");
        }
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
        // The LAST voter votes via a manually-driven session so we can measure
        // the per-message communication sizes from a genuine protocol run.
        for (int i = voteSamples; i < n - 1; i++) {
            VoteProtocol.run(voters.get(i), ctx, ec, bb, 1 + (i % 3));
        }
        VoterSession probe = voters.get(n - 1).beginVote(ctx, 1 + ((n - 1) % 3));
        ECVoteSession ecsProbe = ec.beginVoteSession();
        Messages.Round3 p3 = ecsProbe.processStep2(probe.step2());
        Messages.Round4 p4 = probe.processStep3(p3);
        Ballot probeBallot = probe.finalize(ecsProbe.processStep4(p4), bb);

        // ----- Communication / storage sizes (Dr Kho review, June 2026) -----
        int ciphertextBytes = MessageEncoding.serializeCiphertext(probeBallot.ct()).length;
        int authTokenBytes  = Serialization.encodeAuthToken(probeBallot.voterAuth()).length;
        int ballotBytes     = Serialization.encodeBBEntry(probeBallot).length;
        // BB entry = serialized content + index(4) + prevHash(32) + thisHash(32)
        int bbEntryBytes    = ballotBytes + 4 + 32 + 32;
        int musigSigBytes   = Serialization.encodePoint(p3.ecSig().R()).length
                            + Serialization.encodeScalar(p3.ecSig().s()).length;
        int sigmaProofBytes = 0;
        for (ECPoint a : p3.sigmaA().a()) {
            sigmaProofBytes += Serialization.encodePoint(a).length;
        }
        sigmaProofBytes += Serialization.encodeScalar(probe.challenge()).length
                         + Serialization.encodeScalar(probe.responseZ()).length;
        // Voter-held transcript Trc = (v, C, a, e, z, cmt, h_v, r̂) — Kho 2025 §6.1.
        // h_v is included because our verifier needs the voter's Pedersen base.
        int transcriptBytes = 4 + ciphertextBytes + sigmaProofBytes
                + Serialization.encodePoint(probe.commitment()).length
                + Serialization.encodePoint(probe.pedersen().h()).length
                + Serialization.encodeScalar(probe.randomness()).length;

        // ----- Tally -----
        long t0 = System.nanoTime();
        TallyResult result = Tally.run(ec, ca, bb);
        long tallyNs = System.nanoTime() - t0;
        double tallyMs = tallyNs / 1e6;
        double tallyPerBallotMs = tallyMs / n;
        int resultBytes = Serialization.encodeBBEntry(result).length;

        return new Row(n, encryptMs, sigmaGenMs, sigmaVerMs, fullVoteMs, tallyMs, tallyPerBallotMs,
                ballotBytes, ciphertextBytes, authTokenBytes, sigmaProofBytes,
                musigSigBytes, bbEntryBytes, transcriptBytes, resultBytes);
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
        System.out.printf("  ballot size:       %6d B   (Ci + EOLTAA token, O(n) in directory)%n", r.ballotBytes());
        System.out.printf("  ciphertext size:   %6d B   (Cramer-Shoup, constant)%n", r.ciphertextBytes());
        System.out.printf("  auth token size:   %6d B   (EOLTAA Σ-OR proof, O(n))%n", r.authTokenBytes());
        System.out.printf("  sigma proof size:  %6d B   ((a, e, z), constant)%n", r.sigmaProofBytes());
        System.out.printf("  MuSig2 sig size:   %6d B   ((R, s), constant for any committee size)%n", r.musigSigBytes());
        System.out.printf("  BB entry size:     %6d B   (ballot + hash-chain overhead)%n", r.bbEntryBytes());
        System.out.printf("  transcript size:   %6d B   (voter-held Trc)%n", r.transcriptBytes());
        System.out.printf("  result size:       %6d B   (counts + decryptions + π_result, O(n))%n", r.resultBytes());
    }

    private static void writeCsv(List<Row> rows, Path file) {
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(file))) {
            pw.println("n,encrypt_ms,sigma_gen_ms,sigma_ver_ms,full_vote_ms,tally_total_ms,tally_per_ballot_ms,"
                     + "ballot_bytes,ciphertext_bytes,auth_token_bytes,sigma_proof_bytes,"
                     + "musig_sig_bytes,bb_entry_bytes,transcript_bytes,result_bytes");
            for (Row r : rows) {
                pw.printf("%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%d,%d,%d,%d,%d,%d%n",
                        r.n(), r.encryptMs(), r.sigmaGenMs(), r.sigmaVerMs(),
                        r.fullVoteMs(), r.tallyTotalMs(), r.tallyPerBallotMs(),
                        r.ballotBytes(), r.ciphertextBytes(), r.authTokenBytes(),
                        r.sigmaProofBytes(), r.musigSigBytes(), r.bbEntryBytes(),
                        r.transcriptBytes(), r.resultBytes());
            }
            System.out.println("CSV written to " + file.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("failed to write CSV: " + e.getMessage());
        }
    }

    private static void printSummary(List<Row> rows) {
        System.out.println();
        System.out.println("=== Timing summary ===");
        System.out.printf("%-8s %12s %12s %12s %14s %14s %14s%n",
                "n", "encrypt", "sigma-gen", "sigma-ver", "full-vote", "tally-total", "tally/ballot");
        for (Row r : rows) {
            System.out.printf("%-8d %10.3fms %10.3fms %10.3fms %12.3fms %12.3fms %12.3fms%n",
                    r.n(), r.encryptMs(), r.sigmaGenMs(), r.sigmaVerMs(),
                    r.fullVoteMs(), r.tallyTotalMs(), r.tallyPerBallotMs());
        }
        System.out.println();
        System.out.println("=== Communication / storage summary (bytes) ===");
        System.out.printf("%-8s %10s %12s %12s %12s %12s %10s %12s %10s%n",
                "n", "ballot", "ciphertext", "auth-token", "sigma-proof", "musig-sig",
                "bb-entry", "transcript", "result");
        for (Row r : rows) {
            System.out.printf("%-8d %9dB %11dB %11dB %11dB %11dB %9dB %11dB %9dB%n",
                    r.n(), r.ballotBytes(), r.ciphertextBytes(), r.authTokenBytes(),
                    r.sigmaProofBytes(), r.musigSigBytes(), r.bbEntryBytes(),
                    r.transcriptBytes(), r.resultBytes());
        }
        System.out.println();
        System.out.println("Note: full-vote and tally times, the EOLTAA auth token, the ballot, and the");
        System.out.println("result all scale with the EOLTAA directory size (= electorate) because the");
        System.out.println("Σ-OR proof carries one (challenge, response) pair per directory entry and the");
        System.out.println("result carries one decryption record per counted ballot. Encrypt, sigma, and");
        System.out.println("MuSig2 sizes are directory-size-independent.");
    }

    // Java's java.util.Arrays is referenced by name to avoid a top-of-file import that some
    // readers find noisy in benchmark code.
    private static final class Arrays {
        static String toString(int[] arr) { return java.util.Arrays.toString(arr); }
    }
}
