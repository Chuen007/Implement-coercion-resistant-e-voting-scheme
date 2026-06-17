# Coercion-Resistant E-Voting Prototype (FYP 2)

Implementation of the coercion-resistant e-voting scheme of Kho, Heng, Tan & Chin (2025)

**Faculty of Information Science and Technology, Multimedia University**
Final Year Project — January–June 2026.
Student: Ng Zhen Chuen. Supervisor: Prof. Dr. Heng Swee Huay.

## Stack

- Java 21+ (developed against JDK 22)
- Bouncy Castle 1.78.1 (elliptic-curve cryptography)
- H2 2.2.224 (embedded database for the GUI demo persistence)
- JUnit 5.10 (tests — 202 as of June 2026)
- Maven 3.9 (build)

Rationale for the library and language choices is documented in `docs/chapter3_deviations.md` (§3.7.1).

## Cryptographic components

All primitives operate over **secp256k1** via Bouncy Castle (a prime-order group; see `docs/chapter3_deviations.md` for the Ristretto255 discussion):

| Component | Concrete scheme | Source |
|---|---|---|
| Vote encryption | Cramer–Shoup IND-CCA2 PKE | Cramer & Shoup, CRYPTO 1998 |
| Commitment | Pedersen with per-voter trapdoor | Pedersen, CRYPTO 1991 |
| Σ-protocol | Chaum–Pedersen DLEq (n-base) + HVZK simulator | Chaum & Pedersen, CRYPTO 1992; Cramer 1996 |
| Multi-signature | MuSig2, n = 3 committee | Nick, Ruffing & Seurin, CRYPTO 2021 / BIP 327 |
| Anonymous authentication | EOLTAA via Σ-OR proof (Java instantiation) | Li, Lai & Wu 2021 (interface); Cramer–Damgård–Schoenmakers 1994 (OR-composition) |
| Coercion-resistance | Σ-HVZK simulation + Pedersen equivocation (σ₁) | Finogina & Herranz 2023 §5.1 |

The EOLTAA layer is a **Java-based prototype instantiation of the EOLTAA functionality**, not the original libsnark zk-SNARK construction — see `docs/chapter3_deviations.md` §3.7.2.

## Build and test

```
mvn test
```

Expected: 202 tests, 0 failures.

## Running the CLI demos

After `mvn package` (or using a prebuilt `dist\Ng.jar`):

```
java -cp <classpath> mmu.fyp.evoting.demo.Demo honest
java -cp <classpath> mmu.fyp.evoting.demo.Demo coerced
java -cp <classpath> mmu.fyp.evoting.demo.Demo double-vote
java -cp <classpath> mmu.fyp.evoting.demo.Demo forged
java -cp <classpath> mmu.fyp.evoting.demo.Demo bench --quick
```

where `<classpath>` is either the assembled jar (`dist\Ng.jar`) or
`target\classes` plus the Bouncy Castle jar:

```
target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar
```

(Use `:` instead of `;` as the separator on Linux/macOS. If the jar was
built with preview features enabled, add `--enable-preview`.)

The CLI demos need **only** the Bouncy Castle jar. They never touch the
database.

## Running the GUI (three-window demo with H2 persistence)

```
java -cp "target\classes;<bcprov.jar>;<h2.jar>" mmu.fyp.evoting.demo.Demo gui
```

with the two dependency jars from the local Maven repository:

- `%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar`
- `%USERPROFILE%\.m2\repository\com\h2database\h2\2.2.224\h2-2.2.224.jar`

This opens the **Launcher** window with three roles: Voter, Certificate
Authority, and Election Committee. All three windows share one in-process
election state and refresh automatically.

### H2 database notes

- **The H2 jar must be on the classpath.** A missing H2 jar fails with
  `NoClassDefFoundError: org/h2/...` at startup — this is the most common
  reason the GUI "does not run" on a fresh machine. The CLI demos do not
  have this requirement.
- The database file is created at `<project-root>/db/election.mv.db`,
  where the project root is found by walking up from the working
  directory looking for `pom.xml`. Override the location with:
  `-Dfyp.db.path=C:\some\writable\path\election`
- **Every launcher start wipes the previous election** and begins a fresh
  one (only the citizen registry survives — it is reference data). To
  inspect the live database while the GUI runs, point DBeaver or the H2
  Console at the `.mv.db` file.
- If the database cannot be opened at all, the launcher logs a warning to
  stderr and falls back to in-memory operation; the GUI still works, but
  state is lost on close.

### GUI walkthrough (matches the Kho 2025 §6.1 phases)

1. **Launcher** — shows election ID, candidates, persistence status.
2. **Voter** window: enter name + IC (must match the CA's citizen
   registry; the seeded test identities are listed in the CA window's
   Citizen registry tab) → Submit Registration (runs Φ.UKeyGen
   client-side).
3. **Certificate Authority** window: Identify → Approve (runs
   Φ.CertGen; the issued certificate is displayed in both windows).
4. **Election Committee** window: Open Voting (locks the EOLTAA voter
   directory).
5. **Voter** window: select candidate → Cast Vote (6-round protocol,
   narrated in the log) → optionally Verify My Encryption (CAI),
   Generate Fake Transcript (coercion-resistance), Check Result,
   Verify Tally Proof (π_result NIZK).
6. **Election Committee** window: Collect And Count (6-step tally with
   π_result posted to the bulletin board).

## Project layout

```
src/main/java/mmu/fyp/evoting/
    crypto/
        group/         Prime-order group abstraction (secp256k1)
        pedersen/      Pedersen commitment + trapdoor equivocation
        sigma/         Σ-protocol (DLEq) + HVZK simulator
        cramershoup/   Cramer–Shoup IND-CCA2 PKE
        multisig/      MuSig2 two-round multi-signature (BIP 327)
        eoltaa/        EOLTAA: CSetup/UKeyGen/CertGen/Auth/Verify/Link/Trace
    entities/
        voter/         Voter, VoterSession, CoercionFake (σ₁ transcripts)
        ca/            Certificate Authority (registry, certificates, tracing)
        ec/            Election Committee (MuSig2 committee, PKE, vid)
        bulletinboard/ Hash-chained append-only board (ParamNotice, VidNotice, Ballot, TallyResult)
    protocol/          4-round Vote protocol, Tally (+ π_result NIZK), wire messages
    persistence/       H2 store + deterministic byte serialisation
    gui/               Launcher + Voter / CA / EC Swing windows
    demo/              CLI scenarios (honest, coerced, double-vote, forged)
    bench/             Timing + communication/storage size benchmark

src/test/java/mmu/fyp/evoting/  202 unit/property/integration tests (mirrors main)
docs/                           design notes, deviations, security-test map
```

## Status

All milestones complete: crypto primitives (with tests), honest end-to-end
flow, coercion-resistance fakes, double-vote detection and tracing, forged
ballot rejection, tally correctness proof (π_result), three-window GUI with
H2 persistence, and the timing + size benchmark. The prototype was
independently compiled, executed, and reviewed by the first author of the
scheme (June 2026) and assessed as a working prototype with no
scheme-construction errors.

## References

- Kho, Heng, Tan, Chin (2025) — *A provably secure coercion-resistant e-voting scheme*, PLOS ONE 20(6):e0324182. **The implemented scheme.**
- Finogina, Herranz (2023) — coercion-resistance + CAI verifiability protocol basis (σ₁).
- Li, Lai, Wu (2021) — EOLTAA interface (implemented as a Java Σ-OR instantiation; see docs/chapter3_deviations.md §3.7.2).
- Cramer, Shoup (1998) — IND-CCA2 public-key encryption.
- Pedersen (1991) — trapdoor commitment.
- Chaum, Pedersen (1992); Cramer (1996); Cramer, Damgård, Schoenmakers (1994) — Σ-protocols, OR-composition.
- Nick, Ruffing, Seurin (2021) / BIP 327 — MuSig2 multi-signature.
