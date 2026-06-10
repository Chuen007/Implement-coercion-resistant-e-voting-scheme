package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.crypto.cramershoup.CramerShoup;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.voter.CoercionFake;
import org.bouncycastle.math.ec.ECPoint;

import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;

/**
 * Modal dialog presenting the coercion-resistance demonstration <i>from the
 * coercer's point of view</i>. The voter has already privately cast their real
 * ballot; the coercer is now demanding the voter prove a particular vote
 * choice. This dialog shows <b>only the FAKE transcript</b> the voter hands
 * over and lets the user (playing the coercer) click a verifier button to see
 * that the fake still checks out cryptographically.
 *
 * <p>The REAL transcript and the side-by-side comparison are tucked away
 * behind an "Educational view" toggle, because the whole point of coercion
 * resistance is that the coercer never sees the real one. This matches the
 * threat model in Finogina &amp; Herranz (2023) §3.3: the coercer's view is
 * limited to the public ciphertext on the bulletin board plus the single
 * transcript the voter hands over.
 */
public final class TranscriptDialog extends JDialog {

    private final CoercionFake.Transcript real;
    private final CoercionFake.Transcript fake;
    private final CramerShoup.PublicKey ecPk;
    private final JPanel educationalPanel;
    private final JButton toggleEdu;
    private boolean eduShown = false;

    public TranscriptDialog(Window owner,
                            CoercionFake.Transcript real,
                            CoercionFake.Transcript fake,
                            CramerShoup.PublicKey ecPk) {
        super(owner, "Proof of Vote", ModalityType.APPLICATION_MODAL);
        this.real = real;
        this.fake = fake;
        this.ecPk = ecPk;
        this.educationalPanel = buildEducationalPanel();
        this.educationalPanel.setVisible(false);
        this.toggleEdu = new JButton(toggleLabel(false));
        this.toggleEdu.addActionListener(ev -> toggleEducational());

        JPanel main = new JPanel();
        main.setLayout(new BoxLayout(main, BoxLayout.Y_AXIS));
        main.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        main.add(buildBanner());
        main.add(Box.createVerticalStrut(8));
        main.add(buildFakeTranscriptPanel());
        main.add(Box.createVerticalStrut(8));
        main.add(buildVerifierPanel());
        main.add(Box.createVerticalStrut(8));
        main.add(leftAlign(toggleEdu));
        main.add(educationalPanel);

        JButton close = new JButton("Close");
        close.addActionListener(ev -> dispose());
        JPanel southBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        southBar.add(close);

        setLayout(new BorderLayout());
        JScrollPane outer = new JScrollPane(main,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        outer.setBorder(BorderFactory.createEmptyBorder());
        add(outer, BorderLayout.CENTER);
        add(southBar, BorderLayout.SOUTH);

        pack();
        setSize(960, Math.min(720, getHeight() + 40));
        setLocationRelativeTo(owner);
    }

    private static JComponent leftAlign(JComponent c) {
        JPanel wrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        wrap.add(c);
        wrap.setAlignmentX(Component.LEFT_ALIGNMENT);
        return wrap;
    }

    private JComponent buildBanner() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x9ac4a8)),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)));
        p.setBackground(new Color(0xeaf6ec));
        JLabel label = new JLabel(
                "<html>"
              + "<span style='color:#0a4a2a;font-size:14px;font-weight:bold;'>"
              + "Proof of vote &mdash; candidate " + fake.candidate() + "</span><br><br>"
              + "This document certifies that the holder cast a vote for candidate "
              + fake.candidate() + " in this<br>election. The cryptographic transcript below "
              + "can be independently verified by<br>anyone holding the Election Committee's "
              + "public parameters.<br><br>"
              + "<i>Election bulletin board contains the corresponding ciphertext; this "
              + "transcript<br>proves it encrypts the candidate stated above.</i>"
              + "</html>");
        label.setOpaque(false);
        p.add(label, BorderLayout.CENTER);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private JComponent buildFakeTranscriptPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder("Voting transcript"));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea ta = new JTextArea();
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setEditable(false);

        StringBuilder sb = new StringBuilder();
        appendFakeLine(sb, "field",                  "value");
        appendFakeLine(sb, "----------------------", "------------------------------");
        appendFakeLine(sb, "candidate v",            String.valueOf(fake.candidate()));
        appendFakeLine(sb, "ciphertext u1",          point(fake.ct().u1()));
        appendFakeLine(sb, "ciphertext e",           point(fake.ct().e()));
        appendFakeLine(sb, "commitment cmt",         point(fake.commitment()));
        appendFakeLine(sb, "Pedersen base h_v",      point(fake.pedersenH()));
        appendFakeLine(sb, "sigma A[0]",             point(fake.sigmaA().a().get(0)));
        appendFakeLine(sb, "sigma E (challenge)",    scalar(fake.sigmaE()));
        appendFakeLine(sb, "sigma Z (response)",     scalar(fake.sigmaZ()));
        appendFakeLine(sb, "Pedersen r_hat",         scalar(fake.pedersenR()));
        ta.setText(sb.toString());
        ta.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(ta,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.setPreferredSize(new Dimension(900, 230));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private JComponent buildVerifierPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createTitledBorder("Verification"));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel instr = new JLabel(
                "<html>Click below to run the cryptographic verifier on this transcript.<br>"
              + "A passing result means the proof is valid and the transcript has not<br>"
              + "been tampered with.</html>");
        instr.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        instr.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton verify = new JButton("▶ Run verifier");
        verify.setFont(verify.getFont().deriveFont(Font.BOLD, 13f));

        JLabel result = new JLabel(" ");
        result.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        result.setAlignmentX(Component.LEFT_ALIGNMENT);

        verify.addActionListener(ev -> {
            boolean ok = CoercionFake.verify(fake, ecPk);
            if (ok) {
                result.setText(
                        "<html>"
                      + "<span style='color:#0a8a3a;font-size:14px;font-weight:bold;'>"
                      + "verifies = TRUE &#10003;</span><br><br>"
                      + "<b>Cryptographic verification passed.</b><br>"
                      + "The transcript is a valid proof that the corresponding ciphertext<br>"
                      + "on the bulletin board encrypts candidate " + fake.candidate() + "."
                      + "</html>");
            } else {
                result.setText("<html><span style='color:red;font-weight:bold;'>"
                        + "verifies = FALSE</span> &mdash; transcript is invalid or tampered.</html>");
            }
            verify.setEnabled(false);
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        buttonRow.add(verify);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        p.add(instr);
        p.add(buttonRow);
        p.add(result);
        return p;
    }

    private void toggleEducational() {
        eduShown = !eduShown;
        educationalPanel.setVisible(eduShown);
        toggleEdu.setText(toggleLabel(eduShown));
        validate();
        if (eduShown) {
            // The construction walkthrough is long — grow the window aggressively
            // so the user does not have to scroll to see Phase A.
            setSize(getWidth(), Math.min(1000, getHeight() + 520));
        }
    }

    private static String toggleLabel(boolean shown) {
        return (shown ? "▼" : "▶")
                + " Technical protocol details"
                + (shown ? " — hide" : "");
    }

    /**
     * Step-by-step construction of the fake transcript, structured exactly
     * after Kho et al. (2025) Vote protocol + Lemma 3 (coercion-resistance via
     * Σ-HVZK + Pedersen equivocation). Real numerical values from this voting
     * session are inserted at each step so the reader can trace the
     * construction down to the bytes on the wire.
     */
    private JPanel buildEducationalPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                        "Construction walkthrough — Kho et al. (2025) Vote protocol"),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea ta = new JTextArea();
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setEditable(false);

        StringBuilder sb = new StringBuilder();
        String hr = "─".repeat(72);
        boolean realOk = CoercionFake.verify(real, ecPk);
        boolean fakeOk = CoercionFake.verify(fake, ecPk);

        sb.append("You actually voted for v = ").append(real.candidate())
          .append(".   The coercer demanded v* = ").append(fake.candidate()).append(".\n\n");

        sb.append(hr).append("\n");
        sb.append(" PHASE A — REAL VOTING (already happened when you clicked Cast Vote)\n");
        sb.append(hr).append("\n\n");

        sb.append("  Round 1.  You picked your true choice v = ").append(real.candidate())
          .append(" and a fresh random challenge e.\n");
        sb.append("            You computed the Pedersen commitment\n");
        sb.append("                cmt = Com(e ; r_hat)  =  ").append(point(real.commitment())).append("\n");
        sb.append("            and sent cmt to the Election Committee in Round 1.\n\n");
        sb.append("            Pedersen is HIDING  -> EC cannot learn e from cmt.\n");
        sb.append("            Pedersen is BINDING -> EC cannot get you to open cmt to a\n");
        sb.append("            different e (without your trapdoor).\n\n");

        sb.append("  Round 2.  EC encrypted your choice with Cramer-Shoup:\n");
        sb.append("                C = Enc_CS(pk_EC, g^v) = (u1, e_ct)\n");
        sb.append("                u1   = ").append(point(real.ct().u1())).append("\n");
        sb.append("                e_ct = ").append(point(real.ct().e())).append("\n");
        sb.append("            and posted C to the bulletin board (D2).\n");
        sb.append("            EC then executed Sigma-Protocol Step 1 (commit):\n");
        sb.append("                a = (A[0] = ").append(point(real.sigmaA().a().get(0))).append(")\n");
        sb.append("            EC sent (C, a) back to you.\n\n");

        sb.append("  Round 3.  You revealed the challenge e you had committed:\n");
        sb.append("                e     = ").append(scalar(real.sigmaE())).append("\n");
        sb.append("                r_hat = ").append(scalar(real.pedersenR())).append("\n");
        sb.append("            sent (e, r_hat) to EC.\n\n");

        sb.append("  Round 4.  EC verified that cmt opens to e under r_hat, then\n");
        sb.append("            computed the Sigma-Protocol response\n");
        sb.append("                z = t + e * r       (r = encryption randomness)\n");
        sb.append("                  = ").append(scalar(real.sigmaZ())).append("\n");
        sb.append("            and sent z back to you.\n\n");
        sb.append("            You now hold the REAL transcript:\n");
        sb.append("                Trc = (v=").append(real.candidate())
          .append(", C, a, e, z, cmt, r_hat)\n");
        sb.append("            real (claims v=").append(real.candidate())
          .append("): verifies = ").append(realOk).append("\n\n");
        sb.append("            Only YOU have Trc. C is public on the bulletin board.\n\n");

        sb.append(hr).append("\n");
        sb.append(" PHASE B — COERCER DEMANDS, YOU GENERATE FAKE\n");
        sb.append(hr).append("\n\n");

        sb.append("  Step 5.  The coercer demanded you prove you voted for v* = ")
          .append(fake.candidate()).append(".\n");
        sb.append("           Handing over the real Trc would prove you voted ")
          .append(real.candidate()).append(", not v*.\n\n");

        sb.append("  Step 6.  You invoked the Sigma-Protocol HVZK SIMULATOR with input\n");
        sb.append("                x' = (v* = ").append(fake.candidate()).append(", C)\n");
        sb.append("           Crucially, C still encrypts ").append(real.candidate())
          .append(" — but the simulator does not\n");
        sb.append("           need to know what C encrypts. Pick a fresh e' and the\n");
        sb.append("           simulator produces (a', z') such that (a', e', z') verifies\n");
        sb.append("           against the statement \"C encrypts v*\":\n");
        sb.append("                a' = ").append(point(fake.sigmaA().a().get(0))).append("\n");
        sb.append("                e' = ").append(scalar(fake.sigmaE())).append("\n");
        sb.append("                z' = ").append(scalar(fake.sigmaZ())).append("\n\n");

        sb.append("  Step 7.  You EQUIVOCATED the Pedersen commitment using your private\n");
        sb.append("           trapdoor (the discrete log of h base g) to obtain a new\n");
        sb.append("           opening for the SAME cmt:\n");
        sb.append("                r_hat' = ").append(scalar(fake.pedersenR())).append("\n");
        sb.append("           so that\n");
        sb.append("                cmt = Com(e' ; r_hat')\n");
        sb.append("           The cmt value is unchanged:\n");
        sb.append("                cmt = ").append(point(fake.commitment())).append("\n");
        sb.append("           but it now opens to e' under r_hat'.\n\n");
        sb.append("           You now hold the FAKE transcript:\n");
        sb.append("                Trc' = (v*=").append(fake.candidate())
          .append(", C, a', e', z', cmt, r_hat')\n");
        sb.append("            fake (claims v=").append(fake.candidate())
          .append("): verifies = ").append(fakeOk).append("\n\n");

        sb.append("  Step 8.  You handed Trc' to the coercer (the FAKE table at the top).\n\n");

        sb.append(hr).append("\n");
        sb.append(" PHASE C — COERCER VERIFIES (this is what the button above does)\n");
        sb.append(hr).append("\n\n");

        sb.append("  Step 9.  The coercer's verifier checked:\n");
        sb.append("              (a) cmt opens to e' under r_hat'         -> TRUE  (equivocation)\n");
        sb.append("              (b) (a', e', z') is a valid Sigma-proof\n");
        sb.append("                  for the statement \"C encrypts v*\"   -> TRUE  (HVZK)\n");
        sb.append("           Both checks pass -> coercer is convinced you voted v*.\n\n");

        sb.append(hr).append("\n");
        sb.append(" WHY IT WORKS — Kho et al. (2025) Lemma 3 + Section 5 Theorem 1\n");
        sb.append(hr).append("\n\n");

        sb.append("  * SPECIAL HVZK of the Sigma-Protocol guarantees the simulator's\n");
        sb.append("    (a', e', z') is computationally indistinguishable from a real\n");
        sb.append("    transcript for \"C encrypts v*\".\n\n");
        sb.append("  * EQUIVOCATION of the Pedersen commitment lets a single cmt open\n");
        sb.append("    to ANY e — including e'. The voter holds the trapdoor; the\n");
        sb.append("    coercer does not.\n\n");
        sb.append("  * IND-CCA2 of Cramer-Shoup makes C decryption-resistant — the\n");
        sb.append("    coercer cannot decrypt C themselves to detect the lie.\n\n");
        sb.append("  Lemma 3 (Kho 2025): For any PPT coercer A,\n");
        sb.append("      Pr[ A wins coercion game ]  <=  1/2 + negl(lambda)\n\n");
        sb.append("  Section 5, Theorem 1 (Kho 2025): Anonymity (IND-CVA) IMPLIES CAI\n");
        sb.append("  verifiability (IND-CAI). Once Theorem 3 establishes anonymity, CAI\n");
        sb.append("  verifiability follows automatically — no separate proof is needed.\n\n");

        sb.append(hr).append("\n");
        sb.append(" DATA-LEVEL COMPARISON — REAL vs FAKE side-by-side\n");
        sb.append(hr).append("\n\n");
        sb.append("  The coercer NEVER sees both columns. This panel shows them together\n");
        sb.append("  so YOU can verify the same Sigma-verifier accepts both transcripts.\n\n");

        appendLine(sb, "field",                  "REAL (private to voter)",         "FAKE (given to coercer)");
        appendLine(sb, "----------------------", "---------------------------",    "---------------------------");
        appendLine(sb, "candidate v",            String.valueOf(real.candidate()),  String.valueOf(fake.candidate()));
        appendLine(sb, "ciphertext u1",          point(real.ct().u1()),             point(fake.ct().u1()));
        appendLine(sb, "ciphertext e_ct",        point(real.ct().e()),              point(fake.ct().e()));
        appendLine(sb, "commitment cmt",         point(real.commitment()),          point(fake.commitment()));
        appendLine(sb, "Pedersen base h_v",      point(real.pedersenH()),           point(fake.pedersenH()));
        appendLine(sb, "sigma A[0]",             point(real.sigmaA().a().get(0)),   point(fake.sigmaA().a().get(0)));
        appendLine(sb, "sigma E (challenge)",    scalar(real.sigmaE()),             scalar(fake.sigmaE()));
        appendLine(sb, "sigma Z (response)",     scalar(real.sigmaZ()),             scalar(fake.sigmaZ()));
        appendLine(sb, "Pedersen r_hat",         scalar(real.pedersenR()),          scalar(fake.pedersenR()));
        sb.append("\n");
        sb.append(String.format("  real (claims v=%d): verifies = %s%n", real.candidate(), realOk));
        sb.append(String.format("  fake (claims v=%d): verifies = %s%n", fake.candidate(), fakeOk));
        sb.append("\n");
        sb.append("  Top 5 fields are byte-identical between REAL and FAKE because C,\n");
        sb.append("  cmt, and h_v are public/already-published values that the simulator\n");
        sb.append("  cannot change. Bottom 4 fields differ: the Sigma scalars come from\n");
        sb.append("  the HVZK simulator, and r_hat is equivocated using the trapdoor.\n");

        ta.setText(sb.toString());
        ta.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(ta,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.setPreferredSize(new Dimension(900, 440));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private static void appendLine(StringBuilder sb, String label, String a, String b) {
        sb.append(String.format("  %-25s  %-30s  %-30s%n", label, a, b));
    }

    private static void appendFakeLine(StringBuilder sb, String label, String a) {
        sb.append(String.format("  %-25s  %s%n", label, a));
    }

    private static String point(ECPoint p) {
        byte[] enc = Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(12, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private static String scalar(BigInteger s) {
        byte[] b = s.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(12, b.length); i++) sb.append(String.format("%02x", b[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }
}
