package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.crypto.eoltaa.EOLTAA;
import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.voter.CoercionFake;
import mmu.fyp.evoting.entities.voter.VoterSession;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Voter Client window. Covers every Voter-side use case from FYP 2 Chapter 4 §4.4:
 * Register identity, Select Candidate, Verify Encryption, Submit Ballot,
 * Generate Fake Vote, Check Result.
 *
 * <p>The window auto-refreshes its registration/voting state on a Swing timer, so the
 * voter sees the CA's approval and the EC opening voting without clicking anything.
 * After a ballot is cast, the voter's linking tag is shown in a copy-able field so it
 * can be pasted into the CA's Tracing tab during the double-vote demo.
 */
public final class VoterGui extends JFrame {

    private static final int REFRESH_MS = 750;

    private final ElectionSystem system;
    private final String myName;
    private final String myIc;
    private final String[] candidateNames;

    // Step 1 — Register
    private final JLabel registrationStatus;
    private final JButton submitButton = new JButton("Submit Registration Request");

    // Step 2 — waiting + voting
    private JLabel waitingMessageLabel;   // populated on transition to CARD_WAITING with the issued credentials
    private final ButtonGroup candidateGroup = new ButtonGroup();
    private final JRadioButton[] candidateRadios;
    private final JButton castVoteButton = new JButton("Cast Vote");
    private final JButton verifyButton = new JButton("Verify My Encryption");
    private final JButton fakeButton = new JButton("Generate Fake Transcript");
    private final JButton checkResultButton = new JButton("Check Result");
    private final JButton verifyTallyButton = new JButton("Verify Tally Proof");

    // Linking tag — surfaced after voting so it can be pasted into the CA Tracing tab
    private final JTextField linkingTagField = new JTextField(44);
    private final JButton copyTagButton = new JButton("Copy");
    private String myLinkingTagHex = "";

    private final JTextArea log = new JTextArea(14, 70);

    // Step navigation — three cards swap based on (approved, votingOpen):
    //   CARD_STEP1   → not approved yet (registration form)
    //   CARD_WAITING → approved, but EC has not opened voting yet
    //   CARD_STEP2   → approved AND voting open (candidate selection + cast vote)
    private final CardLayout cardLayout = new CardLayout();
    private final JPanel cardPanel = new JPanel(cardLayout);
    private static final String CARD_STEP1 = "step1";
    private static final String CARD_WAITING = "waiting";
    private static final String CARD_STEP2 = "step2";
    private String currentCard = CARD_STEP1;

    // auto-refresh
    private final Timer refreshTimer;
    private String lastStatusText = "";
    private boolean announcedVotingOpen;

    public VoterGui(ElectionSystem system, String name, String icNumber, String[] candidateNames) {
        super("Voter — " + name);
        this.system = system;
        this.myName = name;
        this.myIc = CitizenRecord.normaliseIc(icNumber);
        this.candidateNames = candidateNames;
        this.candidateRadios = new JRadioButton[candidateNames.length];
        this.registrationStatus = new JLabel("Status: not registered");

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));

        add(buildHeader(), BorderLayout.NORTH);
        add(buildCentre(), BorderLayout.CENTER);
        add(buildLog(), BorderLayout.SOUTH);

        submitButton.addActionListener(e -> onSubmitRegistration());
        castVoteButton.addActionListener(e -> onCastVote());
        verifyButton.addActionListener(e -> onVerify());
        fakeButton.addActionListener(e -> onGenerateFake());
        checkResultButton.addActionListener(e -> onCheckResult());
        verifyTallyButton.addActionListener(e -> onVerifyTally());
        copyTagButton.addActionListener(e -> onCopyTag());

        // Tooltips clarifying what each action means cryptographically — these matter
        // because the GUI labels alone don't distinguish this scheme's "Σ-protocol
        // simulation" coercion-resistance from the unrelated "JCJ-style fake credential"
        // family of solutions (Civitas, TRIP, Anamorphic Encryption). See
        // docs/literature-comparison.md for the design rationale.
        verifyTallyButton.setToolTipText(
                "<html><b>Tally-step-6 π<sub>result</sub> verification.</b><br>"
              + "Verifies the Fiat-Shamir NIZK the EC posted alongside the tally,<br>"
              + "proving (in zero knowledge) that the same secret key {@code z} was<br>"
              + "used to decrypt every counted ballot. Any swap, omission, or<br>"
              + "fabrication by the EC would cause this proof to fail verification.<br><br>"
              + "Implements Kho et al. (2025) §6.1 Tally step 6.</html>");
        verifyButton.setToolTipText(
                "<html><b>Cast-as-Intended (CAI) verification.</b><br>"
              + "Locally decrypts the EC's reply ciphertext and confirms that<br>"
              + "the candidate the EC encrypted matches the candidate you chose.<br>"
              + "Implements Finogina &amp; Herranz (2023) Def. 1 via the &Sigma;-DLEq<br>"
              + "proof embedded in the 4-round Vote protocol.</html>");
        fakeButton.setToolTipText(
                "<html><b>Coercion-resistance demonstration.</b><br><br>"
              + "Generates a simulated &Sigma;-protocol transcript that &quot;proves&quot; you voted for any<br>"
              + "candidate of your choice &mdash; even though your real vote is unchanged. The<br>"
              + "ciphertext sent to the bulletin board is <i>bit-identical</i> between the real<br>"
              + "and fake transcripts; only the Sigma scalars (e, z) and Pedersen randomness differ.<br><br>"
              + "<b>This is a &Sigma;-protocol HVZK simulation</b> (Finogina &amp; Herranz 2023 &sect;5.1, &quot;&sigma;<sub>1</sub>&quot;).<br>"
              + "<b>It is NOT a JCJ-style fake credential</b> (Civitas, Merino TRIP 2024, Michalas AME 2026):<br>"
              + "&nbsp;&nbsp;&bull; You hold a single EOLTAA credential, not multiple real+fake credentials<br>"
              + "&nbsp;&nbsp;&bull; No vote is silently discarded &mdash; the vote you cast IS the vote tallied<br><br>"
              + "<i>See docs/literature-comparison.md for the full design rationale.</i></html>");

        appendLog("[voter] window opened — logged in as " + myName
                + " (IC: " + new CitizenRecord(myName, myIc).displayIc() + ")");
        appendLog("Use Cases: Register identity, Select Candidate, Verify Encryption, "
                + "Submit Ballot, Generate Fake Vote, Check Result");
        appendLog("");

        // initial paint + auto-refresh so CA approval / EC opening voting show up on their own
        syncState();
        refreshTimer = new Timer(REFRESH_MS, e -> syncState());
        refreshTimer.start();
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosed(java.awt.event.WindowEvent e) { refreshTimer.stop(); }
        });

        pack();
        // CardLayout sizes to its largest child; the credentials waiting card is
        // wider and taller than the registration form, so bump the packed minimum
        // to make sure the Φ.CertGen output is fully visible without scrolling.
        setSize(Math.max(getWidth(), 760), Math.max(getHeight(), 620));
        setLocationRelativeTo(null);
    }

    // ---------- layout ----------

    private JComponent buildHeader() {
        JPanel p = new JPanel(new GridLayout(0, 1));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 0, 12));
        JLabel title = new JLabel("Voter Client — " + myName);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        p.add(title);
        JLabel sub = new JLabel("IC: " + new CitizenRecord(myName, myIc).displayIc());
        sub.setForeground(Color.DARK_GRAY);
        p.add(sub);
        return p;
    }

    private JComponent buildCentre() {
        cardPanel.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 12));
        cardPanel.add(buildRegistrationPanel(), CARD_STEP1);
        cardPanel.add(buildWaitingPanel(),      CARD_WAITING);
        cardPanel.add(buildVotingPanel(),       CARD_STEP2);
        return cardPanel;
    }

    /**
     * Card shown after the CA approves the voter but before the EC opens voting.
     * Explicitly tells the voter that voting has not started yet rather than
     * showing a greyed-out candidate list, which is confusing.
     */
    private JComponent buildWaitingPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Step 2 of 2 — Credentials received, waiting for voting to open"),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));

        // JEditorPane handles long HTML far better than JLabel (which silently
        // clips when its preferred height exceeds the available space). Wrapping
        // it in a scrollpane gives a safety net for narrow / short windows.
        waitingMessageLabel = new JLabel("…", SwingConstants.CENTER);
        JScrollPane scroll = new JScrollPane(waitingMessageLabel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    /** Render the issued (upk, usk, Cert) triple plus the wait-for-EC message. */
    private void renderWaitingPanelCredentials() {
        var voter = system.voter(myIc);
        if (voter == null) {
            waitingMessageLabel.setText("<html><div style='text-align:center;'>"
                    + "Waiting for CA approval…</div></html>");
            return;
        }
        var cert = voter.certificate();
        // Compact, single-pass layout: small banner, tight 4-row table, footer.
        // No extra <br> gaps; table cellpadding kept low so the whole block fits
        // inside the card without scrolling on the default window size.
        String html = "<html><div style='text-align:center;'>"
                + "<span style='font-size:13px;color:#0a6a2a;'><b>"
                + "&#10003; The CA has issued your voting credentials."
                + "</b></span>"
                + "<table cellpadding='2' style='font-family:monospace;font-size:11px;margin-top:6px;'>"
                + "<tr><td align='right'><b>upk =</b></td><td align='left'>"
                + truncHex(voter.upk().Y()) + "</td>"
                + "<td align='left' style='color:gray;'>&nbsp;your EOLTAA public key</td></tr>"
                + "<tr><td align='right'><b>usk =</b></td><td align='left'>"
                + "[held privately by this client]</td>"
                + "<td align='left' style='color:gray;'>&nbsp;your EOLTAA secret key</td></tr>"
                + "<tr><td align='right'><b>Cert.R =</b></td><td align='left'>"
                + truncHex(cert.R()) + "</td>"
                + "<td align='left' style='color:gray;'>&nbsp;&Phi;.CertGen output (point)</td></tr>"
                + "<tr><td align='right'><b>Cert.s =</b></td><td align='left'>"
                + truncScalar(cert.s()) + "</td>"
                + "<td align='left' style='color:gray;'>&nbsp;&Phi;.CertGen output (scalar)</td></tr>"
                + "</table>"
                + "<div style='font-size:11px;margin-top:6px;'>"
                + "Anyone holding the CA's MPK can verify your Cert with<br>"
                + "<span style='font-family:monospace;'>&Phi;.CertVerify(Cert, upk, MPK) &rarr; 1</span>"
                + "</div>"
                + "<div style='font-size:11px;margin-top:8px;font-style:italic;color:#444;'>"
                + "Waiting for the Election Committee to open voting.<br>"
                + "This panel switches to the candidate list automatically."
                + "</div>"
                + "</div></html>";
        waitingMessageLabel.setText(html);
    }

    private static String truncHex(org.bouncycastle.math.ec.ECPoint p) {
        byte[] enc = Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private static String truncScalar(java.math.BigInteger s) {
        byte[] b = s.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, b.length); i++) sb.append(String.format("%02x", b[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private JComponent buildRegistrationPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Step 1 of 2 — Register your identity"),
                BorderFactory.createEmptyBorder(12, 16, 12, 16)));

        JLabel intro = new JLabel(
                "<html>You are logged in. Click <b>Submit Registration Request</b> below to send<br>"
              + "your (name, IC) to the Certificate Authority.<br><br>"
              + "The CA will verify your identity against its citizen registry.<br>"
              + "If your identity matches, you will be moved to <b>Step 2 — Cast your vote</b><br>"
              + "automatically once the CA approves your request.<br><br>"
              + "<i>Use Cases: Register identity, Verify Eligibility, Get Voting Credentials.</i></html>");
        panel.add(intro, BorderLayout.NORTH);

        JPanel actionAndStatus = new JPanel();
        actionAndStatus.setLayout(new BoxLayout(actionAndStatus, BoxLayout.Y_AXIS));
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        buttonRow.add(submitButton);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionAndStatus.add(buttonRow);
        actionAndStatus.add(Box.createVerticalStrut(8));
        registrationStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionAndStatus.add(registrationStatus);
        panel.add(actionAndStatus, BorderLayout.CENTER);

        return panel;
    }

    private JComponent buildVotingPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Step 2 of 2 — Cast your vote"),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));

        JPanel top = new JPanel(new BorderLayout(0, 8));
        JLabel intro = new JLabel(
                "<html>You are registered. Choose a candidate below and click <b>Cast Vote</b><br>"
              + "once the Election Committee opens voting.<br>"
              + "<i>Use Cases: Select Candidate, Verify Encryption, Submit Ballot, "
              + "Generate Fake Vote, Check Result.</i></html>");
        top.add(intro, BorderLayout.NORTH);

        JPanel candidatePanel = new JPanel(new GridLayout(0, 1));
        candidatePanel.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        for (int i = 0; i < candidateNames.length; i++) {
            int v = i + 1;
            candidateRadios[i] = new JRadioButton(v + " — " + candidateNames[i]);
            candidateGroup.add(candidateRadios[i]);
            candidatePanel.add(candidateRadios[i]);
        }
        top.add(candidatePanel, BorderLayout.CENTER);
        panel.add(top, BorderLayout.NORTH);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        actionPanel.add(castVoteButton);
        actionPanel.add(verifyButton);
        actionPanel.add(fakeButton);
        actionPanel.add(checkResultButton);
        actionPanel.add(verifyTallyButton);
        panel.add(actionPanel, BorderLayout.CENTER);

        JPanel tagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        tagPanel.add(new JLabel("My linking tag (paste into CA → Tracing):"));
        linkingTagField.setEditable(false);
        linkingTagField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tagPanel.add(linkingTagField);
        tagPanel.add(copyTagButton);
        panel.add(tagPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JComponent buildLog() {
        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(log);
        scroll.setBorder(BorderFactory.createTitledBorder("Log"));
        return scroll;
    }

    // ---------- actions ----------

    private void onSubmitRegistration() {
        // Register step 4 (Kho et al. 2025 §6.1) — voter runs Φ.UKeyGen
        // CLIENT-SIDE before submitting to the CA. The keypair never originates
        // on the system/CA side; only (name, IC, upk) is transmitted plus the
        // usk for tracing escrow per §3.7.2 deviation.
        EOLTAA.UserKeyPair kp = EOLTAA.uKeyGen();
        appendLog("[voter] Φ.UKeyGen → (upk, usk); upk = "
                + Group.encode(kp.upk().Y()).length + " bytes");
        appendLog("[voter] submitting RegistrationRequest(name=\"" + myName
                + "\", IC=\"" + new CitizenRecord(myName, myIc).displayIc() + "\", upk) to CA");
        system.submitRegistration(myName, myIc, kp);
        appendLog("[voter] request enqueued; the CA will verify (name, IC) against "
                + "its citizen registry before issuing Cert via Φ.CertGen");
        appendLog("");
        syncState();
    }

    private void onCastVote() {
        int chosen = selectedCandidate();
        if (chosen == -1) {
            JOptionPane.showMessageDialog(this, "Select a candidate first.",
                    "No candidate", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!system.votingOpen()) {
            appendLog("[voter] voting not open yet — ask the EC to open voting");
            syncState();
            return;
        }
        try {
            // Narrate the 6-round Vote protocol of Kho et al. (2025) §6.1.
            appendLog("[voter] === Vote protocol (Kho et al. 2025 §6.1, 6-round breakdown) ===");
            appendLog("  Round 1: ✓ EC posted (vid ‖ π_T) to BB at election setup");
            appendLog("  Round 2: voter → EC: (v=" + chosen + " '" + candidateNames[chosen - 1]
                    + "', cmt = Com(e ; r̂))");
            Ballot ballot = system.castVote(myIc, chosen);
            appendLog("  Round 3: EC encrypted v under Cramer-Shoup → C_i");
            appendLog("  Round 4: EC → voter: (C_i, σ = MuSig2-sign(C_i), a = σ-protocol first move)");
            appendLog("  Round 5: voter → EC: (e, r̂) — challenge + opening");
            appendLog("  Round 6: EC → voter: z — σ-protocol response");
            appendLog("  ✓ MuSig2.verify(σ, X̃) and σ-DLEq(a, e, z) both pass");
            appendLog("  ✓ voter posts Bal = (C_i, π_i = Φ.Auth(vid ‖ C_i, ...))  to BB");
            myLinkingTagHex = HexFormat.of().formatHex(Group.encode(ballot.voterAuth().linkingTag()));
            linkingTagField.setText(myLinkingTagHex);
            linkingTagField.setCaretPosition(0);
            appendLog("[voter] linking tag (paste into CA Tracing tab): " + myLinkingTagHex);
            appendLog("");
            syncState();
        } catch (Exception ex) {
            appendLog("[voter] ERROR: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Vote failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onCopyTag() {
        if (myLinkingTagHex.isEmpty()) {
            appendLog("[voter] no linking tag yet — cast a vote first");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(myLinkingTagHex), null);
        appendLog("[voter] linking tag copied to clipboard");
    }

    private void onVerify() {
        Optional<Integer> revealed = system.revealEncryptedVote(myIc);
        Optional<VoterSession> session = system.sessionOf(myIc);
        if (revealed.isEmpty() || session.isEmpty()) {
            appendLog("[verify] no ballot yet to verify");
            return;
        }
        int v = revealed.get();
        int chosen = session.get().candidate();
        appendLog("[verify] EC encrypted candidate " + v + " ; you chose " + chosen
                + " — match: " + (v == chosen));
        JOptionPane.showMessageDialog(this,
                "Your vote was correctly encrypted.\n\n"
                        + "Chosen: " + chosen + " (" + candidateNames[chosen - 1] + ")\n"
                        + "Encrypted: " + v + " (" + candidateNames[v - 1] + ")",
                "Encryption verification", JOptionPane.INFORMATION_MESSAGE);
    }

    private void onGenerateFake() {
        Optional<VoterSession> session = system.sessionOf(myIc);
        if (session.isEmpty()) {
            appendLog("[coerce] no ballot to fake against yet");
            return;
        }
        Object[] options = new Object[candidateNames.length];
        for (int i = 0; i < candidateNames.length; i++) options[i] = (i + 1) + " — " + candidateNames[i];
        Object selection = JOptionPane.showInputDialog(this,
                "What candidate should the coercer think you voted for?",
                "Generate fake transcript", JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]);
        if (selection == null) return;
        int target = -1;
        for (int i = 0; i < options.length; i++) if (options[i].equals(selection)) target = i + 1;
        if (target == -1) return;

        CoercionFake.Transcript real = CoercionFake.real(session.get());
        CoercionFake.Transcript fake = CoercionFake.fake(session.get(), target);
        appendLog("[coerce] fake for v*=" + target + ": verifies = "
                + CoercionFake.verify(fake, system.ec.encryptionPk()));
        TranscriptDialog dlg = new TranscriptDialog(this, real, fake, system.ec.encryptionPk());
        dlg.setVisible(true);
    }

    private void onVerifyTally() {
        // Tally step 6 (Kho et al. 2025 §6.1) — verify the EC's π_result NIZK.
        var resultOpt = system.bb.result();
        if (resultOpt.isEmpty()) {
            appendLog("[verify-tally] no tally result on the BB yet — wait for EC to tally");
            return;
        }
        var result = resultOpt.get();
        boolean ok = mmu.fyp.evoting.protocol.Tally.verifyTallyProof(
                result, system.ec.encryptionPk());
        appendLog("[verify-tally] π_result verifies = " + ok
                + " (NIZK over " + result.decryptions().size() + " decryption record(s))");
        if (ok) {
            JOptionPane.showMessageDialog(this,
                    "Tally proof π_result VERIFIES.\n\n"
                  + "The Election Committee proved (in zero knowledge) that it used\n"
                  + "the same secret key z to decrypt every ballot — meaning no\n"
                  + "swap, omission, or fabrication is possible without detection.\n\n"
                  + "Per-ballot decryption records on BB: " + result.decryptions().size(),
                    "π_result verified", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "π_result FAILED to verify.\n\n"
                  + "Either the EC tampered with the tally, or the proof is malformed.",
                    "π_result invalid", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onCheckResult() {
        var voter = system.voter(myIc);
        if (voter == null) {
            appendLog("[check-result] you are not registered");
            return;
        }
        Optional<TallyResult> result = voter.checkResult(system.bb);
        if (result.isEmpty()) {
            appendLog("[check-result] no result on the BB yet — ask the EC to run the tally");
            return;
        }
        appendLog("[check-result] D3 contents: counts=" + result.get().counts()
                + ", traced=" + result.get().tracedDoubleVoters());
        JOptionPane.showMessageDialog(this,
                "Result published to D3:\n\nCounts: " + result.get().counts()
                        + "\nTraced double voters: " + result.get().tracedDoubleVoters(),
                "Result", JOptionPane.INFORMATION_MESSAGE);
    }

    // ---------- state sync (auto-refresh) ----------

    /** Re-derives the whole window's enabled/disabled state from the shared ElectionSystem. */
    private void syncState() {
        Optional<RegistrationOutcome> outcome = system.findOutcome(myIc);
        boolean present = outcome.isPresent();
        boolean approved = outcome.map(RegistrationOutcome::approved).orElse(false);
        boolean rejected = present && !approved;
        boolean pending = system.isPending(myIc);
        boolean voted = system.hasVoted(myIc);
        boolean open = system.votingOpen();

        String status;
        if (approved) status = "registered at directory position " + outcome.get().directoryPosition();
        else if (rejected) status = "rejected (" + outcome.get().status() + ")";
        else if (pending) status = "pending — waiting for CA approval";
        else status = "not registered";
        registrationStatus.setText("Status: " + status);

        if (!status.equals(lastStatusText)) {
            // skip logging the initial "not registered" baseline
            if (!lastStatusText.isEmpty() || !status.equals("not registered")) {
                appendLog("[voter] status changed: " + status);
                appendLog("");
            }
            lastStatusText = status;
        }
        // Step navigation — 3-state card swap based on (approved, open):
        //   not approved    → Step 1 (register)
        //   approved, !open → "voting not started yet" wait page
        //   approved,  open → Step 2 (vote)
        String desiredCard;
        if (!approved)      desiredCard = CARD_STEP1;
        else if (!open)     desiredCard = CARD_WAITING;
        else                desiredCard = CARD_STEP2;
        if (!desiredCard.equals(currentCard)) {
            cardLayout.show(cardPanel, desiredCard);
            switch (desiredCard) {
                case CARD_WAITING -> {
                    // Register step 5 (Kho et al. 2025 §6.1): CA verified eligibility
                    // and handed back Cert via Φ.CertGen. Log the issued cert and show
                    // it in the waiting card so the voter SEES the cryptographic artifact
                    // they just received.
                    var voter = system.voter(myIc);
                    if (voter != null) {
                        var cert = voter.certificate();
                        appendLog("[voter] CA verified eligibility ✓");
                        appendLog("[voter] received Cert via Φ.CertGen(MSK, upk):");
                        appendLog("           Cert.R = " + truncHex(cert.R()));
                        appendLog("           Cert.s = " + truncScalar(cert.s()));
                        appendLog("[voter] credentials complete: (upk, usk, Cert) held by this client");
                    }
                    renderWaitingPanelCredentials();
                    appendLog("[voter] waiting for the EC to open voting");
                    appendLog("");
                }
                case CARD_STEP2 -> {
                    appendLog("[voter] voting is now OPEN — choose a candidate and Cast Vote");
                    appendLog("");
                    announcedVotingOpen = true;
                }
                default -> { /* moved back to Step 1 — no-op */ }
            }
            currentCard = desiredCard;
        }

        submitButton.setEnabled(!present && !pending);

        boolean canVote = approved && open && !voted;
        for (JRadioButton r : candidateRadios) {
            if (r != null) r.setEnabled(canVote);
        }
        castVoteButton.setEnabled(canVote);
        verifyButton.setEnabled(voted);
        fakeButton.setEnabled(voted);
        checkResultButton.setEnabled(true);  // always available; returns Empty until tally
        verifyTallyButton.setEnabled(system.bb.result().isPresent());
        copyTagButton.setEnabled(!myLinkingTagHex.isEmpty());
    }

    // ---------- helpers ----------

    private int selectedCandidate() {
        for (int i = 0; i < candidateRadios.length; i++) {
            if (candidateRadios[i].isSelected()) return i + 1;
        }
        return -1;
    }

    private void appendLog(String line) {
        log.append(line + System.lineSeparator());
        log.setCaretPosition(log.getDocument().getLength());
    }
}
