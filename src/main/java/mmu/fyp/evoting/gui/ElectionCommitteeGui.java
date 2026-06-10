package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.crypto.group.Group;
import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.bulletinboard.TallyResult;
import mmu.fyp.evoting.entities.bulletinboard.VidNotice;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

/**
 * Election Committee window. Covers every EC-side use case from FYP 2 Chapter 4 §4.4:
 * Encrypt Vote (handled inside the Vote protocol), Submit Ballot (storage on BB),
 * Collect ballot (view D2), Collect And Count (run tally), Publish Results.
 */
public final class ElectionCommitteeGui extends JFrame {

    private final ElectionSystem system;
    private final String[] candidateNames;

    private final JLabel statusLine;
    private final JButton openVotingButton = new JButton("Open Voting");
    private final JButton tallyButton = new JButton("Collect And Count (Run Tally)");
    private final DefaultTableModel bbModel;
    private final DefaultTableModel directoryModel;
    private final JTextArea log = new JTextArea(10, 80);

    private final Timer refreshTimer;
    private String lastSignature = "";

    public ElectionCommitteeGui(ElectionSystem system, String[] candidateNames) {
        super("Election Committee");
        this.system = system;
        this.candidateNames = candidateNames;
        this.statusLine = new JLabel(" ");
        this.bbModel = new DefaultTableModel(new Object[]{"#", "Type", "Summary"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        this.directoryModel = new DefaultTableModel(new Object[]{"Position", "EOLTAA user public key (truncated)"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));

        add(buildHeader(), BorderLayout.NORTH);
        add(buildTabs(), BorderLayout.CENTER);
        add(buildLog(), BorderLayout.SOUTH);

        openVotingButton.addActionListener(e -> onOpenVoting());
        tallyButton.addActionListener(e -> onRunTally());

        appendLog("[EC] window opened");
        appendLog("Use Cases: Encrypt Vote, Submit Ballot (BB storage), Collect ballot, "
                + "Collect And Count, Publish Results");
        appendLog("");
        refreshAll();

        // auto-refresh: ballots landing on the BB and registration counts update on their own
        refreshTimer = new Timer(750, e -> refreshAll());
        refreshTimer.start();
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosed(java.awt.event.WindowEvent e) { refreshTimer.stop(); }
        });

        pack();
        setSize(880, 640);
        setLocationRelativeTo(null);
    }

    private JComponent buildHeader() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 0, 12));
        JLabel title = new JLabel("Election Committee");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        p.add(title, BorderLayout.WEST);
        statusLine.setHorizontalAlignment(SwingConstants.RIGHT);
        p.add(statusLine, BorderLayout.EAST);
        return p;
    }

    private JComponent buildTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Actions", buildActionsTab());
        tabs.addTab("Bulletin Board", buildBbTab());
        tabs.addTab("Voter directory", buildDirectoryTab());
        tabs.addTab("EC public keys", buildKeysTab());
        return tabs;
    }

    private JComponent buildActionsTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));

        JPanel actions = new JPanel(new BorderLayout(8, 8));
        actions.setBorder(BorderFactory.createTitledBorder("Election lifecycle"));

        // Description goes north and takes its natural height; buttons go south
        // in a stack so they never get stretched by a GridLayout to match the
        // tall description label.
        JLabel description = new JLabel("<html>"
                + "<b>Register phase</b> already completed at startup (Kho 2025 §6.1):<br>"
                + "&nbsp;&nbsp;Step 1: EC ran MS.Setup + Commitment.Setup → ParamNotice on BB<br>"
                + "&nbsp;&nbsp;Step 2: CA ran Φ.CSetup → (MPK, MSK)<br>"
                + "&nbsp;&nbsp;Step 3: EC ran PKE.KeyGen → (pke, ske)<br>"
                + "&nbsp;&nbsp;Step 4: EC ran Φ.UKeyGen → (pk_T, sk_T)  (voters do step 4 themselves)<br>"
                + "&nbsp;&nbsp;Step 5: CA issued Cert_T via Φ.CertGen<br><br>"
                + "<b>1. Open Voting</b> — locks the voter directory (EOLTAA anonymity set), then EC posts vid notice.<br>"
                + "<b>2. Voters cast ballots</b> in their own windows (6-round Vote protocol).<br>"
                + "<b>3. Collect And Count (Run Tally)</b> — 6-step Tally protocol ending with π_result NIZK on D3."
                + "</html>");
        description.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        actions.add(description, BorderLayout.NORTH);

        // Buttons stacked at fixed height so both stay visible no matter how
        // tall the description label is.
        JPanel buttonStack = new JPanel();
        buttonStack.setLayout(new BoxLayout(buttonStack, BoxLayout.Y_AXIS));
        buttonStack.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
        openVotingButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        tallyButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Keep the buttons at their preferred height — never let the layout
        // stretch them to consume the rest of the panel.
        openVotingButton.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                openVotingButton.getPreferredSize().height));
        tallyButton.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                tallyButton.getPreferredSize().height));
        buttonStack.add(openVotingButton);
        buttonStack.add(Box.createVerticalStrut(6));
        buttonStack.add(tallyButton);
        actions.add(buttonStack, BorderLayout.CENTER);

        p.add(actions, BorderLayout.NORTH);
        return p;
    }

    private JComponent buildBbTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("Bulletin board entries (hash-chained, append-only):"),
                BorderLayout.NORTH);
        p.add(new JScrollPane(new JTable(bbModel)), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildDirectoryTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("<html>Voter directory — the EOLTAA anonymity set the EC uses to verify ballots.<br>"
                + "<i>Locked when 'Open Voting' was clicked; every ballot's Σ-OR proof is checked against this list.</i></html>"),
                BorderLayout.NORTH);
        p.add(new JScrollPane(new JTable(directoryModel)), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildKeysTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        JTextArea keys = new JTextArea();
        keys.setEditable(false);
        keys.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        keys.append("EOLTAA EC user public key (signs the vid notice π_T)\n");
        keys.append("  upk:  " + truncHex(system.ec.upk().Y()) + "\n");
        keys.append("  cert: R=" + truncHex(system.ec.certificate().R())
                + "  s=" + truncScalar(system.ec.certificate().s()) + "\n\n");

        int n = system.ec.musigKeyPairs().size();
        keys.append("MuSig2 EC committee (signs σ on every ballot ciphertext Ci)\n");
        keys.append("  scheme: Nick-Ruffing-Seurin (2021) / BIP 327, n = " + n + " members\n");
        for (int i = 0; i < n; i++) {
            keys.append(String.format("  member %d: X_%d = %s%n",
                    i + 1, i + 1, truncHex(system.ec.musigKeyPairs().get(i).pk().X())));
        }
        keys.append("  aggregate X̃ = Σ a_i·X_i = " + truncHex(system.ec.aggregateSigningKey().X_tilde()) + "\n");
        keys.append("  (verifiers check σ against X̃ as an ordinary Schnorr signature)\n\n");

        keys.append("Cramer-Shoup public key (IND-CCA2 encrypts every vote)\n");
        keys.append("  g2: " + truncHex(system.ec.encryptionPk().g2()) + "\n");
        keys.append("  c : " + truncHex(system.ec.encryptionPk().c())  + "\n");
        keys.append("  d : " + truncHex(system.ec.encryptionPk().d())  + "\n");
        keys.append("  h : " + truncHex(system.ec.encryptionPk().h())  + "\n");
        p.add(new JScrollPane(keys), BorderLayout.CENTER);
        return p;
    }

    private static String truncScalar(BigInteger s) {
        byte[] b = s.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, b.length); i++) sb.append(String.format("%02x", b[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private JComponent buildLog() {
        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(log);
        scroll.setBorder(BorderFactory.createTitledBorder("Log"));
        return scroll;
    }

    // ---------- actions ----------

    private void onOpenVoting() {
        if (system.votingOpen()) {
            appendLog("[EC] voting is already open");
            return;
        }
        int registered = system.ca.registeredVoterCount();
        int pending = system.pendingRegistrations().size();

        StringBuilder msg = new StringBuilder("<html>");
        msg.append("<b>You are about to OPEN VOTING.</b><br><br>");
        msg.append("This will <b>permanently lock the voter directory at ")
           .append(registered).append(" voter(s)</b>.<br><br>");
        msg.append("Once voting opens:<br>");
        msg.append("&nbsp;&nbsp;&bull; No new voters can register or be added<br>");
        msg.append("&nbsp;&nbsp;&bull; The directory is fixed for the rest of this election<br>");
        msg.append("&nbsp;&nbsp;<i>(EOLTAA anonymous authentication requires an identical voter directory at sign &amp; verify time)</i><br><br>");
        if (pending > 0) {
            msg.append("<font color='red'><b>&#9888; ").append(pending)
               .append(" registration request(s) are still pending CA review.</b></font><br>");
            msg.append("Approve or reject them in the CA window first, or they will be lost.<br><br>");
        }
        if (registered == 0) {
            msg.append("<font color='red'><b>&#9888; No voters are registered.</b></font> ");
            msg.append("The election will have no valid ballots.<br><br>");
        }
        msg.append("Continue?</html>");

        int proceed = JOptionPane.showConfirmDialog(this, msg.toString(),
                "Open voting — final confirmation",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (proceed != JOptionPane.YES_OPTION) {
            appendLog("[EC] open voting cancelled by operator");
            return;
        }
        system.openVoting();
        appendLog("[EC] opened voting; voter directory locked at size " + system.ca.directory().size());
        refreshAll();
    }

    private void onRunTally() {
        if (!system.votingOpen()) {
            appendLog("[EC] cannot tally — voting was never opened");
            return;
        }
        appendLog("[EC] === Tally protocol (Kho et al. 2025 §6.1, 6-step flow) ===");
        appendLog("  Step 1: verify Φ.Verify(C_i, π_i) for every ballot — drop invalid");
        appendLog("  Step 2: Φ.Link — group remaining ballots by linking tag");
        appendLog("  Step 3: Φ.Trace — CA recovers identity of every double-voter");
        appendLog("  Step 4: Cramer-Shoup.Decrypt each non-duplicate ballot");
        appendLog("  Step 5: count plaintexts per candidate");
        appendLog("  Step 6: build π_result Σ-DLEq NIZK, post (result, π_result) to D3");
        TallyResult result = system.runTally();
        appendLog("[EC] tally complete; result posted to D3");
        for (Map.Entry<Integer, Integer> e : result.counts().entrySet()) {
            appendLog("  candidate " + e.getKey() + " ("
                    + candidateNames[e.getKey() - 1] + "): " + e.getValue() + " vote(s)");
        }
        for (int v = 1; v <= system.candidateCount(); v++) {
            if (!result.counts().containsKey(v)) {
                appendLog("  candidate " + v + " ("
                        + candidateNames[v - 1] + "): 0 vote(s)");
            }
        }
        if (!result.tracedDoubleVoters().isEmpty()) {
            appendLog("  traced double voters: " + result.tracedDoubleVoters());
        }
        appendLog("  π_result NIZK attached (" + result.decryptions().size()
                + " decryption record(s)); any party can verify with EC's public key");
        appendLog("  BB hash chain verifies: " + system.bb.verifyChain());
        tallyButton.setEnabled(false);
        refreshAll();
    }

    private void refreshAll() {
        String signature = system.votingOpen()
                + "|reg=" + system.ca.registeredVoterCount()
                + "|ballots=" + system.bb.ballots().size()
                + "|result=" + system.bb.result().isPresent()
                + "|dir=" + (system.ec.directory() == null ? 0 : system.ec.directory().size());
        if (signature.equals(lastSignature)) return;
        lastSignature = signature;

        statusLine.setText(String.format(
                "Voting %s | Registered: %d | Ballots: %d | Result: %s",
                system.votingOpen() ? "OPEN" : "CLOSED",
                system.ca.registeredVoterCount(),
                system.bb.ballots().size(),
                system.bb.result().isPresent() ? "PUBLISHED" : "—"));

        openVotingButton.setEnabled(!system.votingOpen());
        tallyButton.setEnabled(system.votingOpen() && system.bb.result().isEmpty());

        // BB table
        bbModel.setRowCount(0);
        int i = 0;
        for (var entry : system.bb.entries()) {
            String type;
            String summary;
            if (entry.content() instanceof mmu.fyp.evoting.entities.bulletinboard.ParamNotice p) {
                type = "ParamNotice";
                summary = "group=" + p.groupName() + ", musig=" + p.musigScheme() + ", pke=" + p.pkeScheme();
            } else if (entry.content() instanceof VidNotice v) {
                type = "VidNotice";
                summary = "vid=" + HexFormat.of().formatHex(v.vid()).substring(0, 16) + "...";
            } else if (entry.content() instanceof Ballot b) {
                type = "Ballot";
                summary = "linkTag=" + truncHex(b.voterAuth().linkingTag());
            } else if (entry.content() instanceof TallyResult r) {
                type = "TallyResult";
                summary = "counts=" + r.counts() + ", traced=" + r.tracedDoubleVoters();
            } else {
                type = entry.content().getClass().getSimpleName();
                summary = "";
            }
            bbModel.addRow(new Object[]{i++, type, summary});
        }

        // Directory table
        directoryModel.setRowCount(0);
        var directory = system.ec.directory() == null
                ? java.util.List.<mmu.fyp.evoting.crypto.eoltaa.EOLTAA.UserPublicKey>of()
                : system.ec.directory();
        for (int idx = 0; idx < directory.size(); idx++) {
            directoryModel.addRow(new Object[]{idx, truncHex(directory.get(idx).Y())});
        }
    }

    private static String truncHex(org.bouncycastle.math.ec.ECPoint p) {
        byte[] enc = Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private void appendLog(String line) {
        log.append(line + System.lineSeparator());
        log.setCaretPosition(log.getDocument().getLength());
    }
}
