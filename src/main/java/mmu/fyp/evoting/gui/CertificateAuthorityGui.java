package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.crypto.group.Group;
import org.bouncycastle.math.ec.ECPoint;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Certificate Authority window. Covers every CA-side use case from FYP 2 Chapter 4 §4.4:
 * Register identity (approval side), Verify Eligibility, Get Voting Credentials, and
 * the tracing role from the M5/M8 design.
 */
public final class CertificateAuthorityGui extends JFrame {

    private final ElectionSystem system;

    private final DefaultTableModel pendingModel;
    private final DefaultTableModel registeredModel;
    private final DefaultTableModel historyModel;
    private final DefaultTableModel citizenRegistryModel;
    private final JTable pendingTable;

    /** Two-step approval workflow: Identify (check the citizen registry) → Approve. */
    private final JButton identifyBtn = new JButton("Identify");
    private final JButton approveBtn  = new JButton("Approve");
    private final JLabel  identifyResultLabel = new JLabel(" ");
    /** ICs that have been Identified as VALID against the citizen registry this session. */
    private final java.util.Set<String> identifiedValidIcs = new java.util.HashSet<>();

    private final JTextField traceLinkingTagField = new JTextField(28);
    private final JLabel traceResult = new JLabel(" ");
    private final JTextArea log = new JTextArea(10, 80);

    private final Timer refreshTimer;
    private String lastSignature = "";

    public CertificateAuthorityGui(ElectionSystem system) {
        super("Certificate Authority");
        this.system = system;

        this.pendingModel = new DefaultTableModel(
                new Object[]{"#", "Name", "IC", "Submitted at"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        this.registeredModel = new DefaultTableModel(
                new Object[]{"Position", "Name", "IC"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        this.historyModel = new DefaultTableModel(
                new Object[]{"Name", "IC", "Outcome", "Position"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        this.citizenRegistryModel = new DefaultTableModel(
                new Object[]{"#", "Name", "IC"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        this.pendingTable = new JTable(pendingModel);

        // Approve must be disabled until the selected row's IC has been Identified
        // as a valid citizen; selecting a new row re-evaluates that condition.
        pendingTable.getSelectionModel().addListSelectionListener(e -> updateActionButtonState());

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));

        add(buildHeader(), BorderLayout.NORTH);
        add(buildTabs(), BorderLayout.CENTER);
        add(buildLog(), BorderLayout.SOUTH);

        appendLog("[CA] window opened");
        appendLog("Use Cases: Register identity (approval side), Verify Eligibility, "
                + "Get Voting Credentials, Trace double-voters");
        appendLog("");
        refreshAll();

        // auto-refresh: new registration requests and approvals show up on their own
        refreshTimer = new Timer(750, e -> refreshAll());
        refreshTimer.start();
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosed(java.awt.event.WindowEvent e) { refreshTimer.stop(); }
        });

        pack();
        setSize(820, 640);
        setLocationRelativeTo(null);
    }

    private JComponent buildHeader() {
        JPanel p = new JPanel(new GridLayout(0, 1));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 0, 12));
        JLabel title = new JLabel("Certificate Authority");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        p.add(title);
        return p;
    }

    private JComponent buildTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Pending registration requests", buildPendingTab());
        tabs.addTab("Registered voters (D1)", buildRegisteredTab());
        tabs.addTab("Citizen registry", buildCitizenRegistryTab());
        tabs.addTab("Tracing", buildTracingTab());
        tabs.addTab("Registration history", buildHistoryTab());
        return tabs;
    }

    private JComponent buildCitizenRegistryTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("<html>National citizen registry — the pre-stored (name, IC) pairs the CA accepts as eligible voters.<br>"
                + "Registration requests must match an entry here. <i>Cross-check this against a pending request before clicking Approve.</i></html>"),
                BorderLayout.NORTH);
        p.add(new JScrollPane(new JTable(citizenRegistryModel)), BorderLayout.CENTER);

        // Populate once — the registry is fixed at startup.
        citizenRegistryModel.setRowCount(0);
        int i = 0;
        for (CitizenRecord c : system.citizenRegistry.all()) {
            citizenRegistryModel.addRow(new Object[]{i++, c.name(), c.displayIc()});
        }
        return p;
    }

    private JComponent buildPendingTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("<html>Voters waiting for the CA's decision. "
                + "<b>Step 1:</b> click <b>Identify</b> to verify the submission against the citizen registry. "
                + "<b>Step 2:</b> if VALID, click <b>Approve</b> to issue voting credentials.</html>"),
                BorderLayout.NORTH);
        p.add(new JScrollPane(pendingTable), BorderLayout.CENTER);

        JPanel actions = new JPanel();
        actions.setLayout(new BoxLayout(actions, BoxLayout.Y_AXIS));

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        identifyBtn.addActionListener(e -> onIdentify());
        approveBtn.addActionListener(e -> onApprove());
        approveBtn.setEnabled(false);          // disabled until Identify says VALID
        identifyBtn.setEnabled(false);          // disabled until a pending row is selected
        buttonRow.add(identifyBtn);
        buttonRow.add(approveBtn);
        actions.add(buttonRow);

        identifyResultLabel.setBorder(BorderFactory.createEmptyBorder(2, 12, 8, 12));
        actions.add(identifyResultLabel);

        p.add(actions, BorderLayout.SOUTH);
        return p;
    }

    private JComponent buildRegisteredTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("D1 ID database — voters that the CA has approved:"), BorderLayout.NORTH);
        p.add(new JScrollPane(new JTable(registeredModel)), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildTracingTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        JPanel form = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        form.add(new JLabel("Linking tag (hex, compressed EC point):"));
        form.add(traceLinkingTagField);
        JButton traceBtn = new JButton("Trace");
        form.add(traceBtn);
        p.add(form, BorderLayout.NORTH);

        traceResult.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(traceResult, BorderLayout.CENTER);

        JTextArea help = new JTextArea(
                "After the tally is run, double-voted ballots produce identical linking tags.\n"
                        + "Paste a linking tag here to ask the CA to identify the offender by\n"
                        + "recomputing the EOLTAA linking tag  usk_i · H_eid(vid)  for every registered voter.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setFont(help.getFont().deriveFont(Font.ITALIC, 12f));
        help.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(help, BorderLayout.SOUTH);

        traceBtn.addActionListener(e -> onTrace());
        return p;
    }

    private JComponent buildHistoryTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        p.add(new JLabel("Every registration outcome the CA has produced this session:"),
                BorderLayout.NORTH);
        p.add(new JScrollPane(new JTable(historyModel)), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildLog() {
        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(log);
        scroll.setBorder(BorderFactory.createTitledBorder("Log"));
        return scroll;
    }

    // ---------- actions ----------

    /**
     * Step 1 of the CA's approval workflow: verify the selected pending request
     * against the citizen registry. This is informational only — it doesn't change
     * any election state, but it gates the Approve button so credentials are never
     * issued before the operator has confirmed the (name, IC) is a known citizen.
     */
    private void onIdentify() {
        int row = pendingTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Select a pending request first.",
                    "Nothing selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        var pending = system.pendingRegistrations();
        if (row >= pending.size()) return;
        var p = pending.get(row);
        var hit = system.citizenRegistry.verify(p.name(), p.icNumber());
        if (hit.isPresent()) {
            identifiedValidIcs.add(p.icNumber());
            identifyResultLabel.setForeground(new Color(0x0a8a3a));
            identifyResultLabel.setText("<html><b>VALID</b> &mdash; " + p.displayLabel()
                    + " matches the citizen registry. You may now click Approve to issue credentials.</html>");
            appendLog("[CA] IDENTIFY " + p.displayLabel() + " → VALID (matched in citizen registry)");
        } else {
            identifiedValidIcs.remove(p.icNumber());
            identifyResultLabel.setForeground(Color.RED);
            identifyResultLabel.setText("<html><b>INVALID</b> &mdash; " + p.displayLabel()
                    + " does NOT match any citizen in the registry. Approve remains disabled for this request.</html>");
            appendLog("[CA] IDENTIFY " + p.displayLabel() + " → INVALID (no match in citizen registry)");
        }
        updateActionButtonState();
    }

    /**
     * Step 2 of the CA's approval workflow: issue voting credentials. Will not
     * proceed unless the selected row's IC has been Identified as VALID this session.
     */
    private void onApprove() {
        int row = pendingTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Select a pending request first.",
                    "Nothing selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        var pending = system.pendingRegistrations();
        if (row >= pending.size()) return;
        String ic = pending.get(row).icNumber();
        if (!identifiedValidIcs.contains(ic)) {
            JOptionPane.showMessageDialog(this,
                    "Please click Identify first to verify the request against the citizen registry.",
                    "Identify required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        var outcome = system.approve(row);
        if (outcome.approved()) {
            // Register step 5 (Kho et al. 2025 §6.1): CA runs Φ.CertGen(MSK, upk)
            // and hands the resulting Cert to the voter.
            var voter = outcome.voter();
            var cert = voter.certificate();
            appendLog("[CA] APPROVED " + outcome.displayLabel());
            appendLog("  → Φ.CertGen(MSK, voter.upk) → Cert");
            appendLog("       upk = " + truncHex(voter.upk().Y()));
            appendLog("       Cert.R = " + truncHex(cert.R()));
            appendLog("       Cert.s = " + truncScalar(cert.s()));
            appendLog("  → Cert handed to " + outcome.name() + "; voter stored at D1 position "
                    + outcome.directoryPosition());
        } else {
            appendLog("[CA] approval auto-rejected for " + outcome.displayLabel()
                    + ": " + outcome.status());
        }
        // The request is no longer pending; drop the cached identify result and clear the label.
        identifiedValidIcs.remove(ic);
        identifyResultLabel.setText(" ");
        refreshAll();
        updateActionButtonState();
    }

    /**
     * Refresh the enabled state of Identify / Approve based on (a) whether a row is
     * selected and (b) whether that row's IC has been identified as VALID.
     */
    private void updateActionButtonState() {
        int row = pendingTable.getSelectedRow();
        if (row < 0 || row >= pendingModel.getRowCount()) {
            identifyBtn.setEnabled(false);
            approveBtn.setEnabled(false);
            return;
        }
        identifyBtn.setEnabled(true);
        // pendingModel column 2 holds the display-format IC ("890101-01-1234"); normalise
        // before checking membership in identifiedValidIcs (which holds digits-only form).
        String displayedIc = String.valueOf(pendingModel.getValueAt(row, 2));
        String normIc = CitizenRecord.normaliseIc(displayedIc);
        approveBtn.setEnabled(identifiedValidIcs.contains(normIc));
    }

    private void onTrace() {
        String hex = traceLinkingTagField.getText().trim();
        if (hex.isEmpty()) {
            traceResult.setText("Enter a linking tag in hex first.");
            return;
        }
        ECPoint tag;
        try {
            tag = Group.decode(HexFormat.of().parseHex(hex));
        } catch (Exception ex) {
            traceResult.setText("Invalid hex / not an EC point: " + ex.getMessage());
            return;
        }
        Optional<String> identity = system.ca.trace(tag, system.vidNotice.vid());
        if (identity.isPresent()) {
            traceResult.setText("Traced to voter: " + identity.get());
            appendLog("[CA] trace(linkingTag) → " + identity.get());
        } else {
            traceResult.setText("No registered voter matches this linking tag.");
            appendLog("[CA] trace(linkingTag) → no match");
        }
    }

    private void refreshAll() {
        var pending = system.pendingRegistrations();
        String signature = pending.stream().map(PendingRegistration::icNumber).toList()
                + "|reg=" + system.ca.registeredVoterCount()
                + "|hist=" + system.registrationHistory().size();
        if (signature.equals(lastSignature)) return;
        lastSignature = signature;

        // remember which pending IC is selected so auto-refresh doesn't drop it
        String selectedIc = null;
        int sel = pendingTable.getSelectedRow();
        if (sel >= 0 && sel < pendingModel.getRowCount()) {
            selectedIc = String.valueOf(pendingModel.getValueAt(sel, 2));
        }

        pendingModel.setRowCount(0);
        for (int i = 0; i < pending.size(); i++) {
            var p = pending.get(i);
            pendingModel.addRow(new Object[]{
                    i, p.name(),
                    new CitizenRecord(p.name(), p.icNumber()).displayIc(),
                    new java.util.Date(p.submittedAt())});
        }
        if (selectedIc != null) {
            for (int r = 0; r < pendingModel.getRowCount(); r++) {
                if (selectedIc.equals(String.valueOf(pendingModel.getValueAt(r, 2)))) {
                    pendingTable.setRowSelectionInterval(r, r);
                    break;
                }
            }
        }

        registeredModel.setRowCount(0);
        var directory = system.ca.directory();
        for (int i = 0; i < directory.size(); i++) {
            for (String ic : system.ca.registeredIdentities()) {
                if (system.ca.positionOf(ic) == i) {
                    String name = system.nameOf(ic);
                    registeredModel.addRow(new Object[]{
                            i,
                            name != null ? name : "—",
                            new CitizenRecord(name != null ? name : "?", ic).displayIc()});
                    break;
                }
            }
        }

        historyModel.setRowCount(0);
        for (var o : system.registrationHistory()) {
            historyModel.addRow(new Object[]{
                    o.name(),
                    new CitizenRecord(o.name(), o.icNumber()).displayIc(),
                    o.approved() ? "approved" : o.status(),
                    o.directoryPosition() >= 0 ? o.directoryPosition() : "—"
            });
        }

        // After table rebuild, re-evaluate Identify / Approve button enabled state
        // based on the (possibly new) selection.
        updateActionButtonState();
    }

    private void appendLog(String line) {
        log.append(line + System.lineSeparator());
        log.setCaretPosition(log.getDocument().getLength());
    }

    private static String truncHex(ECPoint p) {
        byte[] enc = Group.encode(p);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, enc.length); i++) sb.append(String.format("%02x", enc[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }

    private static String truncScalar(BigInteger s) {
        byte[] b = s.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(16, b.length); i++) sb.append(String.format("%02x", b[i] & 0xff));
        sb.append("...");
        return sb.toString();
    }
}
