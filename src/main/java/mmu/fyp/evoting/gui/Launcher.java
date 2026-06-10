package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.persistence.H2PersistenceStore;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.HexFormat;

/**
 * Main launcher window. Presents three role buttons matching the three actors in
 * the FYP 2 Chapter 4 §4.4 use case diagram. Each button opens the corresponding
 * sub-window over the same shared {@link ElectionSystem} instance, so all three
 * windows see and act on the same election state.
 *
 * <p>Persistence: the launcher opens an embedded H2 database under the project
 * root at {@code <project-root>/db/election} (override with {@code -Dfyp.db.path=...})
 * and passes it to the ElectionSystem. All state survives launcher restarts.
 * Falls back to in-memory if the DB cannot be opened.
 */
public final class Launcher extends JFrame {

    private final ElectionSystem system;
    private final H2PersistenceStore store;   // null if persistence disabled
    private final JLabel statusLine;

    private static final String[] CANDIDATE_NAMES = {"Alice", "Bob", "Carol"};

    public Launcher() {
        super("Coercion-Resistant E-Voting — Launcher");

        // Try to open the H2 file-backed store. On any failure, log to stderr and
        // continue in-memory so a broken filesystem can't prevent the demo running.
        H2PersistenceStore openedStore = null;
        try {
            openedStore = new H2PersistenceStore(H2PersistenceStore.resolveDefaultDbPath());
        } catch (SQLException | IOException ex) {
            System.err.println("[Launcher] failed to open H2 store, falling back to in-memory: " + ex);
        }
        this.store = openedStore;

        this.system = (store != null)
                ? new ElectionSystem(CANDIDATE_NAMES.length, store)
                : new ElectionSystem(CANDIDATE_NAMES.length);

        this.statusLine = new JLabel(statusText(), SwingConstants.CENTER);

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout(12, 12));

        add(buildHeader(), BorderLayout.NORTH);
        add(buildRoleButtons(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        // auto-refresh the at-a-glance status bar from the shared ElectionSystem
        Timer statusTimer = new Timer(750, e -> statusLine.setText(statusText()));
        statusTimer.start();

        // Cleanly close the DB connection on shutdown so the .mv.db file is
        // flushed and not corrupted.
        if (store != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { store.close(); } catch (SQLException ignored) {}
            }, "h2-store-shutdown"));
        }

        pack();
        setLocationRelativeTo(null);
    }

    private JComponent buildHeader() {
        JPanel p = new JPanel(new GridLayout(0, 1));
        p.setBorder(BorderFactory.createEmptyBorder(16, 24, 8, 24));
        JLabel title = new JLabel("Coercion-Resistant E-Voting System", SwingConstants.CENTER);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));
        p.add(title);
        JLabel sub = new JLabel("Choose your role", SwingConstants.CENTER);
        sub.setFont(sub.getFont().deriveFont(Font.ITALIC, 13f));
        p.add(sub);
        JLabel vid = new JLabel("Election ID: " + HexFormat.of().formatHex(system.vidNotice.vid()),
                SwingConstants.CENTER);
        vid.setForeground(Color.DARK_GRAY);
        p.add(vid);
        JLabel candidates = new JLabel("Candidates: " + describeCandidates(), SwingConstants.CENTER);
        candidates.setForeground(Color.DARK_GRAY);
        p.add(candidates);
        JLabel dbStatus = new JLabel(dbStatusText(), SwingConstants.CENTER);
        dbStatus.setForeground(store != null ? new Color(0x0a5a2a) : new Color(0x8a4a00));
        dbStatus.setFont(dbStatus.getFont().deriveFont(Font.ITALIC, 11f));
        p.add(dbStatus);
        return p;
    }

    private String dbStatusText() {
        if (store == null) return "Persistence: OFF (in-memory only — state lost on close)";
        return "Persistence: ON  ·  DB: " + store.dbPath().toAbsolutePath() + ".mv.db"
                + "  ·  fresh election on every startup (citizen registry preserved)";
    }

    private JComponent buildRoleButtons() {
        JPanel p = new JPanel(new GridLayout(1, 3, 16, 16));
        p.setBorder(BorderFactory.createEmptyBorder(8, 24, 8, 24));

        p.add(roleButton("Voter",
                "Register, vote, verify, fake transcripts, check result.",
                new Color(220, 235, 250),
                e -> openVoter()));

        p.add(roleButton("Certificate Authority",
                "Approve/reject registration requests, view D1, trace double-voters.",
                new Color(220, 250, 230),
                e -> openCa()));

        p.add(roleButton("Election Committee",
                "Open voting, watch the bulletin board, run tally, publish results.",
                new Color(255, 240, 220),
                e -> openEc()));

        return p;
    }

    private JButton roleButton(String title, String subtitle, Color background, java.awt.event.ActionListener onClick) {
        JButton b = new JButton("<html><div style='text-align:center;'>"
                + "<b style='font-size:14px;'>" + title + "</b><br>"
                + "<span style='font-size:11px;'>" + subtitle + "</span>"
                + "</div></html>");
        b.setPreferredSize(new Dimension(280, 140));
        b.setBackground(background);
        b.setFocusPainted(false);
        b.addActionListener(onClick);
        return b;
    }

    private JComponent buildStatusBar() {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(6, 12, 6, 12)));
        statusLine.setForeground(Color.DARK_GRAY);
        p.add(statusLine, BorderLayout.CENTER);

        if (store != null) {
            JButton resetBtn = new JButton("Reset election (wipe DB)");
            resetBtn.setForeground(new Color(0x8a0a0a));
            resetBtn.addActionListener(e -> onResetElection());
            p.add(resetBtn, BorderLayout.EAST);
        }
        return p;
    }

    private void onResetElection() {
        int proceed = JOptionPane.showConfirmDialog(this,
                "<html>This will <b>permanently wipe all election data</b> in the database:<br>"
              + "&bull; registered voters (D1)<br>"
              + "&bull; pending requests + outcomes<br>"
              + "&bull; bulletin board entries (D2 + D3)<br>"
              + "&bull; EC keypairs and vid<br><br>"
              + "The citizen registry is preserved.<br><br>"
              + "After reset, the launcher will exit. <b>Restart it</b> to start a fresh election.<br><br>"
              + "Continue?</html>",
                "Reset election — final confirmation",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (proceed != JOptionPane.YES_OPTION) return;
        try {
            store.reset();
            store.close();
        } catch (SQLException ex) {
            JOptionPane.showMessageDialog(this, "Reset failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        JOptionPane.showMessageDialog(this,
                "Election data wiped. The launcher will now exit — restart it to begin afresh.",
                "Reset complete", JOptionPane.INFORMATION_MESSAGE);
        System.exit(0);
    }

    private String statusText() {
        return String.format("Pending: %d | Registered: %d | Voting %s | Ballots: %d | Result: %s",
                system.pendingRegistrations().size(),
                system.ca.registeredVoterCount(),
                system.votingOpen() ? "OPEN" : "CLOSED",
                system.bb.ballots().size(),
                system.bb.result().isPresent() ? "PUBLISHED" : "—");
    }

    // ---------- window openers ----------

    private void openVoter() {
        JTextField nameField = new JTextField(24);
        JTextField icField   = new JTextField(20);
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        form.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        form.add(new JLabel("Full name:"));
        form.add(nameField);
        form.add(new JLabel("IC number (12 digits, dashes optional):"));
        form.add(icField);

        JLabel hint = new JLabel(
                "<html><i>Enter your real-world identity. The CA will verify it<br>"
              + "against its citizen registry before approving your request.<br>"
              + "Your (name, IC) is held only by the CA — it never appears on<br>"
              + "your ballot, the EOLTAA voter directory, or the bulletin board.</i></html>");
        hint.setForeground(Color.DARK_GRAY);

        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(form, BorderLayout.CENTER);
        panel.add(hint, BorderLayout.SOUTH);

        int ok = JOptionPane.showConfirmDialog(this, panel,
                "Voter login — enter your identity",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        String name = nameField.getText().trim();
        String ic   = icField.getText().trim();
        if (name.isEmpty() || ic.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Both name and IC number are required.",
                    "Missing fields", JOptionPane.WARNING_MESSAGE);
            return;
        }
        VoterGui w = new VoterGui(system, name, ic, CANDIDATE_NAMES);
        w.setVisible(true);
        statusLine.setText(statusText());
    }

    private void openCa() {
        CertificateAuthorityGui w = new CertificateAuthorityGui(system);
        w.setVisible(true);
        statusLine.setText(statusText());
    }

    private void openEc() {
        ElectionCommitteeGui w = new ElectionCommitteeGui(system, CANDIDATE_NAMES);
        w.setVisible(true);
        statusLine.setText(statusText());
    }

    private String describeCandidates() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < CANDIDATE_NAMES.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(i + 1).append("=").append(CANDIDATE_NAMES[i]);
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}
        SwingUtilities.invokeLater(() -> new Launcher().setVisible(true));
    }
}
