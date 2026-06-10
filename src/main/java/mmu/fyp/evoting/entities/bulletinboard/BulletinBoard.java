package mmu.fyp.evoting.entities.bulletinboard;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Hash-chained, append-only, in-memory log. Replaces the "publicly readable storage" of Kho et al. §6.1. */
public final class BulletinBoard {

    public record Entry(int index, byte[] prevHash, BBEntry content, byte[] hash) {}

    private final List<Entry> entries = new ArrayList<>();
    private byte[] tip = new byte[32];

    public synchronized Entry append(BBEntry content) {
        byte[] entryHash = computeHash(tip, content);
        Entry e = new Entry(entries.size(), tip.clone(), content, entryHash);
        entries.add(e);
        tip = entryHash;
        return e;
    }

    public synchronized List<Entry> entries() {
        return List.copyOf(entries);
    }

    /**
     * Restoration entry point for the persistence layer: replays a sequence of
     * already-hashed entries into an empty bulletin board. The caller is
     * responsible for supplying entries with valid {@code prevHash}/{@code hash}
     * fields; {@link #verifyChain()} can be called after to confirm integrity.
     */
    public synchronized void restore(List<Entry> entriesIn) {
        if (!this.entries.isEmpty()) throw new IllegalStateException("BulletinBoard already populated");
        this.entries.addAll(entriesIn);
        if (!entriesIn.isEmpty()) this.tip = entriesIn.get(entriesIn.size() - 1).hash().clone();
    }

    public synchronized byte[] tipHash() {
        return tip.clone();
    }

    /** D2 view from FYP 2 Chapter 4 §4.7: all posted ballots in order. */
    public synchronized List<Ballot> ballots() {
        List<Ballot> out = new ArrayList<>();
        for (Entry e : entries) {
            if (e.content() instanceof Ballot b) out.add(b);
        }
        return List.copyOf(out);
    }

    /** D3 view from FYP 2 Chapter 4 §4.7: the published tally result, if any. */
    public synchronized Optional<TallyResult> result() {
        for (Entry e : entries) {
            if (e.content() instanceof TallyResult r) return Optional.of(r);
        }
        return Optional.empty();
    }

    /** Returns the vid notice posted at round 1, if any. */
    public synchronized Optional<VidNotice> vidNotice() {
        for (Entry e : entries) {
            if (e.content() instanceof VidNotice v) return Optional.of(v);
        }
        return Optional.empty();
    }

    public synchronized boolean verifyChain() {
        byte[] expected = new byte[32];
        for (Entry e : entries) {
            if (!Arrays.equals(expected, e.prevHash())) return false;
            byte[] computed = computeHash(expected, e.content());
            if (!Arrays.equals(computed, e.hash())) return false;
            expected = e.hash();
        }
        return Arrays.equals(expected, tip);
    }

    private static byte[] computeHash(byte[] prev, BBEntry content) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(prev);
            sha.update(content.encodeForHash());
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
