package mmu.fyp.evoting.gui;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The CA's citizen-identity database. Holds the (name, IC) pairs the CA will
 * accept as eligible voters. A registration request that does not match an
 * entry here is rejected by the CA — modelling the "verify identity against
 * national registry" step requested in the FYP 2 Chapter 4 §4.4 registration
 * use case.
 *
 * <p>The registry is consulted only by the CA. Voters never see the registry,
 * the EC never sees voter names or IC numbers, and the bulletin board only
 * holds anonymous EOLTAA authentication tokens — so the (name, IC) → directory-position
 * mapping is private to the CA, preserving the anonymity property described in
 * Finogina &amp; Herranz (2023) §3.3 and Li, Lai, Wu (2021).
 *
 * <p>For the prototype demo we seed the registry with eight plausible
 * Malaysian citizens via {@link #defaultSeeded()}; in production this would
 * be a network lookup against the national registration system.
 */
public final class CitizenRegistry {

    private final Map<String, CitizenRecord> byIc;

    public CitizenRegistry(List<CitizenRecord> citizens) {
        Map<String, CitizenRecord> m = new LinkedHashMap<>();
        for (CitizenRecord c : citizens) {
            m.put(c.icNumber(), c);
        }
        this.byIc = m;
    }

    /**
     * Verify a registration submission against the registry. The IC is the
     * primary key; the name must also match (case-insensitive, whitespace
     * trimmed). Returns the matching {@link CitizenRecord} on success.
     */
    public Optional<CitizenRecord> verify(String name, String icNumber) {
        if (name == null || icNumber == null) return Optional.empty();
        String normIc = CitizenRecord.normaliseIc(icNumber);
        CitizenRecord c = byIc.get(normIc);
        if (c == null) return Optional.empty();
        if (!c.name().equalsIgnoreCase(name.trim())) return Optional.empty();
        return Optional.of(c);
    }

    /** Public read-only view for the CA GUI to display. */
    public List<CitizenRecord> all() {
        return List.copyOf(byIc.values());
    }

    public int size() {
        return byIc.size();
    }

    /**
     * Eight seeded entries representing a plausible Malaysian electorate.
     * Convenient defaults for the GUI demo; the registry can also be
     * constructed with a custom citizen list for tests or larger demos.
     */
    public static CitizenRegistry defaultSeeded() {
        return new CitizenRegistry(List.of(
                new CitizenRecord("Tan Ah Kow",      "890101-01-1234"),
                new CitizenRecord("Lim Mei Ling",    "900215-02-2345"),
                new CitizenRecord("Muthu Krishnan",  "850330-03-3456"),
                new CitizenRecord("Siti Nor Binti",  "920614-04-4567"),
                new CitizenRecord("Wong Chee Kiat",  "880822-05-5678"),
                new CitizenRecord("Ahmad bin Yusof", "870909-06-6789"),
                new CitizenRecord("Kavita Devi",     "911111-07-7890"),
                new CitizenRecord("Lee Kah Hong",    "931226-08-8901")
        ));
    }
}
