package mmu.fyp.evoting.gui;

import java.util.Objects;

/**
 * A pre-stored citizen entry that the CA consults at registration time.
 *
 * <p>The CA's citizen registry models the real-world identity database that a
 * national EC would query (e.g., the National Registration Department in
 * Malaysia). Voters submit (name, icNumber) at registration; the CA verifies
 * the pair against this registry before approving. The pair is held by the CA
 * only — it never appears in the EOLTAA directory, in a ballot, or on the bulletin
 * board, so the voter's real identity stays decoupled from their vote
 * (Finogina &amp; Herranz 2023, anonymity property; Li, Lai, Wu 2021 EOLTAA
 * §1, traceable but anonymous authentication).
 *
 * @param name     full name as held by the issuing authority
 * @param icNumber Malaysian identity card number, normalised to digits only
 *                 (dashes stripped) so "890101-01-1234" and "890101011234"
 *                 compare equal.
 */
public record CitizenRecord(String name, String icNumber) {

    public CitizenRecord {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(icNumber, "icNumber");
        name = name.trim();
        icNumber = normaliseIc(icNumber);
        if (name.isEmpty()) throw new IllegalArgumentException("name must not be blank");
        if (icNumber.isEmpty()) throw new IllegalArgumentException("icNumber must not be blank");
    }

    /** Strip dashes/spaces so comparisons are format-agnostic. */
    public static String normaliseIc(String ic) {
        return ic.replace("-", "").replace(" ", "").trim();
    }

    /** Format an IC for display: YYMMDD-PB-XXXX. */
    public String displayIc() {
        if (icNumber.length() == 12) {
            return icNumber.substring(0, 6) + "-" + icNumber.substring(6, 8)
                    + "-" + icNumber.substring(8, 12);
        }
        return icNumber;
    }
}
