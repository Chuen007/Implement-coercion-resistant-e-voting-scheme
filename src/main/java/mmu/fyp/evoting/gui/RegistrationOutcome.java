package mmu.fyp.evoting.gui;

import mmu.fyp.evoting.entities.voter.Voter;

/**
 * Outcome of a registration decision by the CA.
 *
 * @param name         voter's declared name (from the original submission)
 * @param icNumber     voter's declared IC number (normalised, no dashes)
 * @param directoryPosition allocated position in the EOLTAA voter directory on approval,
 *                     or -1 if rejected
 * @param status       human-readable status — "approved", "rejected: …",
 *                     "not in citizen registry", "voting open — registration closed", etc.
 * @param voter        constructed {@link Voter} on approval, null on rejection
 */
public record RegistrationOutcome(
        String name,
        String icNumber,
        int directoryPosition,
        String status,
        Voter voter) {

    public boolean approved() { return voter != null; }

    /** The unique identifier used inside the CA registry. We use the IC number. */
    public String identity() { return icNumber; }

    /** "Name (IC: 890101-01-1234)" — for log lines and table cells. */
    public String displayLabel() {
        return name + " (IC: " + new CitizenRecord(name, icNumber).displayIc() + ")";
    }
}
