package mmu.fyp.evoting.entities.bulletinboard;

/** Tagged content type for the bulletin board. Sealed so the hash chain knows every possible payload. */
public sealed interface BBEntry permits ParamNotice, VidNotice, Ballot, TallyResult {

    /** Deterministic byte serialisation used as input to the bulletin board's hash chain. */
    byte[] encodeForHash();
}
