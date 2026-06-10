package mmu.fyp.evoting.protocol;

import mmu.fyp.evoting.entities.bulletinboard.Ballot;
import mmu.fyp.evoting.entities.bulletinboard.BulletinBoard;
import mmu.fyp.evoting.entities.ec.ECVoteSession;
import mmu.fyp.evoting.entities.ec.ElectionCommittee;
import mmu.fyp.evoting.entities.voter.Voter;
import mmu.fyp.evoting.entities.voter.VoterSession;
import mmu.fyp.evoting.entities.voter.VotingContext;

/** Drives the 4-round Vote protocol between one voter and the EC. */
public final class VoteProtocol {

    private VoteProtocol() {}

    public static Ballot run(Voter voter, VotingContext ctx, ElectionCommittee ec, BulletinBoard bb, int candidate) {
        VoterSession vs = voter.beginVote(ctx, candidate);
        ECVoteSession ecs = ec.beginVoteSession();

        Messages.Round2 r2 = vs.step2();
        Messages.Round3 r3 = ecs.processStep2(r2);
        Messages.Round4 r4 = vs.processStep3(r3);
        Messages.Round5 r5 = ecs.processStep4(r4);
        return vs.finalize(r5, bb);
    }
}
