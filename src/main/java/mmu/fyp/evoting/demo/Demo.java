package mmu.fyp.evoting.demo;

/** CLI entry point. Each subcommand maps to one of the scripted scenarios required by M6–M8. */
public final class Demo {

    private Demo() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        String[] rest = new String[args.length - 1];
        System.arraycopy(args, 1, rest, 0, rest.length);
        switch (args[0]) {
            case "honest" -> HonestScenario.run();
            case "coerced" -> CoercedScenario.run();
            case "double-vote" -> DoubleVoteScenario.run();
            case "forged" -> ForgedBallotScenario.run();
            case "bench" -> mmu.fyp.evoting.bench.Benchmark.run(rest);
            case "gui" -> mmu.fyp.evoting.gui.Launcher.main(new String[0]);
            default -> {
                System.err.println("unknown scenario: " + args[0]);
                usage();
                System.exit(2);
            }
        }
    }

    private static void usage() {
        System.err.println("usage: evote demo <scenario> [args]");
        System.err.println("scenarios:");
        System.err.println("  honest                one honest run of register/vote/tally for three voters");
        System.err.println("  coerced               coerced voter shows real and fake transcripts side-by-side");
        System.err.println("  double-vote           one voter votes twice, tally detects and traces");
        System.err.println("  forged                attacker injects forged ballots, tally rejects them");
        System.err.println("  bench [--quick]       run the benchmark at 10/100/1000 voters (--quick skips 1000)");
        System.err.println("  gui                   launch the Voter Client Swing UI");
    }
}
