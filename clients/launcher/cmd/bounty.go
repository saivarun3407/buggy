package cmd

import (
	"fmt"
	"os"

	"github.com/saivarun3407/buggy/clients/launcher/internal/engagement"
	"github.com/spf13/cobra"
)

var bountyPlatform string

var bountyCmd = &cobra.Command{
	Use:   "bounty",
	Short: "Start a HackerOne / Bugcrowd bounty via the Scout intake flow",
	Long: "Bring the stack up and drop into the terminal UI pre-seeded with the " +
		"bounty Scout: it authenticates to HackerOne / Bugcrowd (credentials from " +
		"the environment), lists the programs you can access, lets you pick one, " +
		"ingests that program's scope into an enforced RoE, then hunts.\n\n" +
		"Set HACKERONE_API_USERNAME / HACKERONE_API_TOKEN and/or BUGCROWD_API_TOKEN " +
		"before running. Program selection is interactive.",
	Args: cobra.NoArgs,
	RunE: runBounty,
}

func init() {
	bountyCmd.Flags().StringVar(&bountyPlatform, "platform", "both",
		"Which platform(s) the Scout authenticates to: both|hackerone|bugcrowd")
	rootCmd.AddCommand(bountyCmd)
}

// bountyScoutKickoff mirrors buggy.cli.bounty.scout_kickoff — keep the
// wording in sync so the launcher and the headless `buggy-cli bounty`
// drive the orchestrator into the same Scout intake flow.
func bountyScoutKickoff(platform string) string {
	var platforms string
	switch platform {
	case "hackerone":
		platforms = "HackerOne"
	case "bugcrowd":
		platforms = "Bugcrowd"
	default:
		platforms = "HackerOne and Bugcrowd"
	}
	return "Start an authorized bug-bounty engagement. Hand off to the bounty " +
		"Scout agent now: authenticate to " + platforms + " (credentials are in the " +
		"environment), list the programs I can access, and let me pick one. " +
		"Then fetch that program's structured scope, exclusions, and reporting " +
		"policy, confirm in-scope / out-of-scope with me, and call " +
		"ingest_bounty_scope to write the enforced RoE before any recon. Do " +
		"not test anything until the scope is ingested."
}

func runBounty(cmd *cobra.Command, args []string) error {
	home, env, err := prepareStack(cmd)
	if err != nil {
		return err
	}

	fmt.Println()
	choice, err := engagement.Select(home)
	if err != nil {
		return err
	}
	// The Scout ingests scope at runtime, so always drive the orchestrator
	// (buggy) — even on a fresh engagement that has no plan bundle yet.
	choice.AssistantID = engagement.AssistantBuggy
	if err := os.Setenv("BUGGY_ENGAGEMENT_WORKSPACE", choice.WorkspacePath); err != nil {
		return fmt.Errorf("set engagement workspace env: %w", err)
	}

	if err := startServices(env); err != nil {
		return err
	}

	return launchInteractive(env, choice, map[string]string{
		"BUGGY_INITIAL_MESSAGE": bountyScoutKickoff(bountyPlatform),
	})
}
