package cmd

import (
	"strings"

	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/spf13/cobra"
)

var (
	huntScope          []string
	huntExclude        []string
	huntIncludeSubs    bool
	huntScopeFile      string
	huntInstruction    string
	huntMode           string
	huntPlanOnly       bool
	huntNonInteractive bool
)

var huntCmd = &cobra.Command{
	Use:   "hunt TARGET [TARGET...]",
	Short: "Start a hunt against a target in one command",
	Long: "Bring the Buggy stack up (running the setup wizard first if " +
		"needed) and run an authorized hunt against one or more targets — no " +
		"interactive interview. Scope defaults to exactly the targets you name; " +
		"widen it explicitly with --scope or --include-subdomains.\n\n" +
		"  buggy hunt example.com\n" +
		"  buggy hunt api.example.com app.example.com --include-subdomains\n" +
		"  buggy hunt https://example.com --scope '*.example.com' --instruction 'focus auth'",
	Args: cobra.MinimumNArgs(1),
	RunE: runHunt,
}

func init() {
	huntCmd.Flags().StringArrayVar(&huntScope, "scope", nil, "Extra in-scope pattern: host, *.domain, IP, CIDR (repeatable)")
	huntCmd.Flags().StringArrayVar(&huntExclude, "exclude", nil, "Out-of-scope pattern (repeatable)")
	huntCmd.Flags().BoolVar(&huntIncludeSubs, "include-subdomains", false, "Explicitly add <host> and *.<host> to scope per target")
	huntCmd.Flags().StringVar(&huntScopeFile, "scope-file", "", "Scope file (JSON or text) to merge into scope")
	huntCmd.Flags().StringVar(&huntInstruction, "instruction", "", "Free-form focus/auth notes for the orchestrator")
	huntCmd.Flags().StringVar(&huntMode, "mode", "enforce", "RoE enforcement mode: audit|warn|enforce")
	huntCmd.Flags().BoolVar(&huntPlanOnly, "plan-only", false, "Write the plan bundle and exit without dispatching")
	huntCmd.Flags().BoolVarP(&huntNonInteractive, "non-interactive", "n", false, "Emit JSONL events instead of progress lines")
	rootCmd.AddCommand(huntCmd)
}

func runHunt(cmd *cobra.Command, args []string) error {
	_, env, err := prepareStack(cmd)
	if err != nil {
		return err
	}

	// Non-interactive hunt: leave BUGGY_ENGAGEMENT_WORKSPACE unset so the
	// whole workspace tree mounts at /workspace. buggy-cli hunt writes
	// plan/roe.json under <root>/<slug> and tells the agent workspace_path is
	// /workspace/<slug>; keeping the root at /workspace makes those resolve
	// identically for the langgraph agent and the sandbox.
	if err := startServices(env); err != nil {
		return err
	}

	cliArgs := []string{"buggy-cli", "hunt"}
	cliArgs = append(cliArgs, args...)
	for _, s := range huntScope {
		cliArgs = append(cliArgs, "--scope", s)
	}
	for _, e := range huntExclude {
		cliArgs = append(cliArgs, "--exclude", e)
	}
	if huntIncludeSubs {
		cliArgs = append(cliArgs, "--include-subdomains")
	}
	if huntScopeFile != "" {
		cliArgs = append(cliArgs, "--scope-file", huntScopeFile)
	}
	if huntInstruction != "" {
		cliArgs = append(cliArgs, "--instruction", huntInstruction)
	}
	cliArgs = append(cliArgs, "--mode", huntMode)
	if huntPlanOnly {
		cliArgs = append(cliArgs, "--plan-only")
	}
	if huntNonInteractive {
		cliArgs = append(cliArgs, "--non-interactive")
	}

	ui.Info("Starting hunt against: " + strings.Join(args, ", "))

	// Run inside the langgraph container — it carries the python buggy
	// package (and the buggy-cli console script) and already has the
	// workspace tree mounted at /workspace. Point the engage root there.
	c := compose.New()
	execEnv := map[string]string{"BUGGY_ENGAGEMENT_WORKSPACE": "/workspace"}
	if err := c.ExecWithEnv("langgraph", execEnv, cliArgs...); err != nil {
		return err
	}

	ui.DimText("Hunt finished. Review findings under ~/.buggy/workspace/<engagement>/ — " +
		"run 'buggy' to open the UI, or 'buggy stop' to shut the stack down.")
	return nil
}
