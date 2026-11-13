package cmd

import (
	"fmt"
	"os"

	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/saivarun3407/buggy/clients/launcher/internal/updater"
	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "buggy",
	Short: "Buggy — Autonomous Hacking Agent for Red Team",
	Long:  ui.RenderBanner() + "\n" + ui.Dim.Render("Autonomous Hacking Agent for Red Team"),
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	updater.CleanupOldBinary()
	if err := rootCmd.Execute(); err != nil {
		ui.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("Buggy %s\n", version))
}
