package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/saivarun3407/buggy/clients/launcher/cmd/opscontrol"
	"github.com/saivarun3407/buggy/clients/launcher/internal/compose"
	"github.com/saivarun3407/buggy/clients/launcher/internal/config"
	"github.com/saivarun3407/buggy/clients/launcher/internal/engagement"
	"github.com/saivarun3407/buggy/clients/launcher/internal/health"
	"github.com/saivarun3407/buggy/clients/launcher/internal/migrate"
	"github.com/saivarun3407/buggy/clients/launcher/internal/platform"
	"github.com/saivarun3407/buggy/clients/launcher/internal/starprompt"
	"github.com/saivarun3407/buggy/clients/launcher/internal/ui"
	"github.com/saivarun3407/buggy/clients/launcher/internal/updater"
	"github.com/spf13/cobra"
)

func nullDevice() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// Indirected so tests can swap WSL detection without touching the
// real /proc/version or /etc/resolv.conf on the host they run on.
var (
	isWSLFn     = platform.IsWSL
	wslHostIPFn = platform.WSLHostIP

	// Indirected so tests can assert which AUTO_UPDATE branch ran
	// without making network calls into GitHub.
	autoUpdateFn   = updater.AutoUpdateIfAvailable
	promptUpdateFn = updater.PromptIfUpdateAvailable
)

// applyAutoUpdate dispatches the self-update check based on AUTO_UPDATE.
// See the inline comment in start() (section 2.5) for the value table
// and rationale for default-on behaviour.
//
// The `skip` argument is the --no-update CLI flag. When true it
// short-circuits *before* the env lookup so the operator's one-shot
// override always wins over the persistent .env setting — including
// AUTO_UPDATE=true and AUTO_UPDATE=prompt. This is the escape hatch
// for "I know there's a newer version, I want this exact binary".
//
// Unrecognized values (e.g. AUTO_UPDATE=disabled, where the operator
// probably MEANT "false") fall through to the prompt path rather than
// silent auto-update. Fail-loud beats fail-silent — an unexpected
// re-exec is harder to debug than a one-line prompt.
func applyAutoUpdate(env map[string]string, version string, skip bool) {
	if skip {
		return
	}
	// Which release stream to track (stable | latest). Default stable.
	ch := updater.ResolveChannel(config.Get(env, "BUGGY_CHANNEL", ""))
	switch strings.ToLower(strings.TrimSpace(config.Get(env, "AUTO_UPDATE", ""))) {
	case "", "true", "1", "yes", "on":
		if _, err := autoUpdateFn(version, ch); err != nil {
			ui.Warning("Auto-update: " + err.Error())
		}
	case "false", "0", "no", "off":
		// self-update disabled
	default:
		// Includes the explicit `prompt` / `ask` / `interactive`
		// opt-ins AND any unrecognized value (safer fallback).
		if _, err := promptUpdateFn(version, ch); err != nil {
			ui.Warning("Update check: " + err.Error())
		}
	}
}

// skipUpdate is bound to --no-update. One-shot override for the
// AUTO_UPDATE=true (now default) self-update path: useful in CI, when
// debugging a specific launcher version, or when intentionally
// running an older release against a known-good stack.
var skipUpdate bool

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Buggy services and launch the CLI",
	RunE:  runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)

	// PersistentFlag on root → inherited by `start`, so both
	// `buggy --no-update` (no subcommand → runStart) and
	// `buggy start --no-update` accept the flag.
	rootCmd.PersistentFlags().BoolVar(&skipUpdate, "no-update", false,
		"Skip the self-update check for this launch (does not change AUTO_UPDATE in .env)")

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runStart(cmd, args)
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	home, env, err := prepareStack(cmd)
	if err != nil {
		return err
	}

	// Engagement picker — must run BEFORE compose Up so the sandbox
	// container starts with /workspace bound to the chosen engagement
	// directory. Without this, the operator would briefly see the whole
	// workspace through the sandbox before any picking happens.
	fmt.Println()
	choice, err := engagement.Select(home)
	if err != nil {
		return err
	}
	// Export the bind path. composeEnv() forwards os.Environ(), so docker
	// compose interpolates ${BUGGY_ENGAGEMENT_WORKSPACE} from this var.
	if err := os.Setenv("BUGGY_ENGAGEMENT_WORKSPACE", choice.WorkspacePath); err != nil {
		return fmt.Errorf("set engagement workspace env: %w", err)
	}

	if err := startServices(env); err != nil {
		return err
	}

	return launchInteractive(env, choice, nil)
}

// prepareStack performs every pre-service step a run needs: config load +
// validation + migrations, Docker checks, config-file sync, workspace +
// credential-volume setup, the self-update check, and the one-time star
// prompt. It deliberately stops short of the engagement picker and bringing
// services up, so headless entry points (hunt) and interactive ones (start,
// bounty) can diverge after it. Returns the resolved home dir and env.
func prepareStack(cmd *cobra.Command) (string, map[string]string, error) {
	// 1. Check .env exists
	if !config.EnvExists() {
		ui.Warning("No configuration found. Running setup wizard...")
		fmt.Println()
		if err := runOnboard(cmd, nil); err != nil {
			return "", nil, err
		}
		fmt.Println()
	}

	// 1.5. One-shot migration for v1.1.7->v1.1.8 upgraders (stale
	// COMPOSE_PROFILES line). See the long-form note in the git history.
	if rewrote, mErr := config.MigrateActiveComposeProfiles(config.EnvPath()); mErr != nil {
		ui.Warning("Could not migrate stale COMPOSE_PROFILES in .env: " + mErr.Error())
	} else if rewrote {
		ui.Info("Migrated stale COMPOSE_PROFILES in .env (specialist workloads now spawn via ops_start). Backup at " + config.EnvPath() + ".bak")
	}

	// 2. Load and validate .env
	env, err := config.LoadEnv(config.EnvPath())
	if err != nil {
		return "", nil, fmt.Errorf("load config: %w", err)
	}

	// 2.1. Apply idempotent config/policy migrations for already-onboarded users.
	migrate.RunAll(env)

	if err := config.ValidateAuth(env); err != nil {
		return "", nil, err
	}

	// Verify Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil, fmt.Errorf("Docker is not installed or not in PATH. Install from https://docs.docker.com/get-docker/")
	}
	// Verify Docker Compose V2
	out, err := exec.Command("docker", "compose", "version").CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("Docker Compose V2 is required. Got: %s. Upgrade Docker Desktop or install the compose plugin.", strings.TrimSpace(string(out)))
	}

	probeOllamaIfSelected(env)

	// 2.3. Ensure config files exist (docker-compose.yml, litellm.yaml, workspace)
	home := config.BuggyHome()
	composePath := filepath.Join(home, "docker-compose.yml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		ref := "v" + version
		if version == "dev" || version == "" {
			ref = config.Get(env, "BUGGY_BRANCH", "main")
		}
		ui.Info("Downloading configuration files...")
		if err := updater.SyncConfigFiles(ref, nil); err != nil {
			return "", nil, fmt.Errorf("sync config: %w", err)
		}
	}

	// Ensure workspace + telemetry directories exist (root-owned if docker
	// creates them first, which breaks the host-side CLI write).
	_ = os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	_ = os.MkdirAll(filepath.Join(home, "telemetry"), 0o755)

	// Ensure BUGGY_HOME is set in .env (Docker Compose needs absolute path)
	if config.Get(env, "BUGGY_HOME", "") == "" {
		env["BUGGY_HOME"] = home
		if err := config.AppendEnvLine(config.EnvPath(), "BUGGY_HOME", home); err != nil {
			ui.Warning("Could not set BUGGY_HOME in .env: " + err.Error())
		}
	}

	// 2.6. Set host credential-mount volumes for the conditional litellm mounts.
	userHome, homeErr := os.UserHomeDir()
	if homeErr != nil {
		ui.Warning("Could not resolve home directory; skipping host credential mounts: " + homeErr.Error())
		_ = os.Setenv("CLAUDE_CREDENTIALS_VOLUME", nullDevice())
		_ = os.Setenv("CODEX_AUTH_VOLUME", nullDevice())
	} else {
		credsPath := filepath.Join(userHome, ".claude", ".credentials.json")
		if _, statErr := os.Stat(credsPath); statErr == nil {
			_ = os.Setenv("CLAUDE_CREDENTIALS_VOLUME", credsPath)
		} else {
			_ = os.Setenv("CLAUDE_CREDENTIALS_VOLUME", nullDevice())
		}
		codexAuthPath := filepath.Join(userHome, ".codex", "auth.json")
		if _, statErr := os.Stat(codexAuthPath); statErr == nil {
			_ = os.Setenv("CODEX_AUTH_VOLUME", codexAuthPath)
		} else {
			_ = os.Setenv("CODEX_AUTH_VOLUME", nullDevice())
		}
	}

	// 2.5. Update check, gated by AUTO_UPDATE in .env.
	applyAutoUpdate(env, version, skipUpdate)

	// 2.6. One-time GitHub star ask. Idempotent across launches.
	starprompt.PromptIfNotStarred()

	return home, env, nil
}

// startServices spawns the opscontrol daemon, refuses default credentials,
// brings the compose stack up, and blocks until healthchecks pass. The
// caller sets BUGGY_ENGAGEMENT_WORKSPACE beforehand when an
// engagement-scoped /workspace bind is wanted (the interactive paths do;
// the non-interactive hunt path leaves the whole tree mounted, which is the
// convention buggy-cli engage/hunt relies on).
func startServices(env map[string]string) error {
	// Spawn the opscontrol daemon BEFORE compose up so the langgraph socket
	// bind-mount has a real socket to attach to (ADR-0006 S1').
	sock, err := opscontrol.EnsureRunning()
	if err != nil {
		ui.Warning("opscontrol daemon not started: " + err.Error())
	} else if err := os.Setenv("BUGGY_OPSCONTROL_SOCK_HOST", sock); err != nil {
		ui.Warning("set BUGGY_OPSCONTROL_SOCK_HOST: " + err.Error())
	}

	// Refuse to start with default credentials.
	if err := checkDefaultCredentials(env); err != nil {
		return err
	}

	// Start services and block on healthchecks.
	c := compose.New()
	ui.Info("Starting Buggy services...")
	if err := c.Up(compose.Profiles.CLI); err != nil {
		return fmt.Errorf("start services: %w", err)
	}
	if err := health.WaitForServices(env); err != nil {
		return err
	}
	return nil
}

// launchInteractive opens the terminal CLI against the chosen engagement.
// extraEnv overlays additional CLI env vars (e.g. BUGGY_INITIAL_MESSAGE
// for the bounty flow); services are intentionally left running on exit.
func launchInteractive(env map[string]string, choice engagement.Choice, extraEnv map[string]string) error {
	fmt.Println()
	ui.Info("Launching Buggy CLI...")

	cliEnv := map[string]string{
		"BUGGY_VERSION":              version,
		"BUGGY_ASSISTANT_ID":         choice.AssistantID,
		"BUGGY_ENGAGEMENT":           choice.Engagement,
		"BUGGY_ENGAGEMENT_WORKSPACE": choice.WorkspacePath,
	}
	if port := config.Get(env, "WEB_PORT", "3000"); port != "" {
		cliEnv["WEB_PORT"] = port
	}
	for k, v := range extraEnv {
		cliEnv[k] = v
	}

	c := compose.New()
	if err := c.RunInteractive(
		[]string{compose.Profiles.CLI},
		"cli",
		cliEnv,
	); err != nil {
		ui.Warning("CLI exited with error: " + err.Error())
		return fmt.Errorf("cli: %w", err)
	}

	ui.DimText("CLI exited. Services kept running — run 'buggy stop' to shut down.")
	return nil
}

// probeOllamaIfSelected does a best-effort GET on /api/tags to verify the
// user's Ollama server is reachable when `ollama_local` is configured.
// Failures don't block startup — the user might be about to launch
// Ollama, or running on an unusual setup we can't introspect. We just
// surface a hint so they aren't surprised by a 'model not found' on the
// first agent prompt.
//
// On WSL2 the probe walks several candidate hosts because there's no
// single "the host" address: Docker Desktop installs may have
// host.docker.internal in /etc/hosts; native-WSL Docker installs need
// the Windows host IP from /etc/resolv.conf; an Ollama running inside
// the WSL distro itself sits on 127.0.0.1. Whichever returns 2xx wins.
// checkDefaultCredentials refuses to start when compose fallback credentials
// are still in effect. A bare docker compose up remains available for dev,
// while the supported launcher path cannot expose a default-keyed service.
func checkDefaultCredentials(env map[string]string) error {
	defaults := map[string][]string{
		"LITELLM_MASTER_KEY": {"sk-buggy-master"},
		"LITELLM_SALT_KEY":   {"sk-buggy-salt-change-me", "sk-buggy-salt"},
		"POSTGRES_PASSWORD":  {"buggy"},
		"NEO4J_PASSWORD":     {"buggy-graph"},
	}
	insecure := make([]string, 0, len(defaults))
	for name, fallbacks := range defaults {
		value := strings.TrimSpace(config.Get(env, name, ""))
		if value == "" || slices.Contains(fallbacks, value) {
			insecure = append(insecure, name)
		}
	}
	if len(insecure) == 0 {
		return nil
	}
	slices.Sort(insecure)
	return fmt.Errorf(
		"refusing to start with missing or default credentials in %s: %s.\n"+
			"For a new install, delete %s and run `buggy onboard`.\n"+
			"For an initialized install, do not change database passwords in .env alone; "+
			"back up the engagement, run `buggy remove`, then onboard again so credentials and volumes are recreated together.",
		config.EnvPath(), strings.Join(insecure, ", "), config.EnvPath())
}

func probeOllamaIfSelected(env map[string]string) {
	priority := strings.ToLower(env["BUGGY_AUTH_PRIORITY"])
	hasOllama := strings.Contains(","+priority+",", ",ollama_local,")
	base := strings.TrimSpace(env["OLLAMA_API_BASE"])
	if !hasOllama && base == "" {
		return
	}
	if base == "" {
		ui.Warning("ollama_local selected but OLLAMA_API_BASE is empty — skipping reachability probe.")
		return
	}

	candidates := candidateProbeURLs(base)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastStatus int
	for _, candidate := range candidates {
		resp, err := client.Get(candidate + "/api/tags")
		if err != nil {
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()
		if status < 400 {
			ui.DimText(fmt.Sprintf("Ollama reachable at %s.", base))
			return
		}
		lastStatus = status
	}

	if lastStatus != 0 {
		ui.Warning(fmt.Sprintf(
			"Ollama responded with %d at %s — verify the URL is correct.",
			lastStatus, base,
		))
		return
	}
	ui.Warning(fmt.Sprintf(
		"Ollama not reachable at %s (host-side probe). "+
			"Start it with 'ollama serve' or check OLLAMA_API_BASE.",
		base,
	))
}

// candidateProbeURLs returns the URLs the launcher should probe to
// verify host-side Ollama reachability. The returned list is ordered
// best-first so the loop short-circuits on the most likely candidate.
//
// For URLs that don't reference `host.docker.internal` the list is
// just the URL itself — the user wired up an explicit address (real
// IP, DNS name) and we trust it.
//
// For `host.docker.internal` the resolution depends on platform:
//
//   - Always try the URL verbatim first. Docker Desktop on macOS,
//     Windows, and WSL2 typically populates /etc/hosts with this name.
//   - On WSL, also try the Windows host IP found in /etc/resolv.conf.
//     Native-WSL Docker installs (no Docker Desktop) don't get the
//     hosts entry, but the Windows host is always the WSL2 default
//     nameserver, so this catches the "Ollama on Windows" case.
//   - Always fall back to 127.0.0.1. Native Linux Docker reaches the
//     host loopback via the `extra_hosts: host-gateway` mapping,
//     which on the host is just localhost. On WSL this also catches
//     the "Ollama running inside the WSL distro" case.
func candidateProbeURLs(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return []string{raw}
	}
	host, port, splitErr := net.SplitHostPort(u.Host)
	if splitErr != nil {
		host = u.Host
		port = ""
	}
	if host != "host.docker.internal" {
		return []string{raw}
	}

	candidates := []string{raw}
	seen := map[string]struct{}{raw: {}}
	add := func(replacement string) {
		v := *u
		if port == "" {
			v.Host = replacement
		} else {
			v.Host = net.JoinHostPort(replacement, port)
		}
		s := v.String()
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		candidates = append(candidates, s)
	}

	if isWSLFn() {
		if hostIP := wslHostIPFn(); hostIP != "" {
			add(hostIP)
		}
	}
	add("127.0.0.1")
	return candidates
}
