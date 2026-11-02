// Package cli implements the hvmc command tree (DESIGN §2): one binary that is
// coordinator (`serve`), agent (`agent ...`) and operator tool (`plan`,
// `check`, `test`, `ca`, `token`).
//
// Commands that are not built yet return ErrNotImplemented. Exit codes:
// 0 success, 1 failure (including not implemented), 2 usage error.
package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/matfax/hvmc/internal/version"
)

// Exit codes returned by Execute.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

// ErrNotImplemented is returned by commands that are not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// usageError is a command-line usage mistake: Execute prints the command's
// usage and exits with ExitUsage.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

// env holds what commands take from their surroundings, so tests can replace
// it.
type env struct {
	// now is the wall clock.
	now func() time.Time
	// rootCAs verify TLS endpoints hvmc connects to (hvmc agent enroll);
	// nil means the system roots.
	rootCAs *x509.CertPool
}

func defaultEnv() env { return env{now: time.Now} }

// Execute runs hvmc with args (without the program name), writing to stdout
// and stderr, and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	return execute(defaultEnv(), args, stdout, stderr)
}

func execute(e env, args []string, stdout, stderr io.Writer) int {
	root := newRootCommand(e)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	cmd, err := root.ExecuteContextC(context.Background())
	if err == nil {
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
	var ue *usageError
	if errors.As(err, &ue) {
		_, _ = fmt.Fprint(stderr, cmd.UsageString())
		return ExitUsage
	}
	return ExitFailure
}

// newRootCommand builds the whole command tree.
func newRootCommand(e env) *cobra.Command {
	root := &cobra.Command{
		Use:   "hvmc",
		Short: "Hyper-V Memory Coordinator",
		Long: "hvmc hands out RAM on a Hyper-V host as memory leases. The same binary is the\n" +
			"coordinator (serve), the host and guest agents (agent) and the operator tool.",
		Version:       version.String(),
		Args:          subcommandArgs,
		RunE:          func(*cobra.Command, []string) error { return nil },
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetVersionTemplate("hvmc {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err: err} })
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(
		newVersionCommand(),
		newServeCommand(),
		newAgentCommand(e),
		newPlanCommand(e),
		newCheckCommand(),
		newTestCommand(),
		newCACommand(kubeReader),
		newTokenCommand(),
	)
	return root
}

// group returns a command that only holds subcommands.
func group(use, short string, children ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  subcommandArgs,
		// Never reached (subcommandArgs always fails), but makes the command
		// runnable so that a missing or unknown subcommand is an error
		// instead of a silent help page.
		RunE: func(*cobra.Command, []string) error { return nil },
	}
	c.AddCommand(children...)
	return c
}

// subcommandArgs rejects a group command invoked without a known subcommand.
func subcommandArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageErrorf("%s needs a subcommand", cmd.CommandPath())
	}
	return usageErrorf("unknown command %q for %q", args[0], cmd.CommandPath())
}

// noArgs rejects positional arguments.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageErrorf("%s takes no arguments, got %q", cmd.CommandPath(), args)
	}
	return nil
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the hvmc version",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "hvmc %s\n", version.String())
			return err
		},
	}
}
