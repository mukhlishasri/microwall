package ufw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CLI is the real Firewall: it shells out to the ufw binary. It needs root.
type CLI struct {
	Bin     string
	Timeout time.Duration
}

// NewCLI locates the ufw binary.
func NewCLI() (*CLI, error) {
	bin, err := exec.LookPath("ufw")
	if err != nil {
		for _, p := range []string{"/usr/sbin/ufw", "/sbin/ufw"} {
			if _, statErr := os.Stat(p); statErr == nil {
				bin, err = p, nil
				break
			}
		}
	}
	if err != nil {
		return nil, errors.New("ufw is not installed (try: sudo apt install ufw)")
	}
	return &CLI{Bin: bin, Timeout: 20 * time.Second}, nil
}

func (c *CLI) run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	// Force English output so it can be parsed.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("ufw %s: timed out", strings.Join(args, " "))
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(strings.TrimPrefix(msg, "ERROR: "))
	}
	return stdout.String(), nil
}

func (c *CLI) Status() (Status, error) {
	var st Status
	out, err := c.run("status", "numbered")
	if err != nil {
		return st, err
	}
	st.Active, st.Rules = ParseNumbered(out)

	if st.Active {
		verbose, err := c.run("status", "verbose")
		if err != nil {
			return st, err
		}
		ParseVerbose(verbose, &st)
		return st, nil
	}

	// Inactive: ufw reports neither rules nor policies in "status", so read
	// the pending rules and the config files instead.
	if added, err := c.run("show", "added"); err == nil {
		st.Rules = ParseAdded(added)
	}
	if b, err := os.ReadFile("/etc/default/ufw"); err == nil {
		kv := ParseConfig(string(b))
		st.Incoming = policyName(kv["DEFAULT_INPUT_POLICY"])
		st.Outgoing = policyName(kv["DEFAULT_OUTPUT_POLICY"])
		st.Routed = policyName(kv["DEFAULT_FORWARD_POLICY"])
	}
	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		st.Logging = ParseConfig(string(b))["LOGLEVEL"]
	}
	return st, nil
}

func (c *CLI) Enable() error {
	_, err := c.run("--force", "enable")
	return err
}

func (c *CLI) Disable() error {
	_, err := c.run("disable")
	return err
}

func (c *CLI) Reload() error {
	_, err := c.run("reload")
	return err
}

func (c *CLI) Add(spec RuleSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	_, err := c.run(spec.Args()...)
	return err
}

func (c *CLI) Delete(r Rule) error {
	var args []string
	switch {
	case r.Num > 0:
		args = []string{"--force", "delete", strconv.Itoa(r.Num)}
	case r.Spec != "":
		args = append([]string{"delete"}, strings.Fields(r.Spec)...)
	default:
		return errors.New("rule cannot be identified")
	}
	_, err := c.run(args...)
	return err
}

func (c *CLI) SetDefault(direction, policy string) error {
	if !contains(Chains, direction) || !contains(Policies, policy) {
		return fmt.Errorf("invalid default policy: %s %s", policy, direction)
	}
	_, err := c.run("default", policy, direction)
	return err
}

func (c *CLI) SetLogging(level string) error {
	if !contains(LogLevels, level) {
		return fmt.Errorf("invalid logging level %q", level)
	}
	_, err := c.run("logging", level)
	return err
}
