// Package ufw wraps the ufw command line tool.
package ufw

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Rule is one firewall rule as reported by ufw.
type Rule struct {
	// Num is the rule number from "ufw status numbered". It is 0 when the
	// firewall is inactive, because ufw only numbers rules while it is running.
	Num     int
	To      string
	Action  string // ALLOW, DENY, REJECT, LIMIT
	Dir     string // IN, OUT, FWD or empty
	From    string
	Comment string
	V6      bool
	// Spec is the rule as a ufw command without the leading "ufw" and without
	// the comment (e.g. "allow 22/tcp"). Only set while the firewall is inactive.
	Spec string
}

// Status is a snapshot of the firewall.
type Status struct {
	Active   bool
	Logging  string
	Incoming string
	Outgoing string
	Routed   string
	Rules    []Rule
}

// RuleSpec describes a rule to add.
type RuleSpec struct {
	Action    string // allow, deny, reject, limit
	Direction string // in, out
	Interface string // optional
	Proto     string // any, tcp, udp
	Port      string // optional: 22, 80,443, 6000:6007 or a service name
	From      string // any, an address or a CIDR
	To        string // any, an address or a CIDR
	Comment   string // optional
	Position  string // optional rule number to insert at
}

// Firewall is what the UI needs from ufw.
type Firewall interface {
	Status() (Status, error)
	Enable() error
	Disable() error
	Reload() error
	Add(spec RuleSpec) error
	Delete(rule Rule) error
	SetDefault(direction, policy string) error
	SetLogging(level string) error
}

var (
	Actions    = []string{"allow", "deny", "reject", "limit"}
	Directions = []string{"in", "out"}
	Protos     = []string{"any", "tcp", "udp"}
	Policies   = []string{"allow", "deny", "reject"}
	Chains     = []string{"incoming", "outgoing", "routed"}
	LogLevels  = []string{"off", "low", "medium", "high", "full"}
)

var (
	portRe    = regexp.MustCompile(`^\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$`)
	serviceRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)
	ifaceRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:@-]*$`)
)

// Validate reports the first problem with the spec, or nil.
func (s RuleSpec) Validate() error {
	if !contains(Actions, s.Action) {
		return fmt.Errorf("unknown action %q", s.Action)
	}
	if !contains(Directions, s.Direction) {
		return fmt.Errorf("unknown direction %q", s.Direction)
	}
	if !contains(Protos, s.Proto) {
		return fmt.Errorf("unknown protocol %q", s.Proto)
	}
	if s.Interface != "" && !ifaceRe.MatchString(s.Interface) {
		return fmt.Errorf("invalid interface name %q", s.Interface)
	}
	for _, a := range []struct{ name, val string }{{"from", s.From}, {"to", s.To}} {
		if !validAddr(a.val) {
			return fmt.Errorf("%s must be \"any\", an IP address or a CIDR", a.name)
		}
	}
	if s.Port != "" {
		switch {
		case portRe.MatchString(s.Port):
			for _, p := range strings.FieldsFunc(s.Port, func(r rune) bool { return r == ',' || r == ':' }) {
				if n, _ := strconv.Atoi(p); n < 1 || n > 65535 {
					return fmt.Errorf("port %s is out of range (1-65535)", p)
				}
			}
			if strings.ContainsAny(s.Port, ",:") && s.Proto == "any" {
				return fmt.Errorf("port lists and ranges need protocol tcp or udp")
			}
		case serviceRe.MatchString(s.Port):
			// service name from /etc/services, ufw resolves it
		default:
			return fmt.Errorf("invalid port %q (try 22, 80,443 or 6000:6007)", s.Port)
		}
	}
	if s.Port == "" && isAny(s.From) && isAny(s.To) && s.Interface == "" {
		return fmt.Errorf("too broad: set a port, an address or an interface")
	}
	if strings.Contains(s.Comment, "'") {
		return fmt.Errorf("ufw does not support ' in comments")
	}
	if s.Position != "" {
		if n, err := strconv.Atoi(s.Position); err != nil || n < 1 {
			return fmt.Errorf("position must be a rule number (1 or higher)")
		}
	}
	return nil
}

// Args returns the ufw arguments that add this rule.
func (s RuleSpec) Args() []string {
	var a []string
	if s.Position != "" {
		a = append(a, "insert", s.Position)
	}
	a = append(a, s.Action, s.Direction)
	if s.Interface != "" {
		a = append(a, "on", s.Interface)
	}
	if s.Proto != "" && s.Proto != "any" {
		a = append(a, "proto", s.Proto)
	}
	a = append(a, "from", orAny(s.From), "to", orAny(s.To))
	if s.Port != "" {
		a = append(a, "port", s.Port)
	}
	if s.Comment != "" {
		a = append(a, "comment", s.Comment)
	}
	return a
}

// CommandLine renders the spec as the command a user would type.
func (s RuleSpec) CommandLine() string {
	args := s.Args()
	out := make([]string, 0, len(args)+1)
	out = append(out, "ufw")
	for _, x := range args {
		if strings.ContainsAny(x, " \t") {
			x = "'" + x + "'"
		}
		out = append(out, x)
	}
	return strings.Join(out, " ")
}

func validAddr(s string) bool {
	if isAny(s) {
		return true
	}
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func isAny(s string) bool { return s == "" || strings.EqualFold(s, "any") }

func orAny(s string) string {
	if isAny(s) {
		return "any"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
