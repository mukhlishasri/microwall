package ufw

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrNoChange is returned by Replace when ufw already has the requested rule.
var ErrNoChange = errors.New("no change: that rule already exists (to move a rule, delete it and insert it again)")

var portSpecRe = regexp.MustCompile(`^[0-9]+([,:][0-9]+)*$`)

// stripV6 removes ufw's " (v6)" markers so IPv4 and IPv6 rows can be compared.
func stripV6(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "(v6)", "")), " ")
}

// Twin returns the rule that ufw created for the other IP family from the
// same command as r (e.g. "22/tcp (v6)" for "22/tcp"), if there is one.
func Twin(rules []Rule, r Rule) (Rule, bool) {
	for _, c := range rules {
		if c.V6 != r.V6 && c.Action == r.Action && c.Dir == r.Dir && c.Comment == r.Comment &&
			stripV6(c.To) == stripV6(r.To) && stripV6(c.From) == stripV6(r.From) {
			return c, true
		}
	}
	return Rule{}, false
}

// SpecFromRule converts a rule from "ufw status numbered" back into an
// editable spec. hasTwin says whether the rule has a twin in the other IP
// family; without one, "Anywhere" is pinned to the rule's own family so that
// saving does not create a rule for the other family.
//
// It returns an error for rules the form cannot represent, rather than
// silently dropping part of them.
func SpecFromRule(r Rule, hasTwin bool) (RuleSpec, error) {
	s := RuleSpec{Action: strings.ToLower(r.Action), Proto: "any", Comment: r.Comment}
	if !contains(Actions, s.Action) {
		return s, fmt.Errorf("unknown action %q", r.Action)
	}
	switch r.Dir {
	case "IN", "":
		s.Direction = "in"
	case "OUT":
		s.Direction = "out"
	default:
		return s, errors.New("routed (FWD) rules can't be edited here")
	}
	if r.Num == 0 {
		return s, errors.New("editing needs the firewall to be active, so rules have numbers")
	}
	if strings.Contains(r.To, "(log") || strings.Contains(r.From, "(log") {
		return s, errors.New("rules with logging options can't be edited here")
	}

	var err error
	if s.To, s.Port, err = parseSide(r.To, &s); err != nil {
		return s, err
	}
	var fromPort string
	if s.From, fromPort, err = parseSide(r.From, &s); err != nil {
		return s, err
	}
	if fromPort != "" {
		return s, errors.New("rules with a source port can't be edited here")
	}

	if s.From == "any" && s.To == "any" && !hasTwin {
		if r.V6 {
			s.From = "::/0"
		} else {
			s.From = "0.0.0.0/0"
		}
	}
	return s, nil
}

// parseSide parses the To or From column: an optional address, an optional
// port[/proto], and an optional "on IFACE".
func parseSide(col string, s *RuleSpec) (addr, port string, err error) {
	addr = "any"
	toks := strings.Fields(strings.NewReplacer("(v6)", "", "(out)", "").Replace(col))
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t == "on" && i+1 < len(toks) {
			s.Interface = toks[i+1]
			i++
			continue
		}
		if t == "port" && i+1 < len(toks) {
			continue // "addr port N": the next token is the port
		}
		base, proto := t, ""
		for _, p := range []string{"tcp", "udp"} {
			if strings.HasSuffix(t, "/"+p) {
				base, proto = strings.TrimSuffix(t, "/"+p), p
			}
		}
		if proto != "" {
			if s.Proto != "any" && s.Proto != proto {
				return "", "", errors.New("rule mixes protocols and can't be edited here")
			}
			s.Proto = proto
		}
		switch {
		case base == "Anywhere":
			// already "any"
		case portSpecRe.MatchString(base):
			if port != "" {
				return "", "", fmt.Errorf("can't understand %q", col)
			}
			port = base
		case validAddr(base) && !isAny(base):
			addr = base
		default:
			return "", "", fmt.Errorf("%q looks like an application profile or an unsupported rule; it can't be edited here", col)
		}
	}
	return addr, port, nil
}

func sameRule(a, b Rule) bool {
	a.Num, b.Num = 0, 0
	return a == b
}

func find(rules []Rule, r Rule) (Rule, bool) {
	for _, c := range rules {
		if sameRule(c, r) {
			return c, true
		}
	}
	return Rule{}, false
}

// Replace swaps old for the rule described by spec. ufw has no edit command,
// so this adds the new rule first and removes the old one only once the new
// rule is confirmed to be in place; if adding fails, nothing has changed.
// twin, if not nil, is old's other-family twin and is removed as well.
func Replace(fw Firewall, old Rule, twin *Rule, spec RuleSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	before, err := fw.Status()
	if err != nil {
		return err
	}
	// Rule numbers shift whenever rules change, so make sure the list we
	// edited from is still what ufw has.
	if cur, ok := find(before.Rules, old); !ok || cur.Num != old.Num {
		return errors.New("rules changed since the list was loaded; nothing changed, list refreshed")
	}
	if spec.Position == "" {
		spec.Position = strconv.Itoa(old.Num)
	}

	if err := fw.Add(spec); err != nil {
		return err
	}
	after, err := fw.Status()
	if err != nil {
		return err
	}
	if len(after.Rules) <= len(before.Rules) {
		// ufw added nothing. Either the rule already existed, or only the
		// comment differed and ufw updated it in place.
		if _, still := find(after.Rules, old); still {
			return ErrNoChange
		}
		return nil
	}

	targets := []Rule{old}
	if twin != nil {
		targets = append(targets, *twin)
	}
	for _, target := range targets {
		st, err := fw.Status()
		if err != nil {
			return err
		}
		cur, ok := find(st.Rules, target)
		if !ok {
			return errors.New("the new rule was added, but the old one could not be found to remove; check the list")
		}
		if err := fw.Delete(cur); err != nil {
			return fmt.Errorf("the new rule was added, but removing the old one failed: %w", err)
		}
	}
	return nil
}
