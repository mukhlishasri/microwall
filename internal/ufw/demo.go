package ufw

import (
	"errors"
	"strconv"
	"strings"
	"sync"
)

// Demo is an in-memory Firewall for trying the UI without root or ufw.
// Nothing it does touches the system.
type Demo struct {
	mu sync.Mutex
	st Status
}

func NewDemo() *Demo {
	return &Demo{st: Status{
		Active:   true,
		Logging:  "on (low)",
		Incoming: "deny",
		Outgoing: "allow",
		Routed:   "disabled",
		Rules: []Rule{
			{To: "22/tcp", Action: "LIMIT", Dir: "IN", From: "Anywhere", Comment: "ssh"},
			{To: "80,443/tcp", Action: "ALLOW", Dir: "IN", From: "Anywhere", Comment: "web"},
			{To: "5432/tcp", Action: "ALLOW", Dir: "IN", From: "10.0.0.0/24", Comment: "postgres from lan"},
			{To: "Anywhere", Action: "DENY", Dir: "IN", From: "203.0.113.7"},
			{To: "25/tcp", Action: "REJECT", Dir: "OUT", From: "Anywhere", Comment: "no outbound smtp"},
			{To: "22/tcp (v6)", Action: "LIMIT", Dir: "IN", From: "Anywhere (v6)", Comment: "ssh", V6: true},
			{To: "80,443/tcp (v6)", Action: "ALLOW", Dir: "IN", From: "Anywhere (v6)", Comment: "web", V6: true},
		},
	}}
}

func (d *Demo) Status() (Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.st
	st.Rules = make([]Rule, len(d.st.Rules))
	for i, r := range d.st.Rules {
		r.Num = i + 1
		st.Rules[i] = r
	}
	return st, nil
}

func (d *Demo) Enable() error  { return d.set(func() { d.st.Active = true }) }
func (d *Demo) Disable() error { return d.set(func() { d.st.Active = false }) }
func (d *Demo) Reload() error  { return nil }

// Add mimics the parts of ufw's behaviour that matter to the UI: a rule
// without addresses is created for both IPv4 and IPv6, an existing rule is
// skipped, and re-adding a rule with a new comment updates the comment.
func (d *Demo) Add(s RuleSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	side := func(addr string) string {
		if isAny(addr) || strings.HasSuffix(addr, "/0") {
			return "Anywhere"
		}
		return addr
	}
	to := side(s.To)
	if s.Port != "" {
		port := s.Port
		if s.Proto != "any" {
			port += "/" + s.Proto
		}
		if to == "Anywhere" {
			to = port
		} else {
			to += " " + port
		}
	} else if s.Proto != "any" {
		to += "/" + s.Proto
	}
	if s.Interface != "" {
		to += " on " + s.Interface
	}
	base := Rule{To: to, Action: strings.ToUpper(s.Action), Dir: strings.ToUpper(s.Direction), From: side(s.From), Comment: s.Comment}

	addrs := s.From + " " + s.To
	want4, want6 := !strings.Contains(addrs, ":"), !strings.Contains(addrs, ".")
	v6 := base
	v6.V6 = true
	if !strings.Contains(v6.To, ":") {
		v6.To += " (v6)"
	}
	if v6.From == "Anywhere" {
		v6.From = "Anywhere (v6)"
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	n4 := 0
	for _, r := range d.st.Rules {
		if !r.V6 {
			n4++
		}
	}
	pos := 0
	if s.Position != "" {
		pos, _ = strconv.Atoi(s.Position)
		in4 := pos <= n4
		if pos < 1 || pos > len(d.st.Rules) || (in4 && !want4) || (!in4 && !want6) {
			return errors.New("Invalid position '" + s.Position + "'")
		}
	}
	// put mimics ufw's backend. A rule matching an existing one in everything
	// but action and comment is "the same rule": with a position ufw skips it,
	// without one ufw updates the existing rule in place.
	put := func(r Rule, at int, positioned bool) bool {
		for i, c := range d.st.Rules {
			if c.To == r.To && c.Dir == r.Dir && c.From == r.From {
				if !positioned {
					d.st.Rules[i].Action, d.st.Rules[i].Comment = r.Action, r.Comment
				}
				return false
			}
		}
		d.st.Rules = append(d.st.Rules[:at], append([]Rule{r}, d.st.Rules[at:]...)...)
		return true
	}
	// With a position in the IPv4 rules, ufw puts the IPv6 half before the
	// IPv6 twin of the rule at that position, or at the end if it has none.
	at6, positioned6 := len(d.st.Rules), pos > n4
	if positioned6 {
		at6 = pos - 1
	} else if pos >= 1 {
		if twin, ok := Twin(d.st.Rules, d.st.Rules[pos-1]); ok {
			for i, c := range d.st.Rules {
				if c == twin {
					at6, positioned6 = i, true
				}
			}
		}
	}
	if want4 {
		at := n4 // end of the IPv4 rules
		positioned := pos >= 1 && pos <= n4
		if positioned {
			at = pos - 1
		}
		if put(base, at, positioned) {
			at6++ // everything after the IPv4 rules moved down by one
		}
	}
	if want6 {
		put(v6, at6, positioned6)
	}
	return nil
}

func (d *Demo) Delete(r Rule) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Num < 1 || r.Num > len(d.st.Rules) {
		return errors.New("Could not delete non-existent rule")
	}
	d.st.Rules = append(d.st.Rules[:r.Num-1], d.st.Rules[r.Num:]...)
	return nil
}

func (d *Demo) SetDefault(direction, policy string) error {
	return d.set(func() {
		switch direction {
		case "incoming":
			d.st.Incoming = policy
		case "outgoing":
			d.st.Outgoing = policy
		case "routed":
			d.st.Routed = policy
		}
	})
}

func (d *Demo) SetLogging(level string) error {
	return d.set(func() {
		if level == "off" {
			d.st.Logging = "off"
		} else {
			d.st.Logging = "on (" + level + ")"
		}
	})
}

func (d *Demo) set(f func()) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	f()
	return nil
}
