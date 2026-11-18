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

func (d *Demo) Add(s RuleSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	to := "Anywhere"
	if !isAny(s.To) {
		to = s.To
	}
	if s.Port != "" {
		port := s.Port
		if s.Proto != "any" {
			port += "/" + s.Proto
		}
		if isAny(s.To) {
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
	from := "Anywhere"
	if !isAny(s.From) {
		from = s.From
	}
	r := Rule{To: to, Action: strings.ToUpper(s.Action), Dir: strings.ToUpper(s.Direction), From: from, Comment: s.Comment}

	d.mu.Lock()
	defer d.mu.Unlock()
	if s.Position != "" {
		n, _ := strconv.Atoi(s.Position)
		if n < 1 || n > len(d.st.Rules) {
			return errors.New("Invalid position '" + s.Position + "'")
		}
		d.st.Rules = append(d.st.Rules[:n-1], append([]Rule{r}, d.st.Rules[n-1:]...)...)
		return nil
	}
	d.st.Rules = append(d.st.Rules, r)
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
