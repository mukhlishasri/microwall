package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"microwall/internal/ports"
	"microwall/internal/ufw"
)

const (
	tabRules = iota
	tabPorts
)

// visiblePorts returns the listeners matching the filter.
func (m Model) visiblePorts() []ports.Listener {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	if q == "" {
		return m.listeners
	}
	var out []ports.Listener
	for _, l := range m.listeners {
		verdict, _ := m.verdict(l)
		hay := strings.ToLower(fmt.Sprintf("%s %d %s %s %s", l.Proto, l.Port, l.Addr, l.Process, verdict))
		if strings.Contains(hay, q) {
			out = append(out, l)
		}
	}
	return out
}

func (m Model) selectedPort() (ports.Listener, bool) {
	list := m.visiblePorts()
	if m.pcursor < 0 || m.pcursor >= len(list) {
		return ports.Listener{}, false
	}
	return list[m.pcursor], true
}

var portTokRe = regexp.MustCompile(`^([0-9,:]+)(?:/(tcp|udp))?$`)

// ruleCoversPort reports whether an inbound rule names this port. Rules
// without a port (whole-host rules, application profiles) are not matched.
func ruleCoversPort(r ufw.Rule, port int, proto string) bool {
	if r.Dir == "OUT" || r.Dir == "FWD" {
		return false
	}
	for _, tok := range strings.Fields(r.To) {
		m := portTokRe.FindStringSubmatch(tok)
		if m == nil || (m[2] != "" && m[2] != proto) {
			continue
		}
		for _, part := range strings.Split(m[1], ",") {
			lo, hi, isRange := strings.Cut(part, ":")
			a, err := strconv.Atoi(lo)
			if err != nil {
				continue
			}
			b := a
			if isRange {
				if b, err = strconv.Atoi(hi); err != nil {
					continue
				}
			}
			if port >= a && port <= b {
				return true
			}
		}
	}
	return false
}

// verdict estimates what the firewall does with inbound traffic to l:
// the first rule that names the port, else the default incoming policy.
func (m Model) verdict(l ports.Listener) (string, lipgloss.Style) {
	if l.Local() {
		return "local only", dimStyle
	}
	if !m.status.Active {
		return "open (firewall inactive)", warnStyle
	}
	for _, r := range m.status.Rules {
		if (r.V6 && l.V4Only()) || !ruleCoversPort(r, l.Port, l.Proto) {
			continue
		}
		text := r.Action
		if r.From != "" && !strings.HasPrefix(r.From, "Anywhere") {
			text += " from " + r.From
		}
		return fmt.Sprintf("%s (rule %d)", text, r.Num), actionStyle(r.Action)
	}
	policy := m.status.Incoming
	if policy == "" {
		policy = "?"
	}
	return "default " + policy, actionStyle(policy)
}

func (m Model) portsView() string {
	const protoW, portW, gaps = 5, 6, 5
	rest := max(30, m.width-protoW-portW-gaps-2)
	addrW := rest * 25 / 100
	procW := rest * 30 / 100
	fwW := rest - addrW - procW

	row := func(proto, port, addr, proc, fw string) string {
		return " " + pad(proto, protoW) + " " + pad(port, portW) + " " + pad(addr, addrW) + " " + pad(proc, procW) + " " + pad(fw, fwW)
	}

	var b strings.Builder
	b.WriteString(headStyle.Render(row("Proto", "Port", "Listening on", "Process", "Firewall")) + "\n")

	if !m.loaded {
		return b.String() + "\n" + dimStyle.Render("  Loading…")
	}
	if m.portsErr != "" {
		return b.String() + "\n" + errStyle.Render("  ✗ "+m.portsErr)
	}
	list := m.visiblePorts()
	if len(list) == 0 {
		msg := "  Nothing is listening."
		if m.filter.Value() != "" {
			msg = "  No ports match the filter. Press esc to clear it."
		}
		return b.String() + "\n" + dimStyle.Render(msg)
	}

	end := min(len(list), m.poffset+m.rowsH())
	for i := m.poffset; i < end; i++ {
		l := list[i]
		addr := l.Addr
		switch addr {
		case "0.0.0.0":
			addr = "all IPv4"
		case "::":
			addr = "all IPv6"
		case "*":
			addr = "all"
		}
		proc := l.Process
		if proc == "" {
			proc = "-"
		}
		verdict, style := m.verdict(l)
		port := strconv.Itoa(l.Port)
		if i == m.pcursor {
			b.WriteString(selectedStyle.Render(row(l.Proto, port, addr, proc, verdict)))
		} else {
			b.WriteString(" " + dimStyle.Render(pad(l.Proto, protoW)) + " " + boldStyle.Render(pad(port, portW)) + " " +
				pad(addr, addrW) + " " + pad(proc, procW) + " " + style.Render(pad(verdict, fwW)))
		}
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// tabsView is the third header line.
func (m Model) tabsView() string {
	tab := func(id int, label string) string {
		if m.tab == id {
			return selectedStyle.Render(" " + label + " ")
		}
		return dimStyle.Render(" " + label + " ")
	}
	rules, listening := "Rules", "Ports in use"
	if m.loaded {
		rules = fmt.Sprintf("Rules (%d)", len(m.status.Rules))
		if m.portsErr == "" {
			listening = fmt.Sprintf("Ports in use (%d)", len(m.listeners))
		}
	}
	return " " + tab(tabRules, rules) + " " + tab(tabPorts, listening)
}
