package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const (
	headerLines = 3
	footerLines = 2
)

func (m Model) View() string {
	if m.width == 0 {
		return ""
	}

	var body string
	switch m.mode {
	case modeForm:
		body = m.dialog(boxStyle.Render(m.form.view()))
	case modeConfirm:
		body = m.dialog(m.confirmView())
	case modeMenu:
		body = m.dialog(boxStyle.Render(m.menuView()))
	case modeHelp:
		body = m.dialog(boxStyle.Render(helpView()))
	default:
		if m.tab == tabPorts {
			body = m.portsView()
		} else {
			body = m.tableView()
		}
	}

	return m.headerView() + "\n" + fitLines(body, m.bodyH()) + "\n" + m.footerView()
}

func (m Model) headerView() string {
	left := " " + titleStyle.Render("microwall")
	if m.demo {
		left += " " + badgeDemo.Render("DEMO")
	}
	var badge string
	switch {
	case !m.loaded:
		badge = dimStyle.Render("loading…")
	case m.status.Active:
		badge = badgeOn.Render("● ACTIVE")
	default:
		badge = badgeOff.Render("○ INACTIVE")
	}
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(badge)-1)
	line1 := left + strings.Repeat(" ", gap) + badge

	policy := func(label, val string) string {
		if val == "" {
			val = "?"
		}
		return dimStyle.Render(label+" ") + actionStyle(val).Render(val)
	}
	logging := m.status.Logging
	if logging == "" {
		logging = "?"
	}
	sep := dimStyle.Render("  ·  ")
	line2 := " " + strings.Join([]string{
		policy("Incoming", m.status.Incoming),
		policy("Outgoing", m.status.Outgoing),
		policy("Routed", m.status.Routed),
		dimStyle.Render("Logging ") + logging,
	}, sep)

	return trunc(line1, m.width) + "\n" + trunc(line2, m.width) + "\n" + trunc(m.tabsView(), m.width)
}

func (m Model) tableView() string {
	rules := m.visible()

	// Column widths: fixed number and action columns, the rest is shared.
	const numW, actW, gaps = 4, 10, 5
	rest := max(30, m.width-numW-actW-gaps-2)
	toW := rest * 35 / 100
	fromW := rest * 30 / 100
	comW := rest - toW - fromW

	row := func(num, to, act, from, comment string) string {
		return " " + pad(num, numW) + " " + pad(to, toW) + " " + pad(act, actW) + " " + pad(from, fromW) + " " + pad(comment, comW)
	}

	var b strings.Builder
	b.WriteString(headStyle.Render(row("#", "To", "Action", "From", "Comment")) + "\n")

	if !m.loaded {
		return b.String() + "\n" + dimStyle.Render("  Loading firewall status…")
	}
	if len(rules) == 0 {
		msg := "  No rules yet. Press a to add one."
		if m.filter.Value() != "" {
			msg = "  No rules match the filter. Press esc to clear it."
		}
		return b.String() + "\n" + dimStyle.Render(msg)
	}

	end := min(len(rules), m.offset+m.rowsH())
	for i := m.offset; i < end; i++ {
		r := rules[i]
		num := "-"
		if r.Num > 0 {
			num = fmt.Sprintf("%3d", r.Num)
		}
		act := strings.TrimSpace(r.Action + " " + r.Dir)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(row(num, r.To, act, r.From, r.Comment)))
		} else {
			b.WriteString(" " + dimStyle.Render(pad(num, numW)) + " " + pad(r.To, toW) + " " +
				actionStyle(r.Action).Render(pad(act, actW)) + " " + pad(r.From, fromW) + " " +
				dimStyle.Render(pad(r.Comment, comW)))
		}
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (m Model) footerView() string {
	var line1 string
	switch {
	case m.mode == modeFilter:
		line1 = " " + m.filter.View()
	case m.notice != "" && m.noticeErr:
		line1 = " " + errStyle.Render("✗ "+m.notice)
	case m.notice != "":
		line1 = " " + okStyle.Render(m.notice)
	case m.filter.Value() != "":
		shown, total, what := len(m.visible()), len(m.status.Rules), "rules"
		if m.tab == tabPorts {
			shown, total, what = len(m.visiblePorts()), len(m.listeners), "ports"
		}
		line1 = " " + dimStyle.Render(fmt.Sprintf("filter: %q  (%d of %d %s, esc clears)", m.filter.Value(), shown, total, what))
	case m.loaded && m.tab == tabPorts:
		line1 = " " + dimStyle.Render("Firewall column: first rule naming the port, else the default incoming policy (estimate).")
	case m.loaded && !m.status.Active:
		line1 = " " + warnStyle.Render("Firewall is inactive: these rules are saved but not enforced. Press e to enable.")
	case m.loaded:
		n := len(m.status.Rules)
		line1 = " " + dimStyle.Render(fmt.Sprintf("%d rule%s", n, plural(n)))
	}

	var keys string
	switch m.mode {
	case modeFilter:
		keys = hints("enter", "keep", "esc", "clear")
	case modeList:
		toggle := "enable"
		if m.status.Active {
			toggle = "disable"
		}
		if m.tab == tabPorts {
			keys = hints("tab", "rules", "a", "add rule for port", "e", toggle, "p", "policy", "/", "filter", "r", "refresh", "?", "help", "q", "quit")
		} else {
			keys = hints("tab", "ports", "a", "add", "enter", "edit", "i", "insert", "d", "delete", "e", toggle, "p", "policy", "/", "filter", "?", "help", "q", "quit")
		}
	}
	return trunc(line1, m.width) + "\n" + trunc(" "+keys, m.width)
}

func (m Model) confirmView() string {
	c := m.confirm
	title, box := titleStyle, boxStyle
	if c.danger {
		title, box = errStyle.Bold(true), dangerBox
	}
	var b strings.Builder
	b.WriteString(title.Render(c.title) + "\n\n")
	for _, l := range c.lines {
		if c.danger && !strings.HasPrefix(l, "Runs:") && !strings.HasPrefix(l, "[") && !strings.HasPrefix(l, "The old rule") {
			l = warnStyle.Render(l)
		}
		b.WriteString(l + "\n")
	}
	if c.danger && overSSH() {
		b.WriteString(warnStyle.Render("You are connected over SSH.") + "\n")
	}
	b.WriteString("\n" + hints("y", "yes", "n/esc", "no"))
	return box.Render(b.String())
}

func (m Model) menuView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.menu.title) + "\n\n")
	for i, it := range m.menu.items {
		if i == m.menu.cursor {
			b.WriteString(selectedStyle.Render(" › "+pad(it, 12)) + "\n")
		} else {
			b.WriteString("   " + actionStyle(it).UnsetForeground().Render(it) + "\n")
		}
	}
	b.WriteString("\n" + hints("↑↓", "move", "enter", "select", "esc", "cancel"))
	return b.String()
}

func helpView() string {
	rows := [][2]string{
		{"tab", "switch between Rules and Ports in use"},
		{"↑/k ↓/j", "move selection"},
		{"g / G", "first / last rule"},
		{"pgup pgdn", "page up / down"},
		{"a", "add a rule (pre-filled from the selected port)"},
		{"enter", "edit the selected rule"},
		{"i", "insert a rule before the selected one"},
		{"d", "delete the selected rule"},
		{"e", "enable / disable the firewall"},
		{"p", "change a default policy"},
		{"l", "change the logging level"},
		{"R", "reload the firewall"},
		{"r", "refresh the list"},
		{"/", "filter rules (esc clears)"},
		{"q", "quit"},
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Keys") + "\n\n")
	for _, r := range rows {
		b.WriteString(keyStyle.Render(pad(r[0], 11)) + " " + r[1] + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("Rule order matters: ufw uses the first rule that matches.") + "\n")
	b.WriteString(dimStyle.Render("Every change asks for confirmation before it runs.") + "\n")
	b.WriteString("\n" + dimStyle.Render("press any key to close"))
	return b.String()
}

// dialog centres a box in the body area.
func (m Model) dialog(box string) string {
	return lipgloss.Place(m.width, m.bodyH(), lipgloss.Center, lipgloss.Center, box)
}

// fitLines makes s exactly h lines tall so the footer stays put.
func fitLines(s string, h int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// pad truncates or right-pads plain text to exactly w cells.
func pad(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	return s + strings.Repeat(" ", max(0, w-lipgloss.Width(s)))
}

func trunc(s string, w int) string {
	return ansi.Truncate(s, w, "…")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
