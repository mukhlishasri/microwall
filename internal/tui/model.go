// Package tui is the Bubble Tea user interface.
package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"microwall/internal/ports"
	"microwall/internal/ufw"
)

type mode int

const (
	modeList mode = iota
	modeFilter
	modeForm
	modeConfirm
	modeMenu
	modeHelp
)

type statusMsg struct {
	st        ufw.Status
	err       error
	listeners []ports.Listener
	portsErr  error
}

type opMsg struct {
	ok  string
	err error
}

// confirm is a yes/no dialog guarding a change.
type confirm struct {
	title  string
	lines  []string
	danger bool
	action tea.Cmd
}

// menu is a pick-one dialog.
type menu struct {
	title  string
	items  []string
	cursor int
	pick   func(m *Model, i int) tea.Cmd
}

type Model struct {
	fw     ufw.Firewall
	lister ports.Lister
	demo   bool

	status    ufw.Status
	listeners []ports.Listener
	portsErr  string
	loaded    bool
	busy      bool

	tab              int // tabRules or tabPorts
	cursor, offset   int // rules tab
	pcursor, poffset int // ports tab
	width, height    int

	mode    mode
	filter  textinput.Model
	form    form
	confirm confirm
	menu    menu

	// Set while the form is editing an existing rule instead of adding one.
	editing  bool
	editOld  ufw.Rule
	editTwin *ufw.Rule

	notice    string
	noticeErr bool
}

func New(fw ufw.Firewall, lister ports.Lister, demo bool) Model {
	fi := textinput.New()
	fi.Prompt = "/ "
	fi.Placeholder = "filter rules"
	fi.CharLimit = 60
	return Model{fw: fw, lister: lister, demo: demo, filter: fi}
}

func (m Model) Init() tea.Cmd { return m.refresh() }

func (m Model) refresh() tea.Cmd {
	fw, lister := m.fw, m.lister
	return func() tea.Msg {
		msg := statusMsg{}
		msg.st, msg.err = fw.Status()
		msg.listeners, msg.portsErr = lister()
		return msg
	}
}

// op runs a change in the background and reports ok or the error.
func op(ok string, f func() error) tea.Cmd {
	return func() tea.Msg { return opMsg{ok: ok, err: f()} }
}

func (m *Model) start(cmd tea.Cmd) tea.Cmd {
	m.mode = modeList
	m.busy = true
	m.notice, m.noticeErr = "Working…", false
	return cmd
}

// visible returns the rules matching the filter.
func (m Model) visible() []ufw.Rule {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	if q == "" {
		return m.status.Rules
	}
	var out []ufw.Rule
	for _, r := range m.status.Rules {
		hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s %s", r.Num, r.To, r.Action, r.Dir, r.From, r.Comment))
		if strings.Contains(hay, q) {
			out = append(out, r)
		}
	}
	return out
}

func (m Model) selected() (ufw.Rule, bool) {
	rules := m.visible()
	if m.cursor < 0 || m.cursor >= len(rules) {
		return ufw.Rule{}, false
	}
	return rules[m.cursor], true
}

// rowsH is how many rule rows fit on screen.
func (m Model) rowsH() int {
	return max(1, m.bodyH()-1)
}

// bodyH is the height between the header and the footer.
func (m Model) bodyH() int {
	return max(2, m.height-headerLines-footerLines)
}

// active returns the cursor, scroll offset and row count of the current tab.
func (m *Model) active() (cur, off *int, n int) {
	if m.tab == tabPorts {
		return &m.pcursor, &m.poffset, len(m.visiblePorts())
	}
	return &m.cursor, &m.offset, len(m.visible())
}

// clamp keeps the current tab's cursor in range and on screen.
func (m *Model) clamp() {
	cur, off, n := m.active()
	h := m.rowsH()
	*cur = max(0, min(*cur, n-1))
	if *cur < *off {
		*off = *cur
	}
	if *cur >= *off+h {
		*off = *cur - h + 1
	}
	*off = max(0, min(*off, max(0, n-h)))
}

func (m *Model) clampAll() {
	tab := m.tab
	for _, t := range []int{tabRules, tabPorts} {
		m.tab = t
		m.clamp()
	}
	m.tab = tab
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampAll()
		return m, nil

	case statusMsg:
		m.busy = false
		if msg.err != nil {
			m.notice, m.noticeErr = msg.err.Error(), true
			return m, nil
		}
		if m.notice == "Working…" || m.notice == "Refreshing…" {
			m.notice = ""
		}
		m.status, m.loaded = msg.st, true
		m.listeners, m.portsErr = msg.listeners, ""
		if msg.portsErr != nil {
			m.portsErr = oneLine(msg.portsErr.Error())
		}
		m.clampAll()
		return m, nil

	case opMsg:
		if msg.err != nil {
			m.notice, m.noticeErr = oneLine(msg.err.Error()), true
		} else {
			m.notice, m.noticeErr = msg.ok, false
		}
		return m, m.refresh()

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		switch m.mode {
		case modeFilter:
			return m.updateFilter(msg)
		case modeForm:
			return m.updateForm(msg)
		case modeConfirm:
			return m.updateConfirm(msg)
		case modeMenu:
			return m.updateMenu(msg)
		case modeHelp:
			m.mode = modeList
			return m, nil
		}
		return m.updateList(msg)
	}

	// Cursor blink and similar messages for whichever input is active.
	var cmd tea.Cmd
	switch m.mode {
	case modeFilter:
		m.filter, cmd = m.filter.Update(msg)
	case modeForm:
		if cur := &m.form.fields[m.form.focus]; cur.choices == nil {
			cur.input, cmd = cur.input.Update(msg)
		}
	}
	return m, cmd
}

func (m Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Navigation and read-only keys work even while a change is running.
	cur, _, n := m.active()
	switch key {
	case "q":
		return m, tea.Quit
	case "tab", "shift+tab", "left", "right":
		m.tab = (m.tab + 1) % 2
		m.notice = ""
	case "1":
		m.tab = tabRules
	case "2":
		m.tab = tabPorts
	case "up", "k":
		*cur--
	case "down", "j":
		*cur++
	case "pgup", "ctrl+b":
		*cur -= m.rowsH()
	case "pgdown", "ctrl+f":
		*cur += m.rowsH()
	case "home", "g":
		*cur = 0
	case "end", "G":
		*cur = n - 1
	case "?":
		m.mode = modeHelp
	case "/":
		m.mode = modeFilter
		return m, m.filter.Focus()
	case "esc":
		m.filter.SetValue("")
		m.notice = ""
	}
	m.clamp()

	if m.busy || !m.loaded {
		return m, nil
	}

	switch key {
	case "r":
		m.busy = true
		m.notice, m.noticeErr = "Refreshing…", false
		return m, m.refresh()

	case "a":
		m.editing = false
		m.form = newForm("")
		if l, ok := m.selectedPort(); ok && m.tab == tabPorts {
			m.form.prefill(l.Port, l.Proto)
		}
		m.mode = modeForm
		return m, textinput.Blink

	case "i":
		if m.tab == tabPorts {
			m.notice, m.noticeErr = "Insert works on the Rules tab. Press a to add a rule for this port.", true
			return m, nil
		}
		r, ok := m.selected()
		if !ok || r.Num == 0 {
			m.notice, m.noticeErr = "Insert needs a numbered rule selected (the firewall must be active)", true
			return m, nil
		}
		m.editing = false
		m.form = newForm(fmt.Sprint(r.Num))
		m.mode = modeForm
		return m, textinput.Blink

	case "enter":
		if m.tab == tabPorts {
			m.notice, m.noticeErr = "Edit works on the Rules tab. Press a to add a rule for this port.", true
			return m, nil
		}
		r, ok := m.selected()
		if !ok {
			return m, nil
		}
		twin, hasTwin := ufw.Twin(m.status.Rules, r)
		spec, err := ufw.SpecFromRule(r, hasTwin)
		if err != nil {
			m.notice, m.noticeErr = "Can't edit this rule: "+err.Error(), true
			return m, nil
		}
		m.form = newForm(fmt.Sprint(r.Num))
		m.form.load(spec)
		m.form.title = fmt.Sprintf("Edit rule %d", r.Num)
		m.editing, m.editOld, m.editTwin = true, r, nil
		if hasTwin {
			m.editTwin = &twin
			family := "IPv6"
			if r.V6 {
				family = "IPv4"
			}
			m.form.note = fmt.Sprintf("Also replaces its %s twin, rule %d.", family, twin.Num)
		}
		m.mode = modeForm
		return m, textinput.Blink

	case "d", "delete", "x":
		if m.tab == tabPorts {
			m.notice, m.noticeErr = "Delete works on the Rules tab (press tab).", true
			return m, nil
		}
		r, ok := m.selected()
		if !ok {
			return m, nil
		}
		m.confirm = confirm{
			title:  "Delete this rule?",
			lines:  []string{describe(r)},
			danger: true,
			action: m.deleteCmd(r),
		}
		m.mode = modeConfirm

	case "e":
		m.confirm = m.toggleConfirm()
		m.mode = modeConfirm

	case "R":
		fw := m.fw
		m.confirm = confirm{
			title:  "Reload the firewall?",
			lines:  []string{"Runs: ufw reload"},
			action: op("Firewall reloaded", fw.Reload),
		}
		m.mode = modeConfirm

	case "p":
		m.menu = menu{title: "Default policy for…", items: ufw.Chains, pick: pickChain}
		m.mode = modeMenu

	case "l":
		m.menu = menu{title: "Logging level", items: ufw.LogLevels, pick: pickLogging}
		for i, lvl := range ufw.LogLevels {
			if strings.Contains(m.status.Logging, lvl) {
				m.menu.cursor = i
			}
		}
		m.mode = modeMenu
	}
	return m, nil
}

func (m Model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filter.Blur()
		m.mode = modeList
		return m, nil
	case "esc":
		m.filter.SetValue("")
		m.filter.Blur()
		m.mode = modeList
		m.clampAll()
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.cursor, m.offset, m.pcursor, m.poffset = 0, 0, 0, 0
	return m, cmd
}

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeList
		return m, nil
	case "enter":
		spec := m.form.spec()
		if err := spec.Validate(); err != nil {
			m.form.err = err.Error()
			return m, nil
		}
		fw := m.fw
		if m.editing {
			old, twin := m.editOld, m.editTwin
			// Changing only the action or comment is an in-place update in
			// ufw, without a position; anything else is add-then-remove.
			how := "The old rule is then removed automatically."
			if ufw.InPlace(old, twin != nil, spec) {
				spec.Position = ""
				how = "ufw updates the rule in place."
			}
			c := confirm{
				title:  "Change this rule?",
				lines:  []string{describe(old)},
				action: op("Rule updated: "+spec.CommandLine(), func() error { return ufw.Replace(fw, old, twin, spec) }),
			}
			if twin != nil {
				c.lines = append(c.lines, describe(*twin))
			}
			c.lines = append(c.lines, "", "Runs: "+spec.CommandLine(), how)
			if (Model{status: ufw.Status{Rules: []ufw.Rule{old}}}).allowsSSH() {
				c.danger = true
				c.lines = append(c.lines, "", "This rule appears to allow SSH.", "Check that the new rule still lets you in.")
			}
			m.confirm = c
			m.mode = modeConfirm
			return m, nil
		}
		return m, m.start(op("Added: "+spec.CommandLine(), func() error { return fw.Add(spec) }))
	}
	return m, m.form.update(msg)
}

func (m Model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		return m, m.start(m.confirm.action)
	case "n", "N", "esc", "q", "enter":
		m.mode = modeList
	}
	return m, nil
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := len(m.menu.items)
	switch msg.String() {
	case "esc", "q":
		m.mode = modeList
	case "up", "k":
		m.menu.cursor = (m.menu.cursor - 1 + n) % n
	case "down", "j":
		m.menu.cursor = (m.menu.cursor + 1) % n
	case "enter", " ":
		return m, m.menu.pick(&m, m.menu.cursor)
	}
	return m, nil
}

func pickChain(m *Model, i int) tea.Cmd {
	chain := ufw.Chains[i]
	current := map[string]string{"incoming": m.status.Incoming, "outgoing": m.status.Outgoing, "routed": m.status.Routed}[chain]
	m.menu = menu{
		title: "Default policy for " + chain,
		items: ufw.Policies,
		pick: func(m *Model, j int) tea.Cmd {
			policy := ufw.Policies[j]
			fw := m.fw
			c := confirm{
				title:  fmt.Sprintf("Set default %s policy to %s?", chain, policy),
				lines:  []string{fmt.Sprintf("Runs: ufw default %s %s", policy, chain)},
				action: op(fmt.Sprintf("Default %s policy is now %s", chain, policy), func() error { return fw.SetDefault(chain, policy) }),
			}
			if chain == "incoming" && policy != "allow" && m.status.Active && !m.allowsSSH() {
				c.danger = true
				c.lines = append(c.lines, "", "No rule appears to allow SSH (port 22).", "If you are connected over SSH you may be locked out.")
			}
			if chain == "incoming" && policy == "allow" {
				c.danger = true
				c.lines = append(c.lines, "", "Every port without a deny rule becomes reachable.")
			}
			m.confirm = c
			m.mode = modeConfirm
			return nil
		},
	}
	for j, p := range ufw.Policies {
		if p == current {
			m.menu.cursor = j
		}
	}
	return nil
}

func pickLogging(m *Model, i int) tea.Cmd {
	level := ufw.LogLevels[i]
	fw := m.fw
	return m.start(op("Logging set to "+level, func() error { return fw.SetLogging(level) }))
}

func (m Model) toggleConfirm() confirm {
	fw := m.fw
	if m.status.Active {
		return confirm{
			title:  "Disable the firewall?",
			lines:  []string{"Runs: ufw disable", "", "All ports will be unfiltered until it is enabled again."},
			danger: true,
			action: op("Firewall disabled", fw.Disable),
		}
	}
	c := confirm{
		title:  "Enable the firewall?",
		lines:  []string{"Runs: ufw --force enable", "", "It will also start on boot."},
		action: op("Firewall enabled", fw.Enable),
	}
	if !m.allowsSSH() && m.status.Incoming != "allow" {
		c.danger = true
		c.lines = append(c.lines, "", "No rule appears to allow SSH (port 22).", "If you are connected over SSH you may be locked out.")
	}
	return c
}

// allowsSSH is a heuristic: is there an inbound allow/limit rule mentioning SSH?
func (m Model) allowsSSH() bool {
	for _, r := range m.status.Rules {
		if r.Action != "ALLOW" && r.Action != "LIMIT" {
			continue
		}
		if r.Dir == "OUT" {
			continue
		}
		text := strings.ToLower(r.To + " " + r.Spec)
		if strings.Contains(text, "ssh") {
			return true
		}
		for _, tok := range strings.FieldsFunc(text, func(c rune) bool { return c < '0' || c > '9' }) {
			if tok == "22" {
				return true
			}
		}
	}
	return false
}

// deleteCmd deletes r after checking that it is still the rule ufw has at
// that number, since rule numbers shift whenever rules change.
func (m Model) deleteCmd(r ufw.Rule) tea.Cmd {
	fw := m.fw
	return op("Deleted: "+describe(r), func() error {
		st, err := fw.Status()
		if err != nil {
			return err
		}
		for _, cur := range st.Rules {
			if cur == r {
				return fw.Delete(r)
			}
		}
		return errors.New("rules changed since the list was loaded; nothing deleted, list refreshed")
	})
}

func describe(r ufw.Rule) string {
	var b strings.Builder
	if r.Num > 0 {
		fmt.Fprintf(&b, "[%d] ", r.Num)
	}
	b.WriteString(r.Action)
	if r.Dir != "" {
		b.WriteString(" " + r.Dir)
	}
	b.WriteString("  " + r.To)
	if r.From != "" {
		b.WriteString("  from " + r.From)
	}
	if r.Comment != "" {
		b.WriteString("  # " + r.Comment)
	}
	return b.String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// overSSH reports whether this session looks like a remote one.
func overSSH() bool {
	return os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
}
