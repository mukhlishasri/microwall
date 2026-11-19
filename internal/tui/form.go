package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"microwall/internal/ufw"
)

// Indexes into form.fields.
const (
	fAction = iota
	fDirection
	fProto
	fPort
	fFrom
	fTo
	fInterface
	fComment
	fPosition
)

// field is either a choice (choices != nil) or a text input.
type field struct {
	label   string
	choices []string
	sel     int
	input   textinput.Model
}

func (f field) value() string {
	if f.choices != nil {
		return f.choices[f.sel]
	}
	return strings.TrimSpace(f.input.Value())
}

type form struct {
	fields []field
	focus  int
	err    string
	title  string // overrides the default "Add rule" / "Insert rule"
	note   string // shown under the title
}

func choiceField(label string, choices []string) field {
	return field{label: label, choices: choices}
}

func textField(label, placeholder string) field {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = placeholder
	in.CharLimit = 80
	in.Width = 36
	return field{label: label, input: in}
}

// newForm builds the add-rule form. position pre-fills the insert position.
func newForm(position string) form {
	f := form{fields: []field{
		fAction:    choiceField("Action", ufw.Actions),
		fDirection: choiceField("Direction", ufw.Directions),
		fProto:     choiceField("Protocol", ufw.Protos),
		fPort:      textField("Port", "22, 80,443, 6000:6007 (blank = all)"),
		fFrom:      textField("From", "any, 10.0.0.5 or 10.0.0.0/24"),
		fTo:        textField("To", "any"),
		fInterface: textField("Interface", "any (e.g. eth0)"),
		fComment:   textField("Comment", "optional"),
		fPosition:  textField("Position", "append (or a rule number)"),
	}}
	f.fields[fProto].sel = 1 // tcp
	f.fields[fPosition].input.SetValue(position)
	f.focus = fPort
	f.fields[f.focus].input.Focus()
	return f
}

// prefill sets the port and protocol, for adding a rule from the ports tab.
func (f *form) prefill(port int, proto string) {
	f.fields[fPort].input.SetValue(fmt.Sprint(port))
	f.fields[fPort].input.CursorEnd()
	for i, p := range ufw.Protos {
		if p == proto {
			f.fields[fProto].sel = i
		}
	}
}

// load fills the form from an existing rule, for editing.
func (f *form) load(s ufw.RuleSpec) {
	choose := func(i int, val string) {
		for j, c := range f.fields[i].choices {
			if c == val {
				f.fields[i].sel = j
			}
		}
	}
	text := func(i int, val string) {
		if val == "any" {
			val = ""
		}
		f.fields[i].input.SetValue(val)
		f.fields[i].input.CursorEnd()
	}
	choose(fAction, s.Action)
	choose(fDirection, s.Direction)
	choose(fProto, s.Proto)
	text(fPort, s.Port)
	text(fFrom, s.From)
	text(fTo, s.To)
	text(fInterface, s.Interface)
	text(fComment, s.Comment)
}

func (f *form) spec() ufw.RuleSpec {
	v := func(i int) string { return f.fields[i].value() }
	return ufw.RuleSpec{
		Action:    v(fAction),
		Direction: v(fDirection),
		Proto:     v(fProto),
		Port:      v(fPort),
		From:      v(fFrom),
		To:        v(fTo),
		Interface: v(fInterface),
		Comment:   v(fComment),
		Position:  v(fPosition),
	}
}

func (f *form) move(delta int) tea.Cmd {
	f.fields[f.focus].input.Blur()
	n := len(f.fields)
	f.focus = (f.focus + delta + n) % n
	cur := &f.fields[f.focus]
	if cur.choices == nil {
		return cur.input.Focus()
	}
	return nil
}

// update handles a key that is not enter/esc.
func (f *form) update(msg tea.KeyMsg) tea.Cmd {
	f.err = ""
	switch msg.String() {
	case "tab", "down":
		return f.move(1)
	case "shift+tab", "up":
		return f.move(-1)
	}
	cur := &f.fields[f.focus]
	if cur.choices == nil {
		var cmd tea.Cmd
		cur.input, cmd = cur.input.Update(msg)
		return cmd
	}
	n := len(cur.choices)
	switch key := msg.String(); key {
	case "left", "h":
		cur.sel = (cur.sel - 1 + n) % n
	case "right", "l", " ":
		cur.sel = (cur.sel + 1) % n
	default:
		// A letter jumps to the choice starting with it.
		for i, c := range cur.choices {
			if len(key) == 1 && strings.HasPrefix(c, key) {
				cur.sel = i
				break
			}
		}
	}
	return nil
}

func (f form) view() string {
	var b strings.Builder
	title := "Add rule"
	if f.fields[fPosition].value() != "" {
		title = "Insert rule"
	}
	if f.title != "" {
		title = f.title
	}
	b.WriteString(titleStyle.Render(title) + "\n")
	if f.note != "" {
		b.WriteString(dimStyle.Render(f.note) + "\n")
	}
	b.WriteString("\n")

	for i, fl := range f.fields {
		focused := i == f.focus
		label := fl.label + strings.Repeat(" ", 11-len(fl.label))
		if focused {
			b.WriteString(keyStyle.Render("› " + label))
		} else {
			b.WriteString(dimStyle.Render("  " + label))
		}
		if fl.choices == nil {
			b.WriteString(" " + fl.input.View())
		} else {
			for j, c := range fl.choices {
				switch {
				case j == fl.sel && focused:
					b.WriteString(choiceFocus.Render(c))
				case j == fl.sel:
					b.WriteString(choiceOn.Render(c))
				default:
					b.WriteString(choiceOff.Render(c))
				}
			}
		}
		b.WriteString("\n")
	}

	spec := f.spec()
	b.WriteString("\n" + dimStyle.Render("$ ") + spec.CommandLine() + "\n")
	switch {
	case f.err != "":
		b.WriteString(errStyle.Render("✗ "+f.err) + "\n")
	default:
		b.WriteString("\n")
	}
	b.WriteString("\n" + hints("tab/↑↓", "move", "←→", "choose", "enter", "apply", "esc", "cancel"))
	return b.String()
}

// hints renders "key desc" pairs.
func hints(pairs ...string) string {
	parts := make([]string, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+dimStyle.Render(pairs[i+1]))
	}
	return strings.Join(parts, dimStyle.Render("  "))
}
