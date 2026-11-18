package tui

import "github.com/charmbracelet/lipgloss"

var (
	colGreen  = lipgloss.Color("42")
	colRed    = lipgloss.Color("203")
	colYellow = lipgloss.Color("220")
	colOrange = lipgloss.Color("208")
	colAccent = lipgloss.Color("75")
	colDim    = lipgloss.Color("244")

	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	dimStyle      = lipgloss.NewStyle().Foreground(colDim)
	boldStyle     = lipgloss.NewStyle().Bold(true)
	errStyle      = lipgloss.NewStyle().Foreground(colRed)
	okStyle       = lipgloss.NewStyle().Foreground(colGreen)
	warnStyle     = lipgloss.NewStyle().Foreground(colYellow)
	keyStyle      = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	headStyle     = lipgloss.NewStyle().Bold(true).Foreground(colDim).Underline(true)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("24"))
	badgeOn       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("232")).Background(colGreen).Padding(0, 1)
	badgeOff      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("160")).Padding(0, 1)
	badgeDemo     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("232")).Background(colYellow).Padding(0, 1)
	boxStyle      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colAccent).Padding(1, 2)
	dangerBox     = boxStyle.BorderForeground(colRed)
	choiceFocus   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("24")).Padding(0, 1)
	choiceOn      = lipgloss.NewStyle().Bold(true).Foreground(colAccent).Padding(0, 1)
	choiceOff     = lipgloss.NewStyle().Foreground(colDim).Padding(0, 1)
)

// actionStyle colours a rule action or policy word.
func actionStyle(action string) lipgloss.Style {
	switch action {
	case "ALLOW", "allow":
		return lipgloss.NewStyle().Foreground(colGreen)
	case "DENY", "deny":
		return lipgloss.NewStyle().Foreground(colRed)
	case "REJECT", "reject":
		return lipgloss.NewStyle().Foreground(colOrange)
	case "LIMIT", "limit":
		return lipgloss.NewStyle().Foreground(colYellow)
	}
	return dimStyle
}
