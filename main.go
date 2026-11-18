// microwall is a terminal UI for the ufw firewall that also shows the ports in use.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"microwall/internal/ports"
	"microwall/internal/tui"
	"microwall/internal/ufw"
)

var version = "dev"

func main() {
	demo := flag.Bool("demo", false, "run against a fake in-memory firewall (no root, changes nothing)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "microwall - terminal UI for ufw and listening ports\n\nUsage: microwall [flags]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("microwall", version)
		return
	}

	var fw ufw.Firewall
	lister := ports.Lister(ports.System)
	if *demo {
		fw = ufw.NewDemo()
		lister = ports.Demo
	} else {
		cli, err := ufw.NewCLI()
		if err != nil {
			fatal(err)
		}
		if os.Geteuid() != 0 {
			fatal(rerunWithSudo())
		}
		fw = cli
	}

	if _, err := tea.NewProgram(tui.New(fw, lister, *demo), tea.WithAltScreen()).Run(); err != nil {
		fatal(err)
	}
}

// rerunWithSudo replaces this process with "sudo microwall ...". It only
// returns if that failed.
func rerunWithSudo() error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("ufw needs root: run microwall as root, or use --demo to try it without")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "ufw needs root, re-running with sudo...")
	return syscall.Exec(sudo, append([]string{"sudo", exe}, os.Args[1:]...), os.Environ())
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "microwall:", err)
	os.Exit(1)
}
