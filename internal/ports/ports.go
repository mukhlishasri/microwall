// Package ports lists the ports that programs on this machine are listening on.
package ports

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Listener is one listening socket.
type Listener struct {
	Proto   string // tcp or udp
	Addr    string // 0.0.0.0, ::, * (all addresses), or a specific address
	Port    int
	Process string // empty when unknown (needs root to see other users' processes)
	PID     int
}

// Local reports whether the socket is only reachable from this machine.
func (l Listener) Local() bool {
	return strings.HasPrefix(l.Addr, "127.") || l.Addr == "::1"
}

// V4Only reports whether the socket only accepts IPv4.
func (l Listener) V4Only() bool {
	return strings.Contains(l.Addr, ".") && !strings.Contains(l.Addr, ":")
}

// Lister returns the current listeners.
type Lister func() ([]Listener, error)

// System lists listeners with ss(8) from iproute2.
func System() ([]Listener, error) {
	bin, err := exec.LookPath("ss")
	if err != nil {
		return nil, errors.New("ss not found (install iproute2) so ports in use cannot be listed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-H", "-tulnp")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, errors.New("ss: " + msg)
		}
		return nil, err
	}
	return Parse(stdout.String()), nil
}

var procRe = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// Parse parses the output of "ss -H -tulnp".
func Parse(out string) []Listener {
	var list []Listener
	index := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		i := strings.LastIndex(f[4], ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(f[4][i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(f[4][:i], "[]")
		if j := strings.Index(addr, "%"); j >= 0 { // 127.0.0.53%lo
			addr = addr[:j]
		}
		l := Listener{Proto: f[0], Addr: addr, Port: port}

		// A socket can be shared by several processes (nginx workers);
		// show each distinct name once.
		var names []string
		for _, m := range procRe.FindAllStringSubmatch(line, -1) {
			if l.PID == 0 {
				l.PID, _ = strconv.Atoi(m[2])
			}
			if !contains(names, m[1]) {
				names = append(names, m[1])
			}
		}
		l.Process = strings.Join(names, ", ")

		key := l.Proto + "|" + l.Addr + "|" + strconv.Itoa(l.Port)
		if at, ok := index[key]; ok {
			if list[at].Process == "" {
				list[at] = l
			}
			continue
		}
		index[key] = len(list)
		list = append(list, l)
	}
	sort.SliceStable(list, func(a, b int) bool {
		if list[a].Port != list[b].Port {
			return list[a].Port < list[b].Port
		}
		if list[a].Proto != list[b].Proto {
			return list[a].Proto < list[b].Proto
		}
		return list[a].Addr < list[b].Addr
	})
	return list
}

// Demo returns a fixed list for --demo mode.
func Demo() ([]Listener, error) {
	return []Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd", PID: 812},
		{Proto: "tcp", Addr: "::", Port: 22, Process: "sshd", PID: 812},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53, Process: "systemd-resolve", PID: 301},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 80, Process: "nginx", PID: 1290},
		{Proto: "udp", Addr: "0.0.0.0", Port: 123, Process: "chronyd", PID: 655},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Process: "nginx", PID: 1290},
		{Proto: "tcp", Addr: "*", Port: 3000, Process: "node", PID: 4410},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 5432, Process: "postgres", PID: 990},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6379, Process: "redis-server", PID: 1012},
	}, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
