package ufw

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	numberedRe = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)\s*$`)
	commentRe  = regexp.MustCompile(`^(.*?)\s+#\s?(.*)$`)
	defaultRe  = regexp.MustCompile(`(\w+) \((incoming|outgoing|routed)\)`)
	addedRe    = regexp.MustCompile(`^(.*?)(?:\s+comment '(.*)')?$`)
)

// ParseNumbered parses the output of "ufw status numbered".
func ParseNumbered(out string) (active bool, rules []Rule) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r ")
		if strings.HasPrefix(line, "Status:") {
			active = strings.TrimSpace(strings.TrimPrefix(line, "Status:")) == "active"
			continue
		}
		m := numberedRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		r := Rule{Num: n, To: m[2], Action: m[3], Dir: m[4], From: m[5]}
		if c := commentRe.FindStringSubmatch(r.From); c != nil {
			r.From, r.Comment = c[1], c[2]
		}
		r.To = strings.Join(strings.Fields(r.To), " ")
		r.From = strings.Join(strings.Fields(r.From), " ")
		r.V6 = strings.Contains(r.To, "(v6)") || strings.Contains(r.From, "(v6)")
		rules = append(rules, r)
	}
	return active, rules
}

// ParseVerbose fills the logging level and default policies from the output
// of "ufw status verbose".
func ParseVerbose(out string, st *Status) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Logging:"):
			st.Logging = strings.TrimSpace(strings.TrimPrefix(line, "Logging:"))
		case strings.HasPrefix(line, "Default:"):
			for _, m := range defaultRe.FindAllStringSubmatch(line, -1) {
				switch m[2] {
				case "incoming":
					st.Incoming = m[1]
				case "outgoing":
					st.Outgoing = m[1]
				case "routed":
					st.Routed = m[1]
				}
			}
		}
	}
}

// ParseAdded parses the output of "ufw show added", which is the only way to
// list rules while the firewall is inactive.
func ParseAdded(out string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ufw ") {
			continue
		}
		m := addedRe.FindStringSubmatch(strings.TrimPrefix(line, "ufw "))
		spec, comment := m[1], m[2]
		fields := strings.Fields(spec)
		if len(fields) == 0 {
			continue
		}
		r := Rule{Spec: spec, Comment: comment}
		// "route allow ..." puts the action second.
		i := 0
		if fields[0] == "route" && len(fields) > 1 {
			i = 1
			r.Dir = "FWD"
		}
		r.Action = strings.ToUpper(fields[i])
		r.To = strings.Join(fields[i+1:], " ")
		rules = append(rules, r)
	}
	return rules
}

// ParseConfig reads KEY=value lines as found in /etc/default/ufw and
// /etc/ufw/ufw.conf.
func ParseConfig(content string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

// policyName converts an iptables policy from /etc/default/ufw to ufw's word.
func policyName(p string) string {
	switch strings.ToUpper(p) {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	case "REJECT":
		return "reject"
	}
	return strings.ToLower(p)
}
