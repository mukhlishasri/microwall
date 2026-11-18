package ufw

import (
	"reflect"
	"strings"
	"testing"
)

const numberedOut = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     LIMIT IN    Anywhere                   # ssh
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] Anywhere                   DENY IN     203.0.113.7
[ 4] 25/tcp                     REJECT OUT  Anywhere                   (out)
[ 5] 8080/tcp on eth0           ALLOW IN    10.0.0.0/24                # app # 2
[ 6] 192.168.1.10 5432/tcp      ALLOW FWD   Anywhere
[ 7] Nginx Full                 ALLOW IN    Anywhere
[ 8] 22/tcp (v6)                LIMIT IN    Anywhere (v6)              # ssh
[10] Anywhere                   ALLOW       1.2.3.4
`

func TestParseNumbered(t *testing.T) {
	active, rules := ParseNumbered(numberedOut)
	if !active {
		t.Fatal("want active")
	}
	want := []Rule{
		{Num: 1, To: "22/tcp", Action: "LIMIT", Dir: "IN", From: "Anywhere", Comment: "ssh"},
		{Num: 2, To: "80,443/tcp", Action: "ALLOW", Dir: "IN", From: "Anywhere"},
		{Num: 3, To: "Anywhere", Action: "DENY", Dir: "IN", From: "203.0.113.7"},
		{Num: 4, To: "25/tcp", Action: "REJECT", Dir: "OUT", From: "Anywhere (out)"},
		{Num: 5, To: "8080/tcp on eth0", Action: "ALLOW", Dir: "IN", From: "10.0.0.0/24", Comment: "app # 2"},
		{Num: 6, To: "192.168.1.10 5432/tcp", Action: "ALLOW", Dir: "FWD", From: "Anywhere"},
		{Num: 7, To: "Nginx Full", Action: "ALLOW", Dir: "IN", From: "Anywhere"},
		{Num: 8, To: "22/tcp (v6)", Action: "LIMIT", Dir: "IN", From: "Anywhere (v6)", Comment: "ssh", V6: true},
		{Num: 10, To: "Anywhere", Action: "ALLOW", From: "1.2.3.4"},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d:\n got %+v\nwant %+v", i, rules[i], want[i])
		}
	}
}

func TestParseNumberedInactive(t *testing.T) {
	active, rules := ParseNumbered("Status: inactive\n")
	if active || len(rules) != 0 {
		t.Fatalf("got active=%v rules=%v", active, rules)
	}
}

func TestParseVerbose(t *testing.T) {
	var st Status
	ParseVerbose(`Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
`, &st)
	want := Status{Logging: "on (low)", Incoming: "deny", Outgoing: "allow", Routed: "disabled"}
	if !reflect.DeepEqual(st, want) {
		t.Fatalf("got %+v", st)
	}
}

func TestParseAdded(t *testing.T) {
	rules := ParseAdded(`Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp comment 'ssh access'
ufw deny from 203.0.113.7
ufw route allow in on eth0 out on eth1
`)
	want := []Rule{
		{Spec: "allow 22/tcp", Action: "ALLOW", To: "22/tcp", Comment: "ssh access"},
		{Spec: "deny from 203.0.113.7", Action: "DENY", To: "from 203.0.113.7"},
		{Spec: "route allow in on eth0 out on eth1", Action: "ALLOW", Dir: "FWD", To: "in on eth0 out on eth1"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("got %+v", rules)
	}
	if got := ParseAdded("Added user rules (see 'ufw status' for running firewall):\n(None)\n"); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseConfig(t *testing.T) {
	kv := ParseConfig("# c\nDEFAULT_INPUT_POLICY=\"DROP\"\nLOGLEVEL=low\n")
	if policyName(kv["DEFAULT_INPUT_POLICY"]) != "deny" || kv["LOGLEVEL"] != "low" {
		t.Fatalf("got %v", kv)
	}
}

func TestRuleSpecArgs(t *testing.T) {
	cases := []struct {
		spec RuleSpec
		want string
	}{
		{RuleSpec{Action: "allow", Direction: "in", Proto: "tcp", Port: "22", From: "any", To: "any"},
			"ufw allow in proto tcp from any to any port 22"},
		{RuleSpec{Action: "deny", Direction: "in", Proto: "any", From: "203.0.113.7"},
			"ufw deny in from 203.0.113.7 to any"},
		{RuleSpec{Action: "limit", Direction: "in", Interface: "eth0", Proto: "tcp", Port: "80,443", From: "10.0.0.0/24", To: "10.0.0.5", Comment: "web lan", Position: "2"},
			"ufw insert 2 limit in on eth0 proto tcp from 10.0.0.0/24 to 10.0.0.5 port 80,443 comment 'web lan'"},
	}
	for _, c := range cases {
		if err := c.spec.Validate(); err != nil {
			t.Errorf("%s: unexpected error %v", c.want, err)
		}
		if got := c.spec.CommandLine(); got != c.want {
			t.Errorf("got  %s\nwant %s", got, c.want)
		}
	}
}

func TestRuleSpecValidate(t *testing.T) {
	base := RuleSpec{Action: "allow", Direction: "in", Proto: "tcp", Port: "22", From: "any", To: "any"}
	bad := map[string]func(*RuleSpec){
		"range":         func(s *RuleSpec) { s.Port = "70000" },
		"need protocol": func(s *RuleSpec) { s.Port = "80,443"; s.Proto = "any" },
		"invalid port":  func(s *RuleSpec) { s.Port = "22;rm" },
		"from must":     func(s *RuleSpec) { s.From = "not-an-ip" },
		"too broad":     func(s *RuleSpec) { s.Port = "" },
		"comments":      func(s *RuleSpec) { s.Comment = "it's" },
		"position":      func(s *RuleSpec) { s.Position = "0" },
		"interface":     func(s *RuleSpec) { s.Interface = "eth 0" },
		"unknown actio": func(s *RuleSpec) { s.Action = "nuke" },
	}
	for wantSub, mutate := range bad {
		s := base
		mutate(&s)
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%q: got %v", wantSub, err)
		}
	}
	for _, port := range []string{"22", "6000:6007", "ssh"} {
		s := base
		s.Port = port
		if err := s.Validate(); err != nil {
			t.Errorf("port %q: %v", port, err)
		}
	}
}

func TestDemo(t *testing.T) {
	d := NewDemo()
	st, _ := d.Status()
	n := len(st.Rules)
	if err := d.Add(RuleSpec{Action: "allow", Direction: "in", Proto: "udp", Port: "53", Position: "1"}); err != nil {
		t.Fatal(err)
	}
	st, _ = d.Status()
	if len(st.Rules) != n+1 || st.Rules[0].To != "53/udp" || st.Rules[1].Num != 2 {
		t.Fatalf("got %+v", st.Rules[:2])
	}
	if err := d.Delete(st.Rules[0]); err != nil {
		t.Fatal(err)
	}
	st, _ = d.Status()
	if len(st.Rules) != n || st.Rules[0].To != "22/tcp" {
		t.Fatalf("got %+v", st.Rules[0])
	}
}
