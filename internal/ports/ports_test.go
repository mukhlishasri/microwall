package ports

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	got := Parse(`udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=301,fd=13))
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1291,fd=7),("nginx",pid=1290,fd=7))
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096            [::]:22            [::]:*    users:(("sshd",pid=812,fd=4))
tcp   LISTEN 0      128                *:9090             *:*
tcp   LISTEN 0      128            [::1]:631           [::]:*    users:(("cupsd",pid=5,fd=6))
garbage line
`)
	want := []Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd", PID: 812},
		{Proto: "tcp", Addr: "::", Port: 22, Process: "sshd", PID: 812},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53, Process: "systemd-resolve", PID: 301},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 80, Process: "nginx", PID: 1291},
		{Proto: "tcp", Addr: "::1", Port: 631, Process: "cupsd", PID: 5},
		{Proto: "tcp", Addr: "*", Port: 9090},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if !got[2].Local() || !got[4].Local() || got[0].Local() {
		t.Error("Local() wrong")
	}
	if !got[0].V4Only() || got[1].V4Only() || got[5].V4Only() {
		t.Error("V4Only() wrong")
	}
}
