# microwall

A terminal UI for the [ufw](https://launchpad.net/ufw) firewall that also shows
which ports are in use (via `ss`), written in Go with
[Bubble Tea](https://github.com/charmbracelet/bubbletea).

## Run

```sh
CGO_ENABLED=0 go build -o microwall .
./microwall          # re-runs itself with sudo, ufw needs root
./microwall --demo   # fake in-memory firewall: no root, changes nothing
sudo install -m 0755 microwall /usr/local/bin/   # optional
```

## Keys

| Key | Action |
| --- | --- |
| `↑`/`k` `↓`/`j` `g` `G` | move |
| `tab` | switch between **Rules** and **Ports in use** |
| `a` | add a rule (on the ports tab, pre-filled with the selected port) |
| `i` | insert a rule before the selected one |
| `d` | delete the selected rule |
| `e` | enable / disable the firewall |
| `p` | change a default policy (incoming, outgoing, routed) |
| `l` | change the logging level |
| `R` | reload |
| `r` | refresh |
| `/` | filter (`esc` clears) |
| `?` | help |
| `q` | quit |

Every change shows the `ufw` command it will run and asks for confirmation.
Enabling the firewall or tightening the incoming policy warns when no rule
appears to allow SSH.

The **Ports in use** tab lists listening sockets (from `ss -tulnp`) with the
owning process and an estimate of how the firewall treats each port: the first
rule that names the port, otherwise the default incoming policy. Rules without
a port (whole-host rules, application profiles) are not taken into account.

## Layout

- `main.go`: flags, root check, starts the program
- `internal/ufw`: the `Firewall` interface, the real `CLI` implementation
  (shells out to `ufw` and parses its output), and the `Demo` fake
- `internal/ports`: lists listening ports by parsing `ss`
- `internal/tui`: the Bubble Tea model, views and the add-rule form

## Develop

```sh
CGO_ENABLED=0 go test ./...
```

`CGO_ENABLED=0` gives a static binary and avoids needing a C toolchain.
