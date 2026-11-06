// Command fakestdio is a fake stdio upstream for tests. It echoes every stdin line to stdout,
// except these commands:
//
//	env           print the environment as a JSON array
//	args          print os.Args[1:] as a JSON array
//	stderr N      write N lines "line i" to stderr, then print "ok"
//	stderrlong N  write one N-byte line to stderr, then print "ok"
//	child         start a grandchild in the same process group, print its PID
//	detach        start a grandchild in its own session (outside the group), print its PID
//	block         print "blocking", then never read stdin again
//	crash         exit with status 3
//
// Flag -stubborn ignores SIGTERM and keeps running after stdin closes. Mode "sleep" (first
// argument) blocks forever, ignoring SIGTERM; it is the grandchild.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		signal.Ignore(syscall.SIGTERM)
		hang()
	}
	stubborn := false
	for _, a := range os.Args[1:] {
		if a == "-stubborn" {
			stubborn = true
			signal.Ignore(syscall.SIGTERM)
		}
	}
	out := bufio.NewWriter(os.Stdout)
	reply := func(v any) {
		if s, ok := v.(string); ok {
			fmt.Fprintln(out, s)
		} else {
			b, _ := json.Marshal(v)
			fmt.Fprintln(out, string(b))
		}
		_ = out.Flush()
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		cmd, arg, _ := strings.Cut(line, " ")
		switch cmd {
		case "env":
			reply(os.Environ())
		case "args":
			reply(os.Args[1:])
		case "stderr":
			n, _ := strconv.Atoi(arg)
			for i := range n {
				fmt.Fprintf(os.Stderr, "line %d\n", i)
			}
			reply("ok")
		case "stderrlong":
			n, _ := strconv.Atoi(arg)
			fmt.Fprintln(os.Stderr, strings.Repeat("x", n))
			reply("ok")
		case "child":
			c := exec.Command(os.Args[0], "sleep")
			c.Stdout, c.Stderr = os.Stdout, os.Stderr // holds the pipes open while it lives
			if err := c.Start(); err != nil {
				reply("error " + err.Error())
				continue
			}
			reply(strconv.Itoa(c.Process.Pid))
		case "detach":
			c := exec.Command(os.Args[0], "sleep")
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := c.Start(); err != nil {
				reply("error " + err.Error())
				continue
			}
			reply(strconv.Itoa(c.Process.Pid))
		case "block":
			reply("blocking")
			hang()
		case "crash":
			os.Exit(3)
		default:
			reply(line)
		}
	}
	if stubborn {
		hang()
	}
}

// hang blocks forever. A bare select{} would let the runtime's deadlock detector end the
// program once no other goroutine exists.
func hang() {
	for {
		time.Sleep(time.Hour)
	}
}
