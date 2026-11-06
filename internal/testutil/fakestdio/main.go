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
// Flag -mcp makes it a JSON-RPC server instead (see serveMCP); with -stubborn as well, it then
// keeps running after stdin closes, ignoring SIGTERM. Flag -init=error, -init=exit or -init=hold
// makes initialize fail with a JSON-RPC error, exit the process, or never be answered;
// -init=lognerror sends a notifications/message first, then the error; -init=lognhold sends the
// notification and never answers.
//
// Flag -stubborn keeps running after stdin closes and after SIGTERM, printing "stdin closed" and
// "got SIGTERM" to stdout when they happen. Mode "sleep" (first
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
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		signal.Ignore(syscall.SIGTERM)
		hang()
	}
	stubborn, mcp := false, false
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "-init="); ok {
			initMode = v
			continue
		}
		switch a {
		case "-stubborn":
			stubborn = true
		case "-mcp":
			mcp = true
		}
	}
	if mcp {
		serveMCP()
		if stubborn {
			signal.Ignore(syscall.SIGTERM)
			hang()
		}
		return
	}
	out := bufio.NewWriter(os.Stdout)
	var mu sync.Mutex
	reply := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		if s, ok := v.(string); ok {
			_, _ = fmt.Fprintln(out, s)
		} else {
			b, _ := json.Marshal(v)
			_, _ = fmt.Fprintln(out, string(b))
		}
		_ = out.Flush()
	}
	if stubborn {
		terms := make(chan os.Signal, 1)
		signal.Notify(terms, syscall.SIGTERM)
		go func() {
			for range terms {
				reply("got SIGTERM")
			}
		}()
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
			c := exec.Command(os.Args[0], "sleep")    //nolint:gosec // G204: re-runs this test binary
			c.Stdout, c.Stderr = os.Stdout, os.Stderr // holds the pipes open while it lives
			if err := c.Start(); err != nil {
				reply("error " + err.Error())
				continue
			}
			reply(strconv.Itoa(c.Process.Pid))
		case "detach":
			c := exec.Command(os.Args[0], "sleep") //nolint:gosec // G204: re-runs this test binary
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
		reply("stdin closed")
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

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// serveMCP answers JSON-RPC requests on stdin by method:
//
//	initialize   a 2025-11-25 InitializeResult
//	echo         its params as the result
//	line         the request's stdin line, exactly as received, as a JSON string result
//	noresult     a response with neither result nor error
//	progress     two notifications/progress, then the result
//	ask          a sampling/createMessage request to the client; the result is the client's answer
//	hold         no answer until a later "release" request
//	release      answers itself and every held request
//	announce     the result, then a notifications/message after 50 ms (outside any request)
//	raw          the result, written with a bare CR as whitespace
//	env          the environment as the result
//	asklater     the result, then a sampling/createMessage request after 50 ms (outside any request)
//	floodlater   the result, then params.n notifications/message with params.i = 0..n-1 (outside any request)
//	last         the last client response that matched no "ask", or null
//	crash        exit with status 3
//	closestdout  close stdout and keep reading stdin
//
// A response from the client is matched to an "ask" by id; others are kept for "last".
// Notifications are ignored.
// initMode is how serveMCP answers initialize: "" (normally), error, exit or hold.
var initMode string

func serveMCP() {
	out := bufio.NewWriter(os.Stdout)
	var mu sync.Mutex
	write := func(m message) {
		m.JSONRPC = "2.0"
		b, _ := json.Marshal(m)
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(b, '\n'))
		_ = out.Flush()
	}
	result := func(id json.RawMessage, v any) {
		b, _ := json.Marshal(v)
		write(message{ID: id, Result: b})
	}
	var held []json.RawMessage
	asks := map[string]json.RawMessage{} // our request id -> the client request waiting on it
	n := 0
	last := json.RawMessage("null")
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if m.Method == "" { // a response to one of our requests
			if waiting, ok := asks[string(m.ID)]; ok {
				delete(asks, string(m.ID))
				answer := m.Result
				if answer == nil {
					answer = m.Error
				}
				write(message{ID: waiting, Result: answer})
			} else {
				last = append(json.RawMessage(nil), sc.Bytes()...)
			}
			continue
		}
		if m.ID == nil {
			continue
		}
		switch m.Method {
		case "initialize":
			switch initMode {
			case "error":
				write(message{ID: m.ID, Error: json.RawMessage(`{"code":-32602,"message":"Unsupported protocol version"}`)})
				continue
			case "exit":
				os.Exit(4)
			case "hold":
				continue
			case "lognhold":
				write(message{Method: "notifications/message", Params: json.RawMessage(`{"level":"info"}`)})
				continue
			case "lognerror":
				write(message{Method: "notifications/message", Params: json.RawMessage(`{"level":"info"}`)})
				write(message{ID: m.ID, Error: json.RawMessage(`{"code":-32602,"message":"Unsupported protocol version"}`)})
				continue
			}
			result(m.ID, map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
				"serverInfo": map[string]any{"name": "fakestdio", "version": "0"}})
		case "echo":
			write(message{ID: m.ID, Result: m.Params})
		case "line":
			result(m.ID, sc.Text())
		case "noresult":
			write(message{ID: m.ID})
		case "progress":
			for i := range 2 {
				write(message{Method: "notifications/progress", Params: json.RawMessage(fmt.Sprintf(`{"progress":%d}`, i))})
			}
			result(m.ID, "done")
		case "ask":
			n++
			id := json.RawMessage(fmt.Sprintf(`"srv-%d"`, n))
			asks[string(id)] = m.ID
			write(message{ID: id, Method: "sampling/createMessage", Params: json.RawMessage(`{}`)})
		case "hold":
			held = append(held, m.ID)
		case "release":
			for _, id := range held {
				result(id, "released")
			}
			held = nil
			result(m.ID, "ok")
		case "announce":
			result(m.ID, "ok")
			go func() {
				time.Sleep(50 * time.Millisecond)
				write(message{Method: "notifications/message", Params: json.RawMessage(`{"level":"info"}`)})
			}()
		case "raw":
			mu.Lock()
			_, _ = fmt.Fprintf(out, "{\"jsonrpc\":\"2.0\",\r\"id\":%s,\"result\":\"raw\"}\n", m.ID)
			_ = out.Flush()
			mu.Unlock()
		case "env":
			result(m.ID, os.Environ())
		case "asklater":
			result(m.ID, "ok")
			go func() {
				time.Sleep(50 * time.Millisecond)
				write(message{ID: json.RawMessage(`"srv-later"`), Method: "sampling/createMessage", Params: json.RawMessage(`{}`)})
			}()
		case "floodlater":
			var p struct{ N int }
			_ = json.Unmarshal(m.Params, &p)
			result(m.ID, "ok")
			go func() {
				for i := range p.N {
					write(message{Method: "notifications/message", Params: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i))})
				}
			}()
		case "last":
			write(message{ID: m.ID, Result: last})
		case "crash":
			os.Exit(3)
		case "closestdout":
			_ = os.Stdout.Close()
		default:
			write(message{ID: m.ID, Error: json.RawMessage(`{"code":-32601,"message":"Method not found"}`)})
		}
	}
}
