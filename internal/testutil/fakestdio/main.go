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
// Flag -modern makes it a 2026-07-28 server (see serveModern). Flag -mcp makes it a 2025-11-25
// JSON-RPC server instead (see serveMCP); with -stubborn as well, it then
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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		signal.Ignore(syscall.SIGTERM)
		hang()
	}
	if len(os.Args) > 1 && os.Args[1] == "token" { // a child asking the token socket
		fmt.Println(askToken())
		return
	}
	stubborn, mcp := false, false
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "-version="); ok {
			version = v
			continue
		}
		if v, ok := strings.CutPrefix(a, "-init="); ok {
			initMode = v
			continue
		}
		switch a {
		case "-stubborn":
			stubborn = true
		case "-mcp":
			mcp = true
		case "-modern":
			serveModern()
			return
		case "-silentdiscover":
			silentDiscover = true
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
		case "token":
			reply(askToken())
		case "tokenchild":
			reply(tokenFromChild())
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
// silentDiscover (flag -silentdiscover) makes serveMCP never answer server/discover, like a legacy
// server that ignores unknown requests.
var silentDiscover bool

// initMode is how serveMCP answers initialize: "" (normally), error, exit or hold. version is the
// protocol version its InitializeResult names (flag -version=; "none" leaves it out).
var initMode, version = "", "2025-11-25"

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
		if m.Method == "server/discover" && silentDiscover {
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
			res := map[string]any{"protocolVersion": version, "capabilities": map[string]any{},
				"serverInfo": map[string]any{"name": "fakestdio", "version": "0"}}
			if version == "none" {
				delete(res, "protocolVersion")
			}
			result(m.ID, res)
		case "echo":
			write(message{ID: m.ID, Result: m.Params})
		case "token": // the token socket's answer, as the result
			result(m.ID, askToken())
		case "tokenchild":
			result(m.ID, tokenFromChild())
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

// serveModern is a 2026-07-28 server: it answers server/discover and handles each request in its
// own goroutine, so answers and notifications for concurrent requests interleave. Methods:
//
//	echo        its params as the result
//	progress    three notifications/progress for params._meta.progressToken, each with
//	            message = params.tag, then the result {"tag": params.tag}
//	log         a notifications/message if params._meta carries io.modelcontextprotocol/logLevel,
//	            then the result {"tag": params.tag}
//	hold        no answer until a later "release"; a notifications/cancelled for it is recorded
//	release     "released" to every held request, then its own result
//	cancelled   the request ids notifications/cancelled has named so far
//	ask         writes a JSON-RPC request to stdout (which a modern server must not), then waits
//	            for the answer and returns it as the result
//	stray       writes a notification unrelated to any request, then the result
//	crash       exits with status 3
//	env         the environment as the result
//	burst       params.n notifications/progress for the token, written with no gap, then the result
//	discovers   how many server/discover requests it has answered
//	strayresponse  a response with an id nobody sent, then the result
//	strayprogress  a progress notification for a token nobody sent, then the result
//	answerexit  the result, then exits at once
//	subscriptions/listen  notifications/subscriptions/acknowledged for it, then no answer
//	notify      a notifications/tools/list_changed on every open listen, then the result
//	endlistens  a completion result for every open listen, then its own result
//	teardown    10 list_changed and then a notifications/cancelled for every open listen, written
//	            together, then the result
//	endforeign  a completion result for every open listen whose _meta names another id
//	endrepeated a completion result for every open listen whose _meta repeats the subscription id
//	listens     the ids of the open listens, as the upstream received them
//	refuselisten  an error answer, with no result, for every open listen
//	strayscribe a notification for a subscription nobody opened, then the result
//	straycancel a notifications/cancelled for a request nobody sent, then the result
//	cancelself  a notifications/cancelled naming this request, then the result
//	scribeself  a notification whose subscription id is this request's, then the result
//	dupresult   a result object with a repeated key, under the request's id
//	dupid       a response with the id repeated
func serveModern() {
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
	var cmu sync.Mutex
	cancelled := []json.RawMessage{}
	var listens []json.RawMessage
	var held []json.RawMessage
	takeListens := func() []json.RawMessage {
		cmu.Lock()
		defer cmu.Unlock()
		l := listens
		listens = nil
		return l
	}
	sub := func(id json.RawMessage) string {
		return `"_meta":{"io.modelcontextprotocol/subscriptionId":` + string(id) + `}`
	}
	answers := map[string]chan json.RawMessage{}
	type params struct {
		Tag  string `json:"tag"`
		Meta struct {
			ProgressToken json.RawMessage `json:"progressToken"`
			LogLevel      string          `json:"io.modelcontextprotocol/logLevel"`
		} `json:"_meta"`
		RequestID json.RawMessage `json:"requestId"`
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	var discovers atomic.Int64
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		var p params
		_ = json.Unmarshal(m.Params, &p)
		if m.Method == "" { // an answer to "ask"
			cmu.Lock()
			if ch, ok := answers[string(m.ID)]; ok {
				ch <- append(json.RawMessage(nil), sc.Bytes()...)
			}
			cmu.Unlock()
			continue
		}
		if m.ID == nil {
			if m.Method == "notifications/cancelled" {
				cmu.Lock()
				cancelled = append(cancelled, p.RequestID)
				cmu.Unlock()
			}
			continue
		}
		n++
		id, k := m.ID, n
		go func() {
			switch m.Method {
			case "server/discover":
				discovers.Add(1)
				result(id, map[string]any{"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
					"capabilities": map[string]any{}, "ttlMs": 0, "cacheScope": "public"})
			case "echo":
				write(message{ID: id, Result: m.Params})
			case "progress":
				for i := range 3 {
					time.Sleep(time.Duration(1+k%3) * time.Millisecond)
					write(message{Method: "notifications/progress", Params: json.RawMessage(fmt.Sprintf(
						`{"progressToken":%s,"progress":%d,"message":%q}`, p.Meta.ProgressToken, i+1, p.Tag))})
				}
				result(id, map[string]string{"tag": p.Tag})
			case "log":
				if p.Meta.LogLevel != "" {
					write(message{Method: "notifications/message", Params: json.RawMessage(fmt.Sprintf(`{"level":"info","data":%q}`, p.Tag))})
				}
				result(id, map[string]string{"tag": p.Tag})
			case "hold":
				cmu.Lock()
				held = append(held, id)
				cmu.Unlock()
			case "release":
				cmu.Lock()
				h := held
				held = nil
				cmu.Unlock()
				for _, hid := range h {
					result(hid, "released")
				}
				result(id, "ok")
			case "cancelled":
				cmu.Lock()
				ids := append([]json.RawMessage(nil), cancelled...)
				cmu.Unlock()
				result(id, ids)
			case "ask":
				ask := json.RawMessage(fmt.Sprintf(`"ask-%d"`, k))
				ch := make(chan json.RawMessage, 1)
				cmu.Lock()
				answers[string(ask)] = ch
				cmu.Unlock()
				write(message{ID: ask, Method: "roots/list", Params: json.RawMessage(`{}`)})
				write(message{ID: id, Result: <-ch})
			case "crash":
				os.Exit(3)
			case "env":
				result(id, os.Environ())
			case "burst":
				var b struct{ N int }
				_ = json.Unmarshal(m.Params, &b)
				mu.Lock()
				for i := range b.N {
					_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":%s,"progress":%d}}`+"\n", p.Meta.ProgressToken, i+1)
				}
				_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"result":"done"}`+"\n", id)
				_ = out.Flush()
				mu.Unlock()
			case "discovers":
				result(id, discovers.Load())
			case "strayresponse":
				write(message{ID: json.RawMessage(`"nobody"`), Result: json.RawMessage(`{}`)})
				result(id, "ok")
			case "strayprogress":
				write(message{Method: "notifications/progress", Params: json.RawMessage(`{"progressToken":"nobody","progress":1}`)})
				result(id, "ok")
			case "subscriptions/listen":
				cmu.Lock()
				listens = append(listens, id)
				cmu.Unlock()
				write(message{Method: "notifications/subscriptions/acknowledged", Params: json.RawMessage(`{` + sub(id) + `,"notifications":{"toolsListChanged":true}}`)})
			case "notify":
				cmu.Lock()
				l := append([]json.RawMessage(nil), listens...)
				cmu.Unlock()
				for _, lid := range l {
					write(message{Method: "notifications/tools/list_changed", Params: json.RawMessage(`{` + sub(lid) + `}`)})
				}
				result(id, len(l))
			case "endlistens":
				for _, lid := range takeListens() {
					write(message{ID: lid, Result: json.RawMessage(`{"resultType":"complete",` + sub(lid) + `}`)})
				}
				result(id, "ok")
			case "teardown":
				for _, lid := range takeListens() {
					mu.Lock()
					for i := range 10 {
						_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"n":%d,%s}}`+"\n", i, sub(lid))
					}
					_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":%s}}`+"\n", lid)
					_ = out.Flush()
					mu.Unlock()
				}
				result(id, "ok")
			case "endforeign":
				for _, lid := range takeListens() {
					write(message{ID: lid, Result: json.RawMessage(`{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":"byw-999999"}}`)})
				}
				result(id, "ok")
			case "endrepeated":
				for _, lid := range takeListens() {
					write(message{ID: lid, Result: json.RawMessage(`{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":` +
						string(lid) + `,"io.modelcontextprotocol/subscriptionId":"byw-999999"}}`)})
				}
				result(id, "ok")
			case "refuselisten":
				for _, lid := range takeListens() {
					write(message{ID: lid, Error: json.RawMessage(`{"code":-32602,"message":"no such subscription"}`)})
				}
				result(id, "ok")
			case "listens":
				cmu.Lock()
				l := append([]json.RawMessage{}, listens...)
				cmu.Unlock()
				result(id, l)
			case "strayscribe":
				write(message{Method: "notifications/tools/list_changed", Params: json.RawMessage(`{` + sub(json.RawMessage(`"byw-999999"`)) + `}`)})
				result(id, "ok")
			case "straycancel":
				write(message{Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":"byw-999999"}`)})
				result(id, "ok")
			case "cancelself":
				write(message{Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":` + string(id) + `}`)})
				result(id, "ok")
			case "scribeself":
				write(message{Method: "notifications/tools/list_changed", Params: json.RawMessage(`{` + sub(id) + `}`)})
				result(id, "ok")
			case "dupresult":
				mu.Lock()
				_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"result":{"a":1,"a":2}}`+"\n", id)
				_ = out.Flush()
				mu.Unlock()
			case "dupid":
				mu.Lock()
				_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"id":%s,"result":1}`+"\n", id, id)
				_ = out.Flush()
				mu.Unlock()
			case "answerexit":
				mu.Lock()
				_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"result":"answered"}`+"\n", id)
				_ = out.Flush()
				os.Exit(0)
			case "stray":
				write(message{Method: "notifications/tools/list_changed"})
				result(id, "ok")
			default:
				write(message{ID: id, Error: json.RawMessage(`{"code":-32601,"message":"Method not found"}`)})
			}
		}()
	}
}

// askToken asks the token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET) as an upstream server would and
// returns its answer line, or "error ..." when there is none.
func askToken() string {
	path := os.Getenv("BYWARD_DOWNSTREAM_TOKEN_SOCKET")
	if path == "" {
		return "error no BYWARD_DOWNSTREAM_TOKEN_SOCKET"
	}
	c, err := net.Dial("unix", path) //nolint:gosec // G704: dials the socket the proxy named for this test process
	if err != nil {
		return "error " + err.Error()
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("{}\n")); err != nil {
		return "error " + err.Error()
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "error " + err.Error()
	}
	return strings.TrimSuffix(line, "\n")
}

// tokenFromChild asks the token socket from a child process, as a server started by a launcher
// (npx, uvx) would.
func tokenFromChild() string {
	out, err := exec.Command(os.Args[0], "token").Output() //nolint:gosec // G204: re-runs this test binary
	if err != nil {
		return "error " + err.Error()
	}
	return strings.TrimSuffix(string(out), "\n")
}
