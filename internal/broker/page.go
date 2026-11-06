package broker

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/corker/mcp-authproxy/internal/logging"
)

// The broker's HTML pages: shared headers, the stylesheet, and the error page.

// pageHeaders lock down every HTML page the broker serves (ADR-0010 §6). No form-action: browsers
// disagree on whether it blocks the redirect that follows a form submission. Referrer-Policy is
// same-origin, not no-referrer: under no-referrer, browsers send "Origin: null" with the consent
// form's POST (Fetch, "serialize a request origin"), which the CSRF check must reject.
func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'self'; img-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
}

// StylesheetPath is where the pages' stylesheet is served.
const StylesheetPath = "/assets/page.css"

//go:embed page.css
var assets embed.FS

func stylesheet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	css, _ := assets.ReadFile("page.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(css)
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title><link rel="stylesheet" href="{{.Stylesheet}}"></head>
<body><main><h1>{{.Title}}</h1><p>{{.Hint}}</p><footer>Reference: <code>{{.RequestID}}</code></footer></main></body></html>
`))

// page renders an error page: no script, no external assets, request ID shown (ADR-0021 §2).
func (b *Broker) page(w http.ResponseWriter, r *http.Request, status int, title, hint string) {
	pageHeaders(w)
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, map[string]string{"Title": title, "Hint": hint, "RequestID": logging.RequestID(r.Context()), "Stylesheet": StylesheetPath})
}
