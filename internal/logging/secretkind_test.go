package logging

import (
	"strconv"
	"strings"
	"testing"
)

// fakeToken is a token of prefix's form, made here so no file holds one whole: a secret scanner
// never meets it, and it is never a real credential.
func fakeToken(prefix string) string { return prefix + strings.Repeat("Q7", 18) }

// secretKinds are a value of each kind secretKind names, with its class.
var secretKinds = []struct{ value, class string }{
	{fakeToken("ghp_"), "a GitHub token"},
	{fakeToken("github_pat_"), "a GitHub token"},
	{fakeToken("gho_"), "a GitHub token"},
	{fakeToken("ghu_"), "a GitHub token"},
	{fakeToken("ghs_"), "a GitHub token"},
	{fakeToken("ghr_"), "a GitHub token"},
	{fakeToken("xoxb-"), "a Slack token"},
	{fakeToken("xoxp-"), "a Slack token"},
	{fakeToken("xapp-"), "a Slack token"},
	{fakeToken("xoxe.xapp-"), "a Slack token"},
	{fakeToken("xwfp-"), "a Slack token"},
	{"--token=" + fakeToken("ghp_"), "a GitHub token"},                       // after a character that is not a word's
	{"Bearer " + fakeToken("xoxb-"), "a Slack token"},                        // after a space
	{"\t" + fakeToken("ghp_"), "a GitHub token"},                             // shown quoted, after the escape \t
	{"\x9b" + fakeToken("xoxb-"), "a Slack token"},                           // shown quoted, after the escape \x9b
	{"x\n" + fakeToken("ghp_"), "a GitHub token"},                            // shown quoted, after the escape \n
	{"x\u00a0" + fakeToken("ghp_"), "a GitHub token"},                        // shown quoted, after a no-break space's escape
	{"host=db\n" + "password=Q7Q7Q7", "a connection string with a password"}, // after an escaped line break
	{"ghp_" + strings.Repeat("Q", 10), "a GitHub token"},                     // the fewest token characters a prefix takes
	{"postgres://app:" + "Q7Q7Q7" + "@db.example/app", "a connection string with a password"},
	{"Server=db.example;User Id=app;" + "Password=Q7Q7Q7", "a connection string with a password"},
	{"Host=db.example;" + "PWD=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example user=app " + "password=Q7Q7Q7", "a connection string with a password"}, // libpq's keyword form
	{"postgres://db.example/app?user=app&" + "password=Q7Q7Q7", "a connection string with a password"},
	{"Password=" + "Q7Q7Q7", "a connection string with a password"},
	{"Server=db," + "password=Q7Q7Q7", "a connection string with a password"},
	{"postgres://db.example/app?" + "password=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example," + "password=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example " + "password = Q7Q7Q7", "a connection string with a password"},
	{"xoxb-" + "1234-5678-abcdQ7", "a Slack token"}, // a dashed tail, as Slack's are
	{"x\r" + fakeToken("ghp_"), "a GitHub token"},   // after each escape strconv.Quote writes for a character that is not printable
	{"x\a" + fakeToken("ghp_"), "a GitHub token"},
	{"x\b" + fakeToken("ghp_"), "a GitHub token"},
	{"x\f" + fakeToken("ghp_"), "a GitHub token"},
	{"x\v" + fakeToken("ghp_"), "a GitHub token"},
	{"x\U000e0001" + fakeToken("ghp_"), "a GitHub token"},
	{"x\U000f0000" + fakeToken("ghp_"), "a GitHub token"},
	{"100% " + fakeToken("ghp_"), "a GitHub token"},         // a % that is no escape
	{"ghp_" + strings.Repeat("q7", 18), "a GitHub token"},   // a tail in lower case
	{"ghp_Q_" + strings.Repeat("Q7", 18), "a GitHub token"}, // an underscore in the tail
	{"ghp_A" + "Q7Q7Q7Q7Q", "a GitHub token"},               // the tail's first character, at each end of each range
	{"ghp_Z" + "Q7Q7Q7Q7Q", "a GitHub token"},
	{"ghp_a" + "Q7Q7Q7Q7Q", "a GitHub token"},
	{"ghp_z" + "Q7Q7Q7Q7Q", "a GitHub token"},
	{"ghp_0" + "Q7Q7Q7Q7Q", "a GitHub token"},
	{"ghp_9" + "Q7Q7Q7Q7Q", "a GitHub token"},
	{"ghp_Q" + "AZaz09Q7Q", "a GitHub token"}, // and of the rest
	{token, jwtKind},
	{"Bearer " + token, jwtKind},   // as an Authorization header's value
	{"x\n" + token, jwtKind},       // shown quoted, after the escape \n
	{"Bearer%20" + token, jwtKind}, // percent-escaped, as a URL's path shows it
}

// secretKind names each kind, and nothing else: a prefix named in prose, with too few token
// characters after it, inside a word, split from its tail by a space or tab, or followed by _
// rather than a letter or digit, is no token; a URL with a user but no password, or an empty one,
// a / before what looks like a password, a key=value that is not a password, and a key that only
// starts or ends with "password" are no connection string.
func TestSecretKindNamesOnlyTheKindsItLists(t *testing.T) {
	for i, k := range secretKinds {
		if got := secretKind(k.value); got != k.class {
			t.Errorf("secretKind(secretKinds[%d] <%s>) = %q, want %q", i, k.class, got, k.class)
		}
	}
	for _, s := range []string{"ghp_", "xoxb-", "ghp_ tokens", "B" + fakeToken("ghp_"), "q-" + fakeToken("ghp_"), "ghp_short", "xoxb-style", "ghp_" + strings.Repeat("Q", 9),
		"ghp__" + strings.Repeat("Q", 10), "app-" + fakeToken("ghp_"), "my.xoxb-" + strings.Repeat("Q", 10),
		"team_ghs_" + strings.Repeat("Q", 10), "a" + fakeToken("ghp_"), "1" + fakeToken("ghp_"), "MCP.User", "byward-users",
		"/byward-users", "https://app.example/client.json", "postgres://db.example/app", "postgres://app@db.example/app",
		"user@example.com", "Server=db;Database=app", "a=b", "OldPassword=x", "passwords=many", "00000000-0000-0000-0000-000000000000",
		"A" + fakeToken("ghp_"), "ghp_\t" + strings.Repeat("Q7", 18), "https://h.example/a:b@c", "https://h.example:8080/pkg@1.0",
		"Z" + fakeToken("ghp_"), "z" + fakeToken("ghp_"), "9" + fakeToken("ghp_"), "0" + fakeToken("ghp_"), // a word's character before a prefix, at each end of each range
		"postgres://app:@db.example/app", "a+password=b",
		"docs at https://docs.example: ask ops@example.com",        // a space ends a URL's password
		"docs at https://docs.example see ops:on-call@example.com", // and its user name
		"https://ops@a.example:8443,ops@example.com",               // an @ ends a URL's user name
		"smtp://ops:@mail.example,ops@example.com"} {               // and its password
		if got := secretKind(s); got != "" {
			t.Errorf("secretKind(%q) = %q, want none", s, got)
		}
	}
}

// A list's entries are read one by one, and a connection string whose password a comma split is
// found all the same: an entry scheme://X:Y, Y no port, then an @ before any / in a later entry.
func TestShownListSecretKindReadsEachEntryAndASplitPassword(t *testing.T) {
	for _, tc := range []struct {
		entries []string
		want    string
	}{
		{[]string{"admin", fakeToken("ghp_")}, "a GitHub token"},
		{[]string{"postgres://app:Hun", "ter2Q7@db/x"}, passwordKind},
		{[]string{"openid", "postgres://app:Hun", "ter2Q7@db/x"}, passwordKind},
		{[]string{"https://a.example:8443", "ops@example.com"}, ""},
		{[]string{"https://byward.example", "urn:byward:admin", "ops@example.com"}, ""},
		{[]string{"api://byward:read", "api://byward:write"}, ""},
		{[]string{"api://byward:read", "https://idp.example/groups/@sre"}, ""},
		{[]string{"ops@example.com", "api://byward:read"}, ""},
		{[]string{"postgres://app:Hun", "ter2Q7@db/" + fakeToken("ghp_")}, "a GitHub token"}, // an entry's kind before a split password
		{[]string{"admin", strconv.Quote("x\n" + fakeToken("ghp_"))}, "a GitHub token"},      // an entry read as shown
	} {
		if got := ShownListSecretKind(tc.entries); got != tc.want {
			t.Errorf("ShownListSecretKind(%q) = %q, want %q", tc.entries, got, tc.want)
		}
	}
}

// A URL's password is found under every scheme RFC 3986 allows, and with an empty user name.
func TestSecretKindReadsEveryURLSchemeAndUserPart(t *testing.T) {
	pw := "Q7Q7" + "Q7Q7"
	for _, s := range []string{
		"S3://app:" + pw + "@bucket.example", // an upper-case scheme start, a digit before ://
		"s3://app:" + pw + "@bucket.example", // a digit in the scheme
		"x+1://app:" + pw + "@h.example",     // each of RFC 3986's scheme characters
		"x.1://app:" + pw + "@h.example",
		"x-1://app:" + pw + "@h.example",
		"redis://:" + pw + "@cache.example", // an empty user name
		"A://app:" + pw + "@h.example",      // a one-letter scheme, at each end of each range
		"Z://app:" + pw + "@h.example",
		"a://app:" + pw + "@h.example",
		"z://app:" + pw + "@h.example",
		"s0://app:" + pw + "@h.example", // a digit after the scheme's first letter, at each end of the range
		"s9://app:" + pw + "@h.example",
		"postgres://app:" + "p\"w" + pw + "@db.example/app", // a " in the password
	} {
		if got := secretKind(s); got != passwordKind {
			t.Errorf("secretKind(%q) = %q, want %q", s, got, passwordKind)
		}
	}
	for _, s := range []string{
		`{"level":"info","endpoint":"https://api.example.com","user":"bob@example.com"}`, // a " ends the user name
		`{"iss":"https://login.example","email":"a@b.example"}`,
		`{"level":"info","endpoint":"https://api.example.com/v1","user":"bob@example.com"}`, // a path before the @
		"url=https://api.example.com user=bob@example.com",                                  // a space before the @
	} {
		if got := secretKind(s); got != "" {
			t.Errorf("secretKind(%q) = %q, want none", s, got)
		}
	}
}

// splitPassword finds a password a comma split, however the list is shown, and nothing else: a
// port, an empty password, no URL's start, a / or a space before the @.
func TestSplitPasswordFindsOnlyAPasswordACommaSplit(t *testing.T) {
	for _, tc := range []struct {
		entries []string
		want    bool
	}{
		{[]string{"postgres://app:Hun", "ter2Q7@db/x"}, true},
		{[]string{"Postgres://app:Hun", "ter2Q7@db/x"}, true},     // an upper-case scheme
		{[]string{`"postgres://app:Hun`, `ter2Q7@db/x "`}, true},  // a list shown quoted
		{[]string{" postgres://app:Hun", "ter2Q7@db/x"}, true},    // a space after the comma
		{[]string{`"postgres://a\tpp:Hun`, `ter2Q7@db/x"`}, true}, // an escape in the user name
		{[]string{"postgres://app:Hun", "@db/x"}, true},           // the comma ends the password
		{[]string{"postgres://app:Hun", "ter", "x@db/x"}, true},   // two commas in it
		{[]string{"A://app:Hun", "ter2Q7@db/x"}, true},            // a one-letter scheme, at each end of each range
		{[]string{"Z://app:Hun", "ter2Q7@db/x"}, true},
		{[]string{"a://app:Hun", "ter2Q7@db/x"}, true},
		{[]string{"z://app:Hun", "ter2Q7@db/x"}, true},
		{[]string{"xAZaz09+.-://app:Hun", "ter2Q7@db/x"}, true},          // every scheme character after the first
		{[]string{"redis://:Hun", "ter2Q7@db/x"}, true},                  // an empty user name
		{[]string{"https://a.example:9000", "ops@example.com"}, false},   // a port
		{[]string{"smtp://ops:", "ops@example.com"}, false},              // an empty password
		{[]string{"smtp://ops:@mail.example", "ops@example.com"}, false}, // a whole URL, empty password
		{[]string{"a=postgres://app:Hun", "ter2Q7@db/x"}, false},         // no URL's start
		{[]string{"api://byward:read/all", "ops@example.com"}, false},    // a / after the :
		{[]string{"https://idp.example/roles:admin", "ops@example.com"}, false},
		{[]string{"smtp://ops@mail.example:abc", "ops@example.com"}, false},
		{[]string{"https://docs.example see ops:on", "call@example.com"}, false},
		{[]string{"https://docs.example: ask ops", "ops@example.com"}, false},
	} {
		if got := splitPassword(tc.entries); got != tc.want {
			t.Errorf("splitPassword(%q) = %v, want %v", tc.entries, got, tc.want)
		}
	}
}

// Each kind is found in a value shown quoted, as one that is not printable is: secretKinds' rows
// carry each escape strconv.Quote writes for a character that is not printable.
func TestShownSecretKindReadsEveryKindQuoted(t *testing.T) {
	for i, k := range secretKinds {
		if got := ShownSecretKind(strconv.Quote(k.value)); got != k.class {
			t.Errorf("ShownSecretKind(secretKinds[%d] <%s>, quoted) = %q, want %q", i, k.class, got, k.class)
		}
	}
}

// ShownSecretKind reads a value as it is shown: a Go escape as a break, or inside a URL's user part
// as a character of it; each percent-escape undone once, in either case, an escaped space or
// control character read as a Go escape is.
func TestShownSecretKindReadsAValueAsItIsShown(t *testing.T) {
	tok := fakeToken("ghp_")
	tail := strings.Repeat("Q7", 18)
	for _, tc := range []struct{ name, shown, want string }{
		{"quoted after \\t", strconv.Quote("x\t" + tok), "a GitHub token"},
		{"quoted after \\xf0", strconv.Quote("\xf0" + tok), "a GitHub token"}, // each end of each hex range, in each escape
		{"quoted after \\xa9", strconv.Quote("\xa9" + tok), "a GitHub token"},
		{"quoted after \\u009f", strconv.Quote("\u009f" + tok), "a GitHub token"},
		{"quoted after \\u00ad", strconv.Quote("\u00ad" + tok), "a GitHub token"},
		{"quoted after \\U000f0000", strconv.Quote("\U000f0000" + tok), "a GitHub token"},
		{"quoted after \\U000e009a", strconv.Quote("\U000e009a" + tok), "a GitHub token"},
		{"a \\x escape before a scheme of hex letters", strconv.Quote("\x01db2://app:Q7q7Q7@db/x"), passwordKind}, // an escape takes only its own digits
		{"a \\u escape before a scheme of hex letters", strconv.Quote("\u00addb2://app:Q7q7Q7@db/x"), passwordKind},
		{"a \\U escape before a scheme of hex letters", strconv.Quote("\U000e0001db2://app:Q7q7Q7@db/x"), passwordKind},
		{"a quoted \" in a URL's user name", strconv.Quote("postgres://a\"pp:Q7q7Q7@db/x\t"), passwordKind},
		{"an escaped backslash before a password key", `"host=db\\password=` + "Q7Q7Q7" + `\t"`, passwordKind},
		{"a password key starting a value shown quoted", strconv.Quote("password=" + "Q7Q7Q7\t"), passwordKind},
		{"an escape between a prefix and its tail", strconv.Quote("ghp_\t" + tail), ""},
		{"an escape in a URL's user name", strconv.Quote("postgres://a\tpp:Q7q7Q7@db/x"), passwordKind},
		{"percent-escaped in upper case", "https://up.example/ghp%5F" + tail, "a GitHub token"},
		{"percent-escaped in lower case", "https://up.example/ghp%5f" + tail, "a GitHub token"},
		{"a percent-escaped tab before a token", "https://up.example/x%09" + tok, "a GitHub token"}, // each end of the ranges
		{"a percent-escaped line break before a token", "https://up.example/x%0a" + tok, "a GitHub token"},
		{"percent-escaped twice, undone once", "https://up.example/ghp%255F" + tail, ""},
		{"percent-escaped beside a % that is no escape", "%67hp_" + tail + ",X-100%", "a GitHub token"},
		{"percent-escaped after a % that is no escape", "100% %67hp_" + tail, "a GitHub token"},
		{"a % with one hex digit before a token", "%5" + tok, ""},
		{"a %-escaped / in a URL's password", "postgres://app:" + "p%2FQ7" + "@db.example/app", passwordKind},
		{"a percent-escaped space in a user name", "postgres%3A%2F%2Fa%20pp%3A" + "Q7q7Q7%40db", passwordKind},
		{"a percent-escaped tab in a user name", "postgres%3A%2F%2Fa%09pp%3A" + "Q7q7Q7%40db", passwordKind},
		{"a password key after a percent-escaped control character", "host%3Ddb%01password%3D" + "Q7Q7Q7", passwordKind},
		{"a password key after a percent-escaped DEL", "host%3Ddb%7Fpassword%3D" + "Q7Q7Q7", passwordKind},
	} {
		if got := ShownSecretKind(tc.shown); got != tc.want {
			t.Errorf("%s: ShownSecretKind = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// What the catalogue refuses, logs hide: every value of every kind, plain and as a reader would see
// it, is one LooksSecret redacts, so a value config refuses never reaches a log line whole (#657).
func TestEveryKindTheCatalogueRefusesIsRedacted(t *testing.T) {
	for i, k := range secretKinds {
		if !LooksSecret(k.value) || !LooksSecret(strconv.Quote(k.value)) {
			t.Errorf("secretKinds[%d] (%s) is refused but not redacted, plain or quoted", i, k.class)
		}
	}
}
