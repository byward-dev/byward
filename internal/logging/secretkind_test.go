package logging

import (
	"encoding/json"
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
	// A URL's password, under every scheme RFC 3986 allows, and with each user part.
	{"S3://app:" + "Q7Q7Q7Q7" + "@bucket.example", passwordKind}, // an upper-case scheme start, a digit before ://
	{"x+1://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},     // each of RFC 3986's scheme characters
	{"x.1://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"x-1://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"redis://:" + "Q7Q7Q7Q7" + "@cache.example", passwordKind}, // an empty user name
	{"A://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},      // a one-letter scheme, at each end of each range
	{"Z://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"a://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"z://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"s0://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind}, // a digit after the scheme's first letter, at each end of the range
	{"s9://app:" + "Q7Q7Q7Q7" + "@h.example", passwordKind},
	{"postgres://app:" + "Q7Q7Q7Q7" + "\"@db.example/app", passwordKind},         // a " ending the password
	{"postgres://app:" + "p\"w" + "Q7Q7Q7Q7" + "@db.example/app", passwordKind},  // a " inside it
	{"postgres://app:" + "\"" + "@db.example/app", passwordKind},                 // a password that is only a "
	{"xoxe" + "Z" + "xapp-ABCDEFGHIJ postgres://u:" + "pa55@h/db", passwordKind}, // a prefix's . is a dot, not any character: no token, so the password is named
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
		`{"u":"https://x.example"}, then bob@x.example`,            // a " before a }
		"url=https://api.example.com user=bob@example.com",         // a space before the @
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

// What config refuses only as it shows a value, quoted because it is not printable, or as a list's
// entries, logs hide in the raw text all the same (#657): a password key after a break that only
// the quoted display shows as one (RE2's \s is ASCII), and a password a comma split, with a space
// or a / before the later @, which ShownListSecretKind finds and the whole text's urlPassword does not.
func TestWhatConfigRefusesAsItShowsAValueIsRedacted(t *testing.T) {
	for _, v := range []string{
		"host=db\v" + "password=Q7Q7Q7",
		"host=db\x00" + "password=Q7Q7Q7",
		"host=db\u00a0" + "password=Q7Q7Q7",
		"\xff" + "password=Q7Q7Q7",
	} {
		if ShownSecretKind(AsGiven(v)) != passwordKind || !LooksSecret(v) {
			t.Errorf("%q: refused as shown (%q) but redacted %v", v, ShownSecretKind(AsGiven(v)), LooksSecret(v))
		}
	}
	// A JSON line that is not printable is read as given too: quoted, its \/ is no URL, and as a
	// list the document is cut apart.
	for _, v := range []string{"{\"a\":\t\"postgres:\\/\\/u:" + "pw@h\",\"b\":1}", "{\"a\":\t\"" + fakeToken("ghp_") + "\",\"b\":1}"} {
		if !LooksSecret(v) {
			t.Errorf("%q: a JSON line with a secret, read as given, is not redacted", v)
		}
	}
	// A URL list shows each entry trimmed, so a JWT cut short before white space is one there.
	if jwt := "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiJ4In0"; !LooksSecret(jwt+" ") || !LooksSecret("app.example,"+jwt+"\t") || !LooksSecret(jwt+"\v") || !LooksSecret(jwt+"\u0085") || !LooksSecret("app.example,"+jwt+"\u00a0") {
		t.Errorf("a JWT cut short before white space, which a URL list shows trimmed, is not redacted")
	}
	for _, v := range []string{"postgres://u:pa, " + "ss@h", "postgres://u:pa,x/y," + "ss@h", "postgres://u\n:Q7Q7Q7," + "q x@h"} { // the last only as quoted
		if ShownListSecretKind(strings.Split(AsGiven(v), ",")) != passwordKind || !LooksSecret(v) { // a list as config shows it
			t.Errorf("%q: refused as a list but redacted %v", v, LooksSecret(v))
		}
	}
}

// A JSON document is read by its parts, every key and every string, so a line an upstream logs as
// JSON keeps an origin and an email it names, and still shows no secret in any part (#657). A line
// that is not a whole JSON document is read as text, as before.
func TestShownSecretKindReadsAJSONDocumentByItsParts(t *testing.T) {
	dsn := "postgres://app:" + "s3cretQ7" + "@db.example/x"
	for _, tc := range []struct{ name, shown, want string }{
		{"an origin, then an email", `{"endpoint":"https://api.example.com","user":"bob@example.com"}`, ""},
		{"an origin with a port, then an email", `{"endpoint":"https://api.example.com:8443","user":"bob@example.com"}`, ""},
		{"an array of URLs, then an email", `{"urls":["https://a.example:8443","mailto:x"],"to":"bob@example.com"}`, ""},
		{"an array, then an email", `[{"url":"https://a.example:8443"},"bob@example.com"]`, ""},
		{"spaces around the document", "  " + `{"endpoint":"https://api.example.com:8443","user":"bob@example.com"}` + " ", ""},
		{"numbers, booleans and null", `{"port":8443,"tls":true,"proxy":null}`, ""},
		{"a number too large for a float, then an origin and an email", `{"n":1e999,"endpoint":"https://api.example.com","user":"bob@example.com"}`, ""}, // still read by its parts
		{"a DSN as a value", `{"level":"info","msg":"connect","dsn":"` + dsn + `"}`, passwordKind},
		{"a DSN in an error string", `{"err":"dial ` + dsn + `: refused"}`, passwordKind},
		{"a DSN nested in an array", `{"nested":{"a":["` + dsn + `"]}}`, passwordKind},
		{"a DSN written with \\u escapes", `{"dsn":"postgres://app:s3cretQ7\u0040db.example/x"}`, passwordKind},
		{"a DSN as a key", `{"` + dsn + `":1}`, passwordKind},
		{"a token in an array", `["ok","` + fakeToken("ghp_") + `"]`, "a GitHub token"},
		{"a JSON document inside a string", `{"body":"{\"dsn\":\"` + dsn + `\"}"}`, passwordKind},
		{"a password key in a value", `{"conn":"host=db password=Q7Q7Q7"}`, passwordKind},
		{"a JSON document inside a string, its @ escaped", `{"body":"{\"dsn\":\"postgres://app:s3cretQ7\\u0040db.example/x\"}"}`, passwordKind}, // read by its parts too, not as text
		{"a JSON document inside a string, an origin then an email", `{"body":"{\"endpoint\":\"https://api.example.com\",\"user\":\"bob@example.com\"}"}`, ""},
		{"a password split across two strings of an array", `["postgres://app:Hun","ter2Q7@db.example/x"]`, passwordKind}, // as main finds it
		{"a password split across two values of an object", `{"a":"postgres://app:Hun","b":"ter2Q7@db.example/x"}`, passwordKind},
		{"a port, then an email, in two strings", `["https://api.example.com:8443","bob@example.com"]`, ""},                             // a port is no password
		{"a password split across two values, keys out of order", `{"b":"postgres://app:Hun","a":"ter2Q7@db.example/x"}`, passwordKind}, // read in the document's order
		{"a token under a key given twice", `{"a":"` + fakeToken("ghp_") + `","a":"x"}`, "a GitHub token"},                              // every value of a duplicate key
		{"a token in a nested document with a key given twice", `{"a":"{\"k\":\"` + fakeToken("ghp_") + `\"\u002c\"k\":1}"}`, "a GitHub token"},
		{"a password key after a control character in a string", `{"m":"host=db\u000b` + `password=Q7Q7Q7"}`, passwordKind}, // each string read as config shows it (AsGiven)
		{"an escaped space inside a URL's user part", `{"a":"postgres://u\u0020:` + "s3cretPW" + `@h/db"}`, passwordKind},   // each string read as written too, as main reads it
		{"an escaped space ending a URL's password", `{"a":"postgres://u:` + "s3cretPW" + `\u0020@h/db"}`, passwordKind},
		{"an escaped backslash before a password key", `{"conn":"Server=db\\` + `Password=s3cret"}`, passwordKind},
		{"an escaped character between a password key and its =", `{"a":"password\u003b` + `=x"}`, passwordKind},
		{"an escaped quote between a password key and its =", `{"a":"password\"` + `=x"}`, passwordKind},
		// A credential cut across JSON structure is not found: the split rule needs the first string
		// to end scheme://user:Y, Y neither empty nor all digits. Allowed by decision (#657): finding
		// these would refuse a JSON line naming an origin and then an email, and none is a credential
		// pasted as one.
		{"allowed: a split before the :", `{"postgres://u":"` + "pw@h" + `"}`, ""},
		{"allowed: a split at the :", `["postgres://u:","` + "pw@h" + `"]`, ""},
		{"allowed: a split after an all-digit part", `["postgres://u:123","` + "4@h" + `"]`, ""},
		{"two kinds, named by the first key", `{"a":"` + fakeToken("ghp_") + `","z":"` + dsn + `"}`, "a GitHub token"},
		{"text before the JSON", `time=1 {"endpoint":"https://api.example.com:8443","user":"bob@x.example"}`, passwordKind},
		{"a line cut short", `{"endpoint":"https://api.example.com:8443","user":"bob@x.example"`, passwordKind},
		{"a DSN as plain text", "connect " + dsn + " failed", passwordKind},
		{"a \" in a URL's user name, as main reads it", `postgres://us"er:` + "s3cretPW" + `@h/x`, passwordKind},
	} {
		if got := ShownSecretKind(tc.shown); got != tc.want {
			t.Errorf("%s: ShownSecretKind(%q) = %q, want %q", tc.name, tc.shown, got, tc.want)
		}
		if got := LooksSecret(tc.shown); got != (tc.want != "") {
			t.Errorf("%s: LooksSecret(%q) = %v, want %v", tc.name, tc.shown, got, tc.want != "")
		}
	}
}

// LooksSecret reads a string of at most 16 KiB; a longer one is redacted unread, so what logs cost
// for a value an unauthenticated client controls is bounded (#657).
func TestLooksSecretReadsAtMost16KiB(t *testing.T) {
	if LooksSecret(strings.Repeat("x", 16<<10)) {
		t.Error("a harmless string of 16 KiB is redacted, want it read and kept")
	}
	if !LooksSecret(strings.Repeat("x", 16<<10+1)) {
		t.Error("a string of 16 KiB and one byte is kept, want it redacted unread")
	}
	if tok := fakeToken("ghp_"); !LooksSecret(strings.Repeat("x", 16<<10-len(tok)-1) + " " + tok) {
		t.Error("a token in a string of exactly 16 KiB is kept, want it read and redacted")
	}
	// A string read more than once (a , % or \, or not printable) is read up to MaxReread.
	if LooksSecret(strings.Repeat("x,", 4<<10)) {
		t.Error("a harmless string of 8 KiB with commas is redacted, want it read and kept")
	}
	if !LooksSecret(strings.Repeat("x,", 4<<10) + "x") {
		t.Error("a string of 8 KiB and one byte with commas is kept, want it redacted unread")
	}
	if !LooksSecret(strings.Repeat("x", 16<<10) + "\x01") {
		t.Error("a string over 16 KiB that is not printable is kept, want it redacted unread")
	}
	if tok := fakeToken("ghp_"); !LooksSecret(strings.Repeat("x,", (8<<10-len(tok)-1)/2) + " " + tok) {
		t.Error("a token in a string under 8 KiB with commas is kept, want it read and redacted")
	}
	// A JSON document nested as a string in another, level after level, is read once per level,
	// not twice: a request's path holding one must cost what one of its size costs.
	nested := `["` + strings.Repeat("a", 8) + `"]`
	for {
		b, _ := json.Marshal(nested)
		if len(b)+2 > MaxReread {
			break
		}
		nested = "[" + string(b) + "]"
	}
	if LooksSecret(nested) {
		t.Errorf("a harmless JSON document nested as strings, %d bytes, is redacted", len(nested))
	}
	if allocs := testing.AllocsPerRun(3, func() { LooksSecret(nested) }); allocs > 2000 { // 172 read once per level; 44,274 read twice
		t.Errorf("a JSON document nested as strings, %d bytes, costs %.0f allocations, want it read once per level", len(nested), allocs)
	}
	// Unread: a longer string costs nothing, as the list and quoted readings would allocate.
	if long := strings.Repeat("x,", 1<<19); testing.AllocsPerRun(10, func() { LooksSecret(long) }) != 0 {
		t.Error("a string over 16 KiB is read, want it redacted unread")
	}
}
