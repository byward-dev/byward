package config

import (
	"os"
	"slices"
	"testing"
)

const referencePath = "../../docs/reference/settings.md"

func TestReferenceIsCurrent(t *testing.T) {
	want := reference()
	if os.Getenv("BYWARD_UPDATE_REFERENCE") == "1" {
		if err := os.WriteFile(referencePath, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(referencePath)
	if err != nil || string(got) != want {
		t.Fatalf("%s is stale; run BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/", referencePath)
	}
}

// Every setting is listed under one of the reference's groups, and every group lists a setting: a
// setting with no group, or a group no setting uses, would drop a row or leave an empty table.
func TestEverySettingIsInAGroupAndEveryGroupHasASetting(t *testing.T) {
	used := map[Group]bool{}
	for _, s := range registry {
		if !slices.Contains(groups, s.Group) {
			t.Errorf("%s has the group %q, which the reference does not list", s.Name, s.Group)
		}
		used[s.Group] = true
	}
	for _, g := range groups {
		if !used[g] {
			t.Errorf("no setting is in the group %q", g)
		}
	}
}

// A group listed twice would print its section, and its link in the table of contents, twice.
func TestNoGroupIsListedTwice(t *testing.T) {
	if len(slices.Compact(slices.Sorted(slices.Values(groups)))) != len(groups) {
		t.Errorf("a group is listed twice: %q", groups)
	}
}

// The reference's table of contents links each group's heading by the fragment GitHub gives it.
func TestAnchorIsGitHubsFragmentForAHeading(t *testing.T) {
	for heading, want := range map[string]string{
		"IdP: Microsoft Entra ID":          "idp-microsoft-entra-id",
		"App-only callers":                 "app-only-callers",
		"Upstream: HTTP":                   "upstream-http",
		"Development and trying it out":    "development-and-trying-it-out",
		"OAuth 2.1 tokens":                 "oauth-21-tokens",
		"Downstream tokens (On-Behalf-Of)": "downstream-tokens-on-behalf-of",
		"snake_case Überblick":             "snake_case-überblick",
		"Cafe\u0301":                       "cafe\u0301",
		"1½ Ⅻ":                             "1-ⅻ",
		"x‿y":                              "x‿y",
		"Ⓐ b":                              "ⓐ-b",
	} {
		if got := anchor(heading); got != want {
			t.Errorf("anchor(%q) = %q, want %q", heading, got, want)
		}
	}
}
