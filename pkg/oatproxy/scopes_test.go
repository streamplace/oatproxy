package oatproxy

import (
	"testing"
)

const testFullScope = "atproto blob:*/* repo?collection=app.bsky.feed.post&action=create repo?collection=app.bsky.actor.status include:place.stream.authFull"

func TestScopeContains(t *testing.T) {
	tests := []struct {
		name    string
		granted string
		wanted  string
		expect  bool
	}{
		{"exact match", "atproto", "atproto", true},
		{"subset", testFullScope, "atproto blob:*/*", true},
		{"subset single granular", testFullScope, "repo?collection=app.bsky.actor.status", true},
		{"missing value", "atproto blob:*/*", "repo?collection=app.bsky.actor.status", false},
		{"empty wanted always contained", testFullScope, "", true},
		{"empty granted contains nothing", "", "atproto", false},
		{"no partial token match", "repo?collection=app.bsky.feed.post&action=create", "repo?collection=app.bsky.feed.post", false},
		{"order independent", "b a", "a b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeContains(tt.granted, tt.wanted); got != tt.expect {
				t.Errorf("ScopeContains(%q, %q) = %v, want %v", tt.granted, tt.wanted, got, tt.expect)
			}
		})
	}
}

func TestValidateRequestedScope(t *testing.T) {
	o := &OATProxy{scope: testFullScope}
	if err := o.validateRequestedScope(testFullScope); err != nil {
		t.Errorf("full scope should be valid: %v", err)
	}
	if err := o.validateRequestedScope("atproto blob:*/* include:place.stream.authFull"); err != nil {
		t.Errorf("subset scope should be valid: %v", err)
	}
	if err := o.validateRequestedScope("blob:*/*"); err == nil {
		t.Error("scope without atproto should be rejected")
	}
	if err := o.validateRequestedScope(""); err == nil {
		t.Error("empty scope should be rejected")
	}
	if err := o.validateRequestedScope("atproto transition:generic"); err == nil {
		t.Error("scope outside the configured set should be rejected")
	}
}

func TestSessionScopes(t *testing.T) {
	// legacy session, no scopes recorded: treated as full grant
	legacy := &OAuthSession{}
	if !legacy.HasScope("repo?collection=app.bsky.actor.status") {
		t.Error("legacy session should be treated as having all scopes")
	}
	if got := legacy.GrantedScope(); got != "" {
		t.Errorf("legacy GrantedScope() = %q, want empty", got)
	}

	o := &OATProxy{scope: testFullScope}
	if got := o.grantedScope(legacy); got != testFullScope {
		t.Errorf("grantedScope(legacy) = %q, want configured scope", got)
	}

	// session that declined bluesky scopes
	limited := &OAuthSession{
		DownstreamScope: "atproto blob:*/* include:place.stream.authFull",
		UpstreamScope:   "atproto blob:*/* include:place.stream.authFull",
	}
	if limited.HasScope("repo?collection=app.bsky.actor.status") {
		t.Error("limited session should not have the actor.status scope")
	}
	if !limited.HasScope("include:place.stream.authFull") {
		t.Error("limited session should have the streamplace scope")
	}

	// upstream (what the PDS actually granted) wins over downstream
	mismatched := &OAuthSession{
		DownstreamScope: testFullScope,
		UpstreamScope:   "atproto",
	}
	if got := mismatched.GrantedScope(); got != "atproto" {
		t.Errorf("GrantedScope() = %q, want upstream scope", got)
	}
	if mismatched.HasScope("blob:*/*") {
		t.Error("scope not granted upstream should be reported missing")
	}
}
