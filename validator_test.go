package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// genKey generates a real Ed25519 key pair and returns the canonical base64
// public key and the private key.
func genKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

// mint creates a token and signs its canonical payload with priv.
func mint(id, issuer string, priv ed25519.PrivateKey, subject string,
	actions []string, path string, nb, na, depth int64) Token {
	tk := Token{
		ID: id, Issuer: issuer, Subject: subject, Actions: actions,
		Path: path, NotBefore: nb, NotAfter: na, Depth: depth,
	}
	tk.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload(&tk)))
	return tk
}

// chainFixture builds a valid two-level chain: root -> t1(A) -> t2(B).
type chainFixture struct {
	rootPub, aPub, bPub string
	rootPriv, aPriv     ed25519.PrivateKey
	t1, t2              Token
}

func newChainFixture(t *testing.T) chainFixture {
	t.Helper()
	rootPub, rootPriv := genKey(t)
	aPub, aPriv := genKey(t)
	bPub, _ := genKey(t)
	return chainFixture{
		rootPub: rootPub, aPub: aPub, bPub: bPub,
		rootPriv: rootPriv, aPriv: aPriv,
		t1: mint("t1", rootPub, rootPriv, aPub, []string{"read", "write"}, "/docs/", 100, 200, 2),
		t2: mint("t2", aPub, aPriv, bPub, []string{"read"}, "/docs/team/", 120, 180, 1),
	}
}

func (f chainFixture) input() *Input {
	return &Input{
		Roots:  []string{f.rootPub},
		Tokens: []Token{f.t1, f.t2},
		Request: Request{
			Subject: f.bPub, Action: "read",
			Resource: "/docs/team/report.txt", Time: 150,
		},
	}
}

func TestValidChainWithEvidence(t *testing.T) {
	f := newChainFixture(t)
	res := Validate(f.input())

	if res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}
	if got := strings.Join(res.Chain, ","); got != "t1,t2" {
		t.Fatalf("chain = %q, want t1,t2", got)
	}
	if len(res.Evidence) != 2 {
		t.Fatalf("evidence layers = %d, want 2", len(res.Evidence))
	}
	if !strings.Contains(res.Evidence[0].Narrowing, "trust root") {
		t.Errorf("layer 1 narrowing should anchor at the trust root: %q", res.Evidence[0].Narrowing)
	}
	n := res.Evidence[1].Narrowing
	for _, want := range []string{"read,write", "read", "/docs/", "/docs/team/", "2 -> 1"} {
		if !strings.Contains(n, want) {
			t.Errorf("layer 2 narrowing %q missing %q", n, want)
		}
	}
	if res.Request == nil || res.Request.LeafToken != "t2" {
		t.Errorf("request check leaf = %+v, want t2", res.Request)
	}
}

func TestTamperedSignaturePayload(t *testing.T) {
	otherPub, _ := genKey(t)
	cases := map[string]func(tk *Token){
		"id changed":         func(tk *Token) { tk.ID = "t2-forged" },
		"subject changed":    func(tk *Token) { tk.Subject = otherPub },
		"action added":       func(tk *Token) { tk.Actions = append(tk.Actions, "admin") },
		"path widened":       func(tk *Token) { tk.Path = "/" },
		"not_before moved":   func(tk *Token) { tk.NotBefore = 0 },
		"not_after extended": func(tk *Token) { tk.NotAfter = 9999 },
		"depth raised":       func(tk *Token) { tk.Depth = 9 },
		"signature flipped": func(tk *Token) {
			sig, _ := base64.StdEncoding.DecodeString(tk.Signature)
			sig[0] ^= 0xff
			tk.Signature = base64.StdEncoding.EncodeToString(sig)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newChainFixture(t)
			mutate(&f.t2) // keep the original signature over a changed payload
			res := Validate(f.input())
			if res.Status != StatusRejected {
				t.Fatalf("status = %q, want rejected", res.Status)
			}
			if !strings.Contains(res.Reason, "signature") {
				t.Fatalf("reason = %q, want a signature failure", res.Reason)
			}
		})
	}
}

func TestBadSignatureAnywhereRejectsBatch(t *testing.T) {
	f := newChainFixture(t)
	// An unrelated, correctly structured token with a broken signature must
	// poison the whole batch even though no chain needs it.
	dPub, _ := genKey(t)
	bad := mint("unrelated", f.rootPub, f.rootPriv, dPub, []string{"read"}, "/x/", 0, 10, 0)
	bad.Actions = []string{"read", "rm"} // payload changed after signing
	in := f.input()
	in.Tokens = append(in.Tokens, bad)
	if res := Validate(in); res.Status != StatusRejected {
		t.Fatalf("status = %q, want rejected", res.Status)
	}
}

func TestBoundaryMoments(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, _ := genKey(t)
	tok := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/r/", 100, 200, 0)

	for _, tc := range []struct {
		time int64
		want string
	}{
		{99, StatusUnauthorized},  // just before the window
		{100, StatusAuthorized},   // not_before is inclusive
		{199, StatusAuthorized},   // last valid instant
		{200, StatusUnauthorized}, // not_after is exclusive (half-open)
		{201, StatusUnauthorized},
	} {
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{tok},
			Request: Request{Subject: aPub, Action: "read", Resource: "/r/x", Time: tc.time},
		}
		if res := Validate(in); res.Status != tc.want {
			t.Errorf("time %d: status = %q, want %q", tc.time, res.Status, tc.want)
		}
	}
}

func TestNearPaths(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, _ := genKey(t)
	tok := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/a/b", 0, 100, 0)

	for _, tc := range []struct {
		resource string
		want     string
	}{
		{"/a/b", StatusAuthorized},   // the prefix itself
		{"/a/b/c", StatusAuthorized}, // strictly below
		{"/a/b/c/d.txt", StatusAuthorized},
		{"/a/bc", StatusUnauthorized}, // shares characters but not a segment boundary
		{"/a/bc/d", StatusUnauthorized},
		{"/a", StatusUnauthorized}, // above the prefix
		{"/a/bb", StatusUnauthorized},
	} {
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{tok},
			Request: Request{Subject: aPub, Action: "read", Resource: tc.resource, Time: 50},
		}
		if res := Validate(in); res.Status != tc.want {
			t.Errorf("resource %q: status = %q, want %q", tc.resource, res.Status, tc.want)
		}
	}
}

// TestRequestPathCanonicalization: the decision must be made on the
// canonical resource identity, so "." / ".." / duplicate separators cannot
// smuggle the resource outside the granted prefix, and equivalent spellings
// of the same resource get the same verdict.
func TestRequestPathCanonicalization(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, _ := genKey(t)
	tok := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/docs/team/", 0, 100, 0)

	for _, tc := range []struct {
		resource string
		want     string
	}{
		{"/docs/team/a.txt", StatusAuthorized},           // baseline
		{"/docs//team///a.txt", StatusAuthorized},        // duplicate separators
		{"/docs/./team/./a.txt", StatusAuthorized},       // dot segments
		{"/docs/team/sub/../a.txt", StatusAuthorized},    // ".." stays inside the prefix
		{"/docs/x/../team/a.txt", StatusAuthorized},      // ".." leaves and re-enters
		{"/docs/team/", StatusAuthorized},                // the prefix itself, trailing slash
		{"/docs/team/.", StatusAuthorized},               // the prefix itself, via "."
		{"/docs/team/../etc/passwd", StatusUnauthorized}, // escapes the prefix
		{"/docs/team/../../etc/passwd", StatusUnauthorized},
		{"/docs/../etc/passwd", StatusUnauthorized}, // never enters the prefix
		{"/../docs/team/a.txt", StatusAuthorized},   // ".." at the root is dropped: canonical "/docs/team/a.txt"
		{"/docs/team/..", StatusUnauthorized},       // canonical "/docs" is above the prefix
		{"/docs/team/../team", StatusAuthorized},    // canonical "/docs/team" == the prefix
	} {
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{tok},
			Request: Request{Subject: aPub, Action: "read", Resource: tc.resource, Time: 50},
		}
		if res := Validate(in); res.Status != tc.want {
			t.Errorf("resource %q: status = %q (%s), want %q", tc.resource, res.Status, res.Reason, tc.want)
		}
	}
}

func TestChildPathMustNarrowOnSegmentBoundary(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, aPriv := genKey(t)
	bPub, _ := genKey(t)
	parent := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/a/b", 0, 100, 2)

	// "/a/bc" is NOT under "/a/b" on a segment boundary: the child widens the
	// path, so the chain is broken and the request is unauthorized.
	sneaky := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/a/bc", 0, 100, 1)
	in := &Input{
		Roots:   []string{rootPub},
		Tokens:  []Token{parent, sneaky},
		Request: Request{Subject: bPub, Action: "read", Resource: "/a/bc/f", Time: 50},
	}
	if res := Validate(in); res.Status != StatusUnauthorized {
		t.Fatalf("status = %q, want unauthorized", res.Status)
	}

	// "/a/b/c" is a proper narrowing and must authorize.
	good := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/a/b/c", 0, 100, 1)
	in.Tokens = []Token{parent, good}
	in.Request.Resource = "/a/b/c/f"
	if res := Validate(in); res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}
}

// TestTokenPathCanonicalizedForNarrowing: narrowing between delegation
// layers is judged on canonical path identities, so an oddly spelled parent
// prefix still matches a clean child, and a child whose canonical identity
// escapes the parent breaks the chain.
func TestTokenPathCanonicalizedForNarrowing(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, aPriv := genKey(t)
	bPub, _ := genKey(t)

	// The parent's canonical identity is "/a/b" despite the odd spelling.
	parent := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/a/./b/", 0, 100, 2)
	child := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/a/b//c", 0, 100, 1)
	in := &Input{
		Roots:   []string{rootPub},
		Tokens:  []Token{parent, child},
		Request: Request{Subject: bPub, Action: "read", Resource: "/a/b/c/f", Time: 50},
	}
	if res := Validate(in); res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}

	// "/a/b/../c" canonicalizes to "/a/c", which is NOT under "/a/b": the
	// child widens the path and the chain must break.
	sneaky := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/a/b/../c", 0, 100, 1)
	in.Tokens = []Token{parent, sneaky}
	in.Request.Resource = "/a/c/f"
	if res := Validate(in); res.Status != StatusUnauthorized {
		t.Fatalf("status = %q, want unauthorized", res.Status)
	}
}

// TestSignatureBindsRawPath: the signature covers the raw path field; the
// canonical identity is derived from that signed field. Rewriting the raw
// path — even to an equivalent spelling — invalidates the signature.
func TestSignatureBindsRawPath(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, _ := genKey(t)
	tok := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/a/./b", 0, 100, 0)
	in := &Input{
		Roots:   []string{rootPub},
		Tokens:  []Token{tok},
		Request: Request{Subject: aPub, Action: "read", Resource: "/a/b/x", Time: 50},
	}
	if res := Validate(in); res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}

	tok.Path = "/a/b" // same canonical identity, different signed bytes
	in.Tokens = []Token{tok}
	if res := Validate(in); res.Status != StatusRejected {
		t.Fatalf("status = %q, want rejected", res.Status)
	}
}

// TestCanonicalIdentityInOutput: the authorized output exposes the canonical
// resource identity the decision was made on, per layer and for the request,
// alongside the raw signed fields.
func TestCanonicalIdentityInOutput(t *testing.T) {
	f := newChainFixture(t)
	in := f.input()
	in.Request.Resource = "/docs//team/./report.txt"
	res := Validate(in)
	if res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}
	if got := res.Request.CanonicalResource; got != "/docs/team/report.txt" {
		t.Errorf("canonical resource = %q, want /docs/team/report.txt", got)
	}
	if got := res.Evidence[0].CanonicalPath; got != "/docs" {
		t.Errorf("layer 1 canonical path = %q, want /docs", got)
	}
	if got := res.Evidence[1].CanonicalPath; got != "/docs/team" {
		t.Errorf("layer 2 canonical path = %q, want /docs/team", got)
	}
	// The raw signed fields remain visible for audit.
	if got := res.Evidence[1].Path; got != "/docs/team/" {
		t.Errorf("layer 2 raw path = %q, want /docs/team/", got)
	}
	if got := res.Request.Resource; got != "/docs//team/./report.txt" {
		t.Errorf("raw resource = %q, want the spelling from the request", got)
	}
}

// TestRevocationAndValidityUseCanonicalIdentity: with a non-canonical
// request spelling, revocation and validity checks still apply to the chain
// selected by the canonical resource identity.
func TestRevocationAndValidityUseCanonicalIdentity(t *testing.T) {
	f := newChainFixture(t)
	build := func(revoked ...string) *Input {
		in := f.input()
		in.Request.Resource = "/docs/team/../team/report.txt" // canonical "/docs/team/report.txt"
		in.Revoked = revoked
		return in
	}
	if res := Validate(build()); res.Status != StatusAuthorized {
		t.Fatalf("baseline: status = %q (%s), want authorized", res.Status, res.Reason)
	}
	if res := Validate(build("t2")); res.Status != StatusUnauthorized {
		t.Errorf("leaf revoked: status = %q, want unauthorized", res.Status)
	}
	expired := build()
	expired.Request.Time = 180 // outside the leaf's [120,180) window
	if res := Validate(expired); res.Status != StatusUnauthorized {
		t.Errorf("expired: status = %q, want unauthorized", res.Status)
	}
}

func TestMidChainRevocation(t *testing.T) {
	rootPub, rootPriv := genKey(t)
	aPub, aPriv := genKey(t)
	bPub, bPriv := genKey(t)
	cPub, _ := genKey(t)
	t1 := mint("t1", rootPub, rootPriv, aPub, []string{"read", "write"}, "/d/", 0, 100, 3)
	t2 := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/d/e/", 10, 90, 2)
	t3 := mint("t3", bPub, bPriv, cPub, []string{"read"}, "/d/e/f/", 20, 80, 1)

	build := func(revoked ...string) *Input {
		return &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{t1, t2, t3},
			Revoked: revoked,
			Request: Request{Subject: cPub, Action: "read", Resource: "/d/e/f/g", Time: 50},
		}
	}

	if res := Validate(build()); res.Status != StatusAuthorized {
		t.Fatalf("baseline: status = %q (%s), want authorized", res.Status, res.Reason)
	}
	for _, id := range []string{"t1", "t2", "t3"} { // root, middle, leaf
		if res := Validate(build(id)); res.Status != StatusUnauthorized {
			t.Errorf("revoking %s: status = %q, want unauthorized", id, res.Status)
		}
	}
	if res := Validate(build("no-such-token")); res.Status != StatusAuthorized {
		t.Errorf("unknown revoked id should be ignored: status = %q (%s)", res.Status, res.Reason)
	}
}

func TestRevokedUnrelatedTokenKeepsChain(t *testing.T) {
	f := newChainFixture(t)
	dPub, _ := genKey(t)
	other := mint("t9", f.rootPub, f.rootPriv, dPub, []string{"read"}, "/elsewhere/", 0, 50, 0)
	in := f.input()
	in.Tokens = append(in.Tokens, other)
	in.Revoked = []string{"t9"}
	if res := Validate(in); res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}
}

func TestLexicographicallySmallestChain(t *testing.T) {
	t.Run("string order of ids", func(t *testing.T) {
		rootPub, rootPriv := genKey(t)
		bPub, _ := genKey(t)
		// Both tokens authorize the request directly; "t10" < "t2" as strings.
		t10 := mint("t10", rootPub, rootPriv, bPub, []string{"read"}, "/r/", 0, 100, 0)
		t2 := mint("t2", rootPub, rootPriv, bPub, []string{"read"}, "/r/", 0, 100, 0)
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{t2, t10},
			Request: Request{Subject: bPub, Action: "read", Resource: "/r/x", Time: 50},
		}
		res := Validate(in)
		if res.Status != StatusAuthorized || strings.Join(res.Chain, ",") != "t10" {
			t.Fatalf("chain = %v (status %q), want [t10]", res.Chain, res.Status)
		}
	})

	t.Run("smallest at every position", func(t *testing.T) {
		rootPub, rootPriv := genKey(t)
		aPub, aPriv := genKey(t)
		bPub, bPriv := genKey(t)
		cPub, _ := genKey(t)
		t1 := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/r/", 0, 100, 5)
		t9 := mint("t9", aPub, aPriv, bPub, []string{"read"}, "/r/", 0, 100, 4)
		t4 := mint("t4", bPub, bPriv, cPub, []string{"read"}, "/r/", 0, 100, 3)
		t2 := mint("t2", aPub, aPriv, cPub, []string{"read"}, "/r/", 0, 100, 4)
		// Valid chains: [t1 t2] and [t1 t9 t4]; "t2" < "t9" at position 2.
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{t9, t4, t1, t2},
			Request: Request{Subject: cPub, Action: "read", Resource: "/r/x", Time: 50},
		}
		res := Validate(in)
		if res.Status != StatusAuthorized || strings.Join(res.Chain, ",") != "t1,t2" {
			t.Fatalf("chain = %v (status %q), want [t1 t2]", res.Chain, res.Status)
		}
	})
}

func TestDepthMustStrictlyDecrease(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		parentDepth, childDepth int64
	}{
		{"equal depth", 1, 1},
		{"child deeper", 1, 2},
		{"parent cannot delegate", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootPub, rootPriv := genKey(t)
			aPub, aPriv := genKey(t)
			bPub, _ := genKey(t)
			t1 := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/r/", 0, 100, tc.parentDepth)
			t2 := mint("t2", aPub, aPriv, bPub, []string{"read"}, "/r/", 0, 100, tc.childDepth)
			in := &Input{
				Roots:   []string{rootPub},
				Tokens:  []Token{t1, t2},
				Request: Request{Subject: bPub, Action: "read", Resource: "/r/x", Time: 50},
			}
			if res := Validate(in); res.Status != StatusUnauthorized {
				t.Fatalf("status = %q, want unauthorized", res.Status)
			}
		})
	}
}

func TestChildMustNotWidenActionsOrTime(t *testing.T) {
	cases := map[string]struct {
		childActions []string
		childNB      int64
		childNA      int64
	}{
		"action widened":     {[]string{"read", "write"}, 10, 90},
		"not_before earlier": {[]string{"read"}, 5, 90},
		"not_after later":    {[]string{"read"}, 10, 95},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rootPub, rootPriv := genKey(t)
			aPub, aPriv := genKey(t)
			bPub, _ := genKey(t)
			t1 := mint("t1", rootPub, rootPriv, aPub, []string{"read"}, "/r/", 10, 90, 2)
			t2 := mint("t2", aPub, aPriv, bPub, tc.childActions, "/r/", tc.childNB, tc.childNA, 1)
			in := &Input{
				Roots:   []string{rootPub},
				Tokens:  []Token{t1, t2},
				Request: Request{Subject: bPub, Action: "read", Resource: "/r/x", Time: 50},
			}
			if res := Validate(in); res.Status != StatusUnauthorized {
				t.Fatalf("status = %q, want unauthorized", res.Status)
			}
		})
	}
}

func TestActionNotGranted(t *testing.T) {
	f := newChainFixture(t)
	in := f.input()
	in.Request.Action = "delete"
	res := Validate(in)
	if res.Status != StatusUnauthorized {
		t.Fatalf("status = %q, want unauthorized", res.Status)
	}
	if !strings.Contains(res.Reason, "action not granted") {
		t.Fatalf("reason = %q, want an explicit action failure", res.Reason)
	}
}

func TestDelegationCycleRejectsBatch(t *testing.T) {
	rootPub, _ := genKey(t)
	xPub, xPriv := genKey(t)
	yPub, yPriv := genKey(t)

	t.Run("two-token cycle", func(t *testing.T) {
		t1 := mint("t1", xPub, xPriv, yPub, []string{"read"}, "/r/", 0, 100, 5)
		t2 := mint("t2", yPub, yPriv, xPub, []string{"read"}, "/r/", 0, 100, 5)
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{t1, t2},
			Request: Request{Subject: xPub, Action: "read", Resource: "/r/x", Time: 50},
		}
		res := Validate(in)
		if res.Status != StatusRejected || !strings.Contains(res.Reason, "cycle") {
			t.Fatalf("status = %q reason = %q, want rejected with cycle", res.Status, res.Reason)
		}
	})

	t.Run("self delegation", func(t *testing.T) {
		tk := mint("t1", xPub, xPriv, xPub, []string{"read"}, "/r/", 0, 100, 5)
		in := &Input{
			Roots:   []string{rootPub},
			Tokens:  []Token{tk},
			Request: Request{Subject: xPub, Action: "read", Resource: "/r/x", Time: 50},
		}
		if res := Validate(in); res.Status != StatusRejected {
			t.Fatalf("status = %q, want rejected", res.Status)
		}
	})
}

func TestDuplicateTokenIDRejectsBatch(t *testing.T) {
	f := newChainFixture(t)
	dup := f.t2
	dup.ID = "t1" // collides with the first token
	in := f.input()
	in.Tokens = append(in.Tokens, dup)
	res := Validate(in)
	if res.Status != StatusRejected || !strings.Contains(res.Reason, "duplicate") {
		t.Fatalf("status = %q reason = %q, want rejected with duplicate", res.Status, res.Reason)
	}
}

func TestUnknownIssuerRejectsBatch(t *testing.T) {
	f := newChainFixture(t)
	roguePub, roguePriv := genKey(t)
	dPub, _ := genKey(t)
	rogue := mint("rogue", roguePub, roguePriv, dPub, []string{"read"}, "/r/", 0, 100, 0)
	in := f.input()
	in.Tokens = append(in.Tokens, rogue)
	res := Validate(in)
	if res.Status != StatusRejected || !strings.Contains(res.Reason, "unknown issuer") {
		t.Fatalf("status = %q reason = %q, want rejected with unknown issuer", res.Status, res.Reason)
	}
}

func TestBatchLimits(t *testing.T) {
	f := newChainFixture(t)

	t.Run("no roots", func(t *testing.T) {
		in := f.input()
		in.Roots = nil
		if res := Validate(in); res.Status != StatusRejected {
			t.Fatalf("status = %q, want rejected", res.Status)
		}
	})

	t.Run("too many roots", func(t *testing.T) {
		in := f.input()
		for i := 0; i < 4; i++ {
			pub, _ := genKey(t)
			in.Roots = append(in.Roots, pub)
		}
		if res := Validate(in); res.Status != StatusRejected {
			t.Fatalf("status = %q, want rejected", res.Status)
		}
	})

	t.Run("too many tokens", func(t *testing.T) {
		in := f.input()
		dPub, _ := genKey(t)
		for i := 0; i < 39; i++ { // 2 + 39 = 41 > 40
			id := strings.Repeat("x", 1) + string(rune('a'+i%26)) + string(rune('a'+i/26))
			in.Tokens = append(in.Tokens, mint(id, f.rootPub, f.rootPriv, dPub, nil, "/z/", 0, 1, 0))
		}
		if res := Validate(in); res.Status != StatusRejected {
			t.Fatalf("status = %q, want rejected", res.Status)
		}
	})
}

func TestMultipleRoots(t *testing.T) {
	r1Pub, _ := genKey(t)
	r2Pub, r2Priv := genKey(t)
	bPub, _ := genKey(t)
	tok := mint("t1", r2Pub, r2Priv, bPub, []string{"read"}, "/r/", 0, 100, 0)
	in := &Input{
		Roots:   []string{r1Pub, r2Pub},
		Tokens:  []Token{tok},
		Request: Request{Subject: bPub, Action: "read", Resource: "/r/x", Time: 50},
	}
	if res := Validate(in); res.Status != StatusAuthorized {
		t.Fatalf("status = %q (%s), want authorized", res.Status, res.Reason)
	}
}

func TestUnknownSubjectIsUnauthorized(t *testing.T) {
	f := newChainFixture(t)
	strangerPub, _ := genKey(t)
	in := f.input()
	in.Request.Subject = strangerPub
	res := Validate(in)
	if res.Status != StatusUnauthorized {
		t.Fatalf("status = %q, want unauthorized", res.Status)
	}
	if !strings.Contains(res.Reason, "no live token names the subject") {
		t.Fatalf("reason = %q, want an explicit no-subject-token note", res.Reason)
	}
}

// TestCLI builds the binary and exercises exit codes and JSON output.
func TestCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "validator")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	run := func(in *Input) (Result, int) {
		t.Helper()
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		file := filepath.Join(t.TempDir(), "input.json")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
		cmd := exec.Command(bin, file)
		out, err := cmd.Output()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run validator: %v", err)
		}
		var res Result
		if err := json.Unmarshal(out, &res); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, out)
		}
		return res, code
	}

	f := newChainFixture(t)

	res, code := run(f.input())
	if code != 0 || res.Status != StatusAuthorized || len(res.Chain) != 2 || len(res.Evidence) != 2 {
		t.Fatalf("authorized case: code=%d res=%+v", code, res)
	}

	bad := f.input()
	bad.Request.Time = 200 // outside the half-open window
	res, code = run(bad)
	if code != 1 || res.Status != StatusUnauthorized || res.Reason == "" {
		t.Fatalf("unauthorized case: code=%d res=%+v", code, res)
	}

	tampered := f.input()
	tampered.Tokens[1].NotAfter = 9999 // signature no longer matches
	res, code = run(tampered)
	if code != 2 || res.Status != StatusRejected || res.Reason == "" {
		t.Fatalf("rejected case: code=%d res=%+v", code, res)
	}
}
