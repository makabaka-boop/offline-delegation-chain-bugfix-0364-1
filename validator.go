package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	maxRoots  = 4
	maxTokens = 40
)

// Verdict statuses.
const (
	StatusAuthorized   = "authorized"
	StatusUnauthorized = "unauthorized"
	StatusRejected     = "rejected" // the token batch itself is invalid; fail closed
)

// Token is a delegation token. Issuer and Subject are base64-encoded Ed25519
// public keys: principals are identified by their keys, so no identity
// service is needed. The signature covers the length-prefixed canonical
// encoding of every other field (see payload).
type Token struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Actions   []string `json:"actions"`
	Path      string   `json:"path"` // resource path prefix, segment-boundary matched
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"` // half-open interval [NotBefore, NotAfter)
	Depth     int64    `json:"depth"`     // remaining delegation layers; must strictly decrease along a chain
	Signature string   `json:"signature"`
}

// Request asks whether Subject may perform Action on Resource at Time.
type Request struct {
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Time     int64  `json:"time"`
}

// Input is the full CLI input document.
type Input struct {
	Roots   []string `json:"roots"`   // 1..4 base64 Ed25519 trust-root public keys
	Tokens  []Token  `json:"tokens"`  // up to 40 delegation tokens
	Revoked []string `json:"revoked"` // revoked token IDs; unknown IDs are ignored
	Request Request  `json:"request"`
}

// LayerEvidence records one chain layer and how it narrowed its parent.
type LayerEvidence struct {
	TokenID       string   `json:"token_id"`
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	Actions       []string `json:"actions"`
	Path          string   `json:"path"`           // raw path covered by the signature
	CanonicalPath string   `json:"canonical_path"` // normalized resource identity actually enforced
	NotBefore     int64    `json:"not_before"`
	NotAfter      int64    `json:"not_after"`
	Depth         int64    `json:"depth"`
	Narrowing     string   `json:"narrowing"`
}

// RequestCheck records the leaf token the request was matched against.
type RequestCheck struct {
	Subject           string `json:"subject"`
	Action            string `json:"action"`
	Resource          string `json:"resource"`           // resource spelling from the request
	CanonicalResource string `json:"canonical_resource"` // normalized identity the verdict was made on
	Time              int64  `json:"time"`
	LeafToken         string `json:"leaf_token"`
}

// Result is the CLI output document.
type Result struct {
	Status   string          `json:"status"`
	Reason   string          `json:"reason,omitempty"`
	Chain    []string        `json:"chain,omitempty"`
	Evidence []LayerEvidence `json:"evidence,omitempty"`
	Request  *RequestCheck   `json:"request_check,omitempty"`
}

// parsedToken carries a Token plus derived, trusted-once-verified data.
type parsedToken struct {
	tok       *Token
	actionSet map[string]bool
	segments  []string // canonical path split into segments
	canonical string   // lexical canonical form of tok.Path (path.Clean)
}

// canonicalPath resolves a resource path to a single lexical identity so that
// authorization is always decided on the resource, never on its spelling:
// duplicate separators collapse, "." segments drop, and ".." segments pop the
// preceding segment ("/a/../b" -> "/b"). Paths must be absolute; a path that
// escapes above the root is clamped there by path.Clean (e.g. "/../x" -> "/x").
// Relative or empty paths are rejected (fail closed). The raw string is what
// the signature covers; the canonical string is what every prefix comparison
// uses, so the two never get confused.
func canonicalPath(p string) (string, error) {
	if p == "" || p[0] != '/' {
		return "", fmt.Errorf("path %q must be absolute (start with /)", p)
	}
	c := path.Clean(p)
	if c != "/" {
		c = strings.TrimSuffix(c, "/")
	}
	return c, nil
}

// pathSegments splits a canonical path into its non-empty segments.
func pathSegments(canonical string) []string {
	if canonical == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(canonical, "/"), "/")
}

// pathWithin reports whether child lies under (or equals) the parent prefix.
// Both must be canonical segment lists.
func pathWithinSeg(parent, child []string) bool {
	if len(parent) > len(child) {
		return false
	}
	for i, s := range parent {
		if child[i] != s {
			return false
		}
	}
	return true
}

// canonicalKey decodes a base64 Ed25519 public key and re-encodes it
// canonically so keys compare by value, not by encoding.
func canonicalKey(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("bad base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return "", fmt.Errorf("want %d-byte Ed25519 key, got %d bytes", ed25519.PublicKeySize, len(b))
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func keyBytes(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte(s) // deterministic fallback; verification will fail anyway
	}
	return b
}

func normalizedActions(as []string) []string {
	seen := make(map[string]bool, len(as))
	out := make([]string, 0, len(as))
	for _, a := range as {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// payload is the canonical length-prefixed encoding of every signed field.
// Each field is emitted as an 8-byte big-endian length followed by its bytes;
// the action set is sorted and deduplicated, integers are 8-byte big-endian.
func payload(t *Token) []byte {
	var buf bytes.Buffer
	lp := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		buf.Write(n[:])
		buf.Write(b)
	}
	var num [8]byte
	putInt := func(v int64) {
		binary.BigEndian.PutUint64(num[:], uint64(v))
		lp(num[:])
	}

	lp([]byte(t.ID))
	lp(keyBytes(t.Issuer))
	lp(keyBytes(t.Subject))
	acts := normalizedActions(t.Actions)
	putInt(int64(len(acts)))
	for _, a := range acts {
		lp([]byte(a))
	}
	lp([]byte(t.Path))
	putInt(t.NotBefore)
	putInt(t.NotAfter)
	putInt(t.Depth)
	return buf.Bytes()
}

// narrows reports whether child is a valid delegation from parent: issued by
// the parent's subject, with strictly smaller depth and no widening of the
// action set, path prefix, or validity interval.
func narrows(parent, child *parsedToken) bool {
	if child.tok.Issuer != parent.tok.Subject {
		return false
	}
	if child.tok.Depth >= parent.tok.Depth {
		return false
	}
	for a := range child.actionSet {
		if !parent.actionSet[a] {
			return false
		}
	}
	if !pathWithinSeg(parent.segments, child.segments) {
		return false
	}
	if child.tok.NotBefore < parent.tok.NotBefore || child.tok.NotAfter > parent.tok.NotAfter {
		return false
	}
	return true
}

// findCycle returns one delegation cycle as token indices, or nil.
func findCycle(adj [][]int) []int {
	const (
		white = iota
		gray
		black
	)
	color := make([]int, len(adj))
	var stack []int
	var cycle []int
	var dfs func(u int) bool
	dfs = func(u int) bool {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range adj[u] {
			if color[v] == gray {
				start := 0
				for stack[start] != v {
					start++
				}
				cycle = append([]int(nil), stack[start:]...)
				return true
			}
			if color[v] == white && dfs(v) {
				return true
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
		return false
	}
	for i := range adj {
		if color[i] == white && dfs(i) {
			return cycle
		}
	}
	return nil
}

// Validate checks the batch (fail-closed) and, if it is well-formed, searches
// for the lexicographically smallest valid delegation chain answering the
// request.
func Validate(in *Input) Result {
	reject := func(format string, args ...any) Result {
		return Result{Status: StatusRejected, Reason: fmt.Sprintf(format, args...)}
	}

	if len(in.Roots) < 1 || len(in.Roots) > maxRoots {
		return reject("trust roots: need 1..%d, got %d", maxRoots, len(in.Roots))
	}
	if len(in.Tokens) > maxTokens {
		return reject("too many tokens: %d > %d", len(in.Tokens), maxTokens)
	}

	roots := make(map[string]bool, len(in.Roots))
	for _, r := range in.Roots {
		c, err := canonicalKey(r)
		if err != nil {
			return reject("invalid trust root key: %v", err)
		}
		roots[c] = true
	}

	reqSubject, err := canonicalKey(in.Request.Subject)
	if err != nil {
		return reject("invalid request subject key: %v", err)
	}

	// The request resource is normalized once, up front, so every check and the
	// emitted evidence refer to the same resource identity.
	reqCanonical, err := canonicalPath(in.Request.Resource)
	if err != nil {
		return reject("invalid request resource: %v", err)
	}

	// Per-token structural checks and duplicate-ID detection.
	ids := make(map[string]bool, len(in.Tokens))
	subjects := make(map[string]bool, len(in.Tokens))
	toks := make([]*parsedToken, 0, len(in.Tokens))
	for i := range in.Tokens {
		tk := &in.Tokens[i]
		if tk.ID == "" {
			return reject("token with empty id")
		}
		if ids[tk.ID] {
			return reject("duplicate token id %q", tk.ID)
		}
		ids[tk.ID] = true
		ci, err := canonicalKey(tk.Issuer)
		if err != nil {
			return reject("token %q: bad issuer key: %v", tk.ID, err)
		}
		cs, err := canonicalKey(tk.Subject)
		if err != nil {
			return reject("token %q: bad subject key: %v", tk.ID, err)
		}
		tk.Issuer, tk.Subject = ci, cs
		if tk.Depth < 0 {
			return reject("token %q: negative depth %d", tk.ID, tk.Depth)
		}
		if tk.NotBefore >= tk.NotAfter {
			return reject("token %q: empty validity interval [%d,%d)", tk.ID, tk.NotBefore, tk.NotAfter)
		}
		canonical, err := canonicalPath(tk.Path)
		if err != nil {
			return reject("token %q: invalid path: %v", tk.ID, err)
		}
		pt := &parsedToken{
			tok:       tk,
			actionSet: make(map[string]bool, len(tk.Actions)),
			segments:  pathSegments(canonical),
			canonical: canonical,
		}
		for _, a := range tk.Actions {
			pt.actionSet[a] = true
		}
		toks = append(toks, pt)
		subjects[cs] = true
	}

	// Every issuer must be a trust root or the subject of some batch token.
	for _, pt := range toks {
		if !roots[pt.tok.Issuer] && !subjects[pt.tok.Issuer] {
			return reject("token %q: unknown issuer", pt.tok.ID)
		}
	}

	// Every signature must verify against its issuer's key.
	for _, pt := range toks {
		sig, err := base64.StdEncoding.DecodeString(pt.tok.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return reject("token %q: malformed signature", pt.tok.ID)
		}
		if !ed25519.Verify(keyBytes(pt.tok.Issuer), payload(pt.tok), sig) {
			return reject("token %q: invalid signature", pt.tok.ID)
		}
	}

	// Delegation cycles anywhere in the batch poison it.
	adj := make([][]int, len(toks))
	for i, a := range toks {
		for j, b := range toks {
			if a.tok.Subject == b.tok.Issuer {
				adj[i] = append(adj[i], j)
			}
		}
	}
	if cyc := findCycle(adj); cyc != nil {
		names := make([]string, len(cyc))
		for i, idx := range cyc {
			names[i] = toks[idx].tok.ID
		}
		return reject("delegation cycle detected: %s", strings.Join(names, " -> "))
	}

	// The batch is well-formed. Revoked tokens drop out of chain building.
	revoked := make(map[string]bool, len(in.Revoked))
	for _, r := range in.Revoked {
		revoked[r] = true
	}
	live := make([]*parsedToken, 0, len(toks))
	for _, pt := range toks {
		if !revoked[pt.tok.ID] {
			live = append(live, pt)
		}
	}

	// Valid narrowing edges among live tokens. Depth strictly decreases along
	// every edge, so this graph is acyclic.
	edges := make([][]int, len(live))
	for i, a := range live {
		for j, b := range live {
			if i != j && narrows(a, b) {
				edges[i] = append(edges[i], j)
			}
		}
	}

	req := &in.Request
	reqSegments := pathSegments(reqCanonical)
	leafOK := func(pt *parsedToken) bool {
		return pt.tok.Subject == reqSubject &&
			pt.actionSet[req.Action] &&
			pathWithinSeg(pt.segments, reqSegments) &&
			pt.tok.NotBefore <= req.Time && req.Time < pt.tok.NotAfter
	}

	// canReach(i): some valid chain starting at live[i] ends in a leaf that
	// answers the request. Because every edge narrows, the constraints in
	// force at live[i] are exactly live[i]'s own, so memoization on i is sound.
	memo := make([]int8, len(live)) // 0 unknown, 1 no, 2 yes
	var canReach func(i int) bool
	canReach = func(i int) bool {
		if memo[i] != 0 {
			return memo[i] == 2
		}
		ok := leafOK(live[i])
		if !ok {
			for _, j := range edges[i] {
				if canReach(j) {
					ok = true
					break
				}
			}
		}
		if ok {
			memo[i] = 2
		} else {
			memo[i] = 1
		}
		return ok
	}

	// Greedily build the lexicographically smallest token-ID sequence: at each
	// position take the smallest ID that can still complete a valid chain.
	// (A chain is never a strict prefix of another chain to the same subject:
	// extending past a leaf would require a self-delegation, i.e. a cycle.)
	var chain []int
	cur := -1
	for {
		if cur >= 0 && leafOK(live[cur]) {
			break
		}
		best := -1
		if cur < 0 {
			for i, pt := range live {
				if roots[pt.tok.Issuer] && canReach(i) && (best < 0 || pt.tok.ID < live[best].tok.ID) {
					best = i
				}
			}
		} else {
			for _, j := range edges[cur] {
				if canReach(j) && (best < 0 || live[j].tok.ID < live[best].tok.ID) {
					best = j
				}
			}
		}
		if best < 0 {
			break
		}
		chain = append(chain, best)
		cur = best
	}

	if cur < 0 || !leafOK(live[cur]) {
		return Result{Status: StatusUnauthorized, Reason: unauthorizedReason(live, req, reqCanonical, reqSubject, reqSegments)}
	}

	return Result{
		Status:   StatusAuthorized,
		Chain:    chainIDs(live, chain),
		Evidence: buildEvidence(live, chain),
		Request: &RequestCheck{
			Subject:           req.Subject,
			Action:            req.Action,
			Resource:          req.Resource,
			CanonicalResource: reqCanonical,
			Time:              req.Time,
			LeafToken:         live[cur].tok.ID,
		},
	}
}

// unauthorizedReason explains, per live token naming the subject, why it
// could not answer the request.
func unauthorizedReason(live []*parsedToken, req *Request, reqCanonical string, reqSubject string, reqSegments []string) string {
	base := fmt.Sprintf("no valid delegation chain from a trust root to the subject for action %q on %q (canonical %q) at time %d",
		req.Action, req.Resource, reqCanonical, req.Time)
	var hints []string
	for _, pt := range live {
		if pt.tok.Subject != reqSubject {
			continue
		}
		var fails []string
		if !pt.actionSet[req.Action] {
			fails = append(fails, "action not granted")
		}
		if !pathWithinSeg(pt.segments, reqSegments) {
			fails = append(fails, fmt.Sprintf("resource %q outside canonical path prefix %q (signed path %q)",
				reqCanonical, pt.canonical, pt.tok.Path))
		}
		if !(pt.tok.NotBefore <= req.Time && req.Time < pt.tok.NotAfter) {
			fails = append(fails, fmt.Sprintf("time outside validity [%d,%d)", pt.tok.NotBefore, pt.tok.NotAfter))
		}
		if len(fails) == 0 {
			fails = append(fails, "no unrevoked narrowing chain from a trust root")
		}
		hints = append(hints, fmt.Sprintf("token %q: %s", pt.tok.ID, strings.Join(fails, "; ")))
	}
	if len(hints) == 0 {
		return base + "; no live token names the subject"
	}
	return base + ": " + strings.Join(hints, "; ")
}

func chainIDs(live []*parsedToken, chain []int) []string {
	ids := make([]string, len(chain))
	for i, idx := range chain {
		ids[i] = live[idx].tok.ID
	}
	return ids
}

func buildEvidence(live []*parsedToken, chain []int) []LayerEvidence {
	ev := make([]LayerEvidence, len(chain))
	for i, idx := range chain {
		pt := live[idx]
		narrowing := "root-issued: chain anchored at a trust root"
		if i > 0 {
			prev := live[chain[i-1]]
			narrowing = fmt.Sprintf("actions {%s} narrowed to {%s}; canonical path %q narrowed to %q (signed %q -> %q); validity [%d,%d) narrowed to [%d,%d); depth %d -> %d",
				strings.Join(normalizedActions(prev.tok.Actions), ","),
				strings.Join(normalizedActions(pt.tok.Actions), ","),
				prev.canonical, pt.canonical,
				prev.tok.Path, pt.tok.Path,
				prev.tok.NotBefore, prev.tok.NotAfter,
				pt.tok.NotBefore, pt.tok.NotAfter,
				prev.tok.Depth, pt.tok.Depth)
		}
		ev[i] = LayerEvidence{
			TokenID:       pt.tok.ID,
			Issuer:        pt.tok.Issuer,
			Subject:       pt.tok.Subject,
			Actions:       normalizedActions(pt.tok.Actions),
			Path:          pt.tok.Path,
			CanonicalPath: pt.canonical,
			NotBefore:     pt.tok.NotBefore,
			NotAfter:      pt.tok.NotAfter,
			Depth:         pt.tok.Depth,
			Narrowing:     narrowing,
		}
	}
	return ev
}
