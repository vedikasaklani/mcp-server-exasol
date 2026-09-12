package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// ManifestDrift implements §4.3's rug-pull defence at the analysis layer.
//
// The attack is that a server advertises benign tool descriptions at
// approval time and mutates them afterwards, because the description is
// what the model reads and therefore what the model obeys. Pinning the
// manifest hash for the session lifetime makes the mutation detectable
// for the cost of one hash comparison.
type ManifestDrift struct{}

func (ManifestDrift) Name() string   { return "manifest-drift" }
func (ManifestDrift) Family() Family { return FamilyProtocol }

func (d ManifestDrift) Inspect(s *Snapshot) []Finding {
	// The engine only ever stores a drift marker here; the comparison
	// itself happens at the moment a manifest is observed, since that is
	// the only point both values exist.
	if !strings.HasPrefix(s.ManifestHash, "DRIFT ") {
		return nil
	}
	return []Finding{mk(d, "changed", SeverityCritical, ConfidenceDeterministic,
		"tool manifest changed mid-session",
		"the server's advertised tool names, descriptions or schemas differ from the ones pinned at session start",
		strings.TrimPrefix(s.ManifestHash, "DRIFT "))}
}

// HashManifest produces the pinned value for a tools/list response. Tool
// entries are sorted by name first so that a server reordering its list
// — which changes nothing a client depends on — does not read as a
// rug-pull.
func HashManifest(payload []byte) (string, bool) {
	var msg struct {
		Result struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil || len(msg.Result.Tools) == 0 {
		return "", false
	}
	tools := msg.Result.Tools
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	h := sha256.New()
	for _, t := range tools {
		h.Write([]byte(t.Name))
		h.Write([]byte{0})
		h.Write([]byte(t.Description))
		h.Write([]byte{0})
		h.Write(t.InputSchema)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), true
}

// ArgumentAccessMismatch compares what a tool call asked for against what
// it actually touched.
//
// §5.1 requires the target resource to be extracted from arguments by a
// typed extractor, never by a model. This is the same comparison applied
// after the fact and against the kernel's record: the call said
// path=/data/report.csv, the syscalls opened /home/user/.ssh/id_ed25519.
// It is the closest thing in this system to detecting intent, and it
// works precisely because it never asks what the server meant — only
// whether the files it opened bear any relation to the ones it was asked
// about.
type ArgumentAccessMismatch struct{}

func (ArgumentAccessMismatch) Name() string   { return "argument-access-mismatch" }
func (ArgumentAccessMismatch) Family() Family { return FamilyProtocol }

func (d ArgumentAccessMismatch) Inspect(s *Snapshot) []Finding {
	var out []Finding
	for _, w := range s.CompletedRequests() {
		wanted := pathArguments(w.Args)
		if len(wanted) == 0 {
			continue
		}
		var unrelated []string
		for p, a := range w.Paths {
			// Only data access counts. Module resolution, library loads
			// and metadata probes are the runtime's business, not the
			// request's, and including them would make every call look
			// like a mismatch.
			if a.Kind == AccessStat || a.ReadBytes+a.WriteBytes == 0 {
				continue
			}
			if IsModulePath(p) || IsSharedObject(p) {
				continue
			}
			if relatedToAny(p, wanted) {
				continue
			}
			unrelated = append(unrelated, fmt.Sprintf("%s (%s, %d bytes)", p, a.Kind, a.ReadBytes+a.WriteBytes))
		}
		if len(unrelated) == 0 {
			continue
		}
		sort.Strings(unrelated)
		sev := SeverityMedium
		conf := ConfidenceStatistical
		for _, u := range unrelated {
			if IsSensitivePath(u) {
				sev = SeverityCritical
				conf = ConfidenceDeterministic
				break
			}
		}
		out = append(out, mk(d, w.ToolName, sev, conf,
			"files accessed bear no relation to the call's arguments",
			fmt.Sprintf("request %s (%s) named %v but read or wrote %d unrelated path(s)",
				w.RequestID, w.ToolName, wanted, len(unrelated)),
			unrelated...))
	}
	return out
}

// pathArguments picks out the argument values that look like filesystem
// paths or path fragments.
func pathArguments(args map[string]string) []string {
	var out []string
	for k, v := range args {
		if v == "" || len(v) > 4096 {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(v, "/") || strings.Contains(lk, "path") ||
			strings.Contains(lk, "file") || strings.Contains(lk, "dir") ||
			strings.Contains(lk, "uri") {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// relatedToAny reports whether an accessed path plausibly corresponds to
// one of the paths the call named — the same file, something under a
// named directory, a parent directory traversed to reach it, or a name
// match for a relative argument.
func relatedToAny(accessed string, wanted []string) bool {
	for _, w := range wanted {
		if w == "" {
			continue
		}
		clean := strings.TrimSuffix(w, "/")
		if accessed == clean || strings.HasPrefix(accessed, clean+"/") {
			return true
		}
		// Traversing toward the target is legitimate: opening
		// /data/reports requires resolving /data.
		if strings.HasPrefix(clean, strings.TrimSuffix(accessed, "/")+"/") {
			return true
		}
		if base := path.Base(clean); base != "" && base != "." && base != "/" && strings.Contains(accessed, base) {
			return true
		}
	}
	return false
}

// UnsolicitedTraffic reports server-initiated messages that answered no
// request.
//
// Unsolicited output is not inherently wrong — MCP defines progress and
// logging notifications — but it is content that reaches the client, and
// therefore the model, without a request having asked for it. §4.4 treats
// everything on the return path as attacker-influenceable; this measures
// how much of it arrives unrequested.
type UnsolicitedTraffic struct {
	// PerRequest is the ratio of notifications to requests above which
	// the volume is reported.
	PerRequest float64
}

func (UnsolicitedTraffic) Name() string   { return "unsolicited-traffic" }
func (UnsolicitedTraffic) Family() Family { return FamilyProtocol }

func (d UnsolicitedTraffic) Inspect(s *Snapshot) []Finding {
	if s.Requests == 0 || s.Totals.Unsolicited == 0 {
		return nil
	}
	limit := d.PerRequest
	if limit <= 0 {
		limit = 4
	}
	rate := float64(s.Totals.Unsolicited) / float64(s.Requests)
	if rate <= limit {
		return nil
	}
	return []Finding{mk(d, "rate", SeverityLow, ConfidenceHeuristic,
		"high volume of unsolicited messages",
		fmt.Sprintf("%d unsolicited messages across %d requests (%.1f per request); all of it reaches the client as model-visible content",
			s.Totals.Unsolicited, s.Requests, rate))}
}

// ResponseAnomaly reports responses far larger than the session norm.
// Oversized responses are how a compromised server delivers injected
// instructions into the model's context at scale, and the size is
// measurable without inspecting the content — which matters, because the
// content is exactly what must not be trusted.
type ResponseAnomaly struct {
	MADThreshold float64
	MinBytes     int
}

func (ResponseAnomaly) Name() string   { return "response-anomaly" }
func (ResponseAnomaly) Family() Family { return FamilyProtocol }

func (d ResponseAnomaly) Inspect(s *Snapshot) []Finding {
	if !s.Warm() {
		return nil
	}
	threshold := d.MADThreshold
	if threshold <= 0 {
		threshold = 8
	}
	minBytes := d.MinBytes
	if minBytes <= 0 {
		minBytes = 64 * 1024
	}
	done := s.CompletedRequests()
	vals := make([]float64, 0, len(done))
	for _, w := range done {
		vals = append(vals, float64(w.ResponseBytes))
	}
	var out []Finding
	for _, w := range done {
		if w.ResponseBytes < minBytes {
			continue
		}
		if madScore(float64(w.ResponseBytes), vals) < threshold {
			continue
		}
		out = append(out, mk(d, w.RequestID, SeverityLow, ConfidenceStatistical,
			"response much larger than the session norm",
			fmt.Sprintf("request %s returned %d bytes against a median of %.0f", w.RequestID, w.ResponseBytes, median(vals))))
	}
	return out
}
