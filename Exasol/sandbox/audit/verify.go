package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Report is the result of verifying a chain.
type Report struct {
	Entries      int      `json:"entries"`
	Checkpoints  int      `json:"checkpoints"`
	Executions   int      `json:"executions"`
	Findings     int      `json:"findings"`
	Gaps         int      `json:"gaps"`
	LostEntries  int64    `json:"lost_entries"`
	ChainHead    string   `json:"chain_head"`
	Valid        bool     `json:"valid"`
	Problems     []string `json:"problems,omitempty"`
	LearningRuns int      `json:"learning_mode_entries"`
}

// Verify replays a chain file and checks three independent things: that
// every entry's hash matches its own content, that every entry links to
// its predecessor, and that every checkpoint signature is valid for the
// chain head it commits to.
//
// All three are checked even after the first failure. A verifier that
// stops at the first broken link tells you where tampering started but
// not how much of the log is affected, and the second question is the one
// an incident responder actually has.
func Verify(path string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: open chain: %w", err)
	}
	defer f.Close()
	return VerifyReader(f)
}

// VerifyReader verifies a chain read from r.
func VerifyReader(r io.Reader) (*Report, error) {
	rep := &Report{Valid: true, ChainHead: GenesisHash}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)

	expectedPrev := GenesisHash
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			rep.Valid = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("line %d: not a valid entry: %v", line, err))
			continue
		}
		rep.Entries++

		if e.PrevHash != expectedPrev {
			rep.Valid = false
			rep.Problems = append(rep.Problems,
				fmt.Sprintf("line %d (%s): chain break — prev_hash %s, expected %s", line, e.EntryID, short(e.PrevHash), short(expectedPrev)))
		}
		want, err := e.Digest()
		if err != nil {
			rep.Valid = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("line %d: cannot hash: %v", line, err))
		} else if want != e.Hash {
			rep.Valid = false
			rep.Problems = append(rep.Problems,
				fmt.Sprintf("line %d (%s): content does not match its hash — the entry was modified after it was written", line, e.EntryID))
		}
		expectedPrev = e.Hash
		rep.ChainHead = e.Hash

		if e.LearningMode {
			rep.LearningRuns++
		}
		switch e.Kind {
		case KindCheckpoint:
			rep.Checkpoints++
			if problem := verifyCheckpoint(e, line); problem != "" {
				rep.Valid = false
				rep.Problems = append(rep.Problems, problem)
			}
		case KindExecution:
			rep.Executions++
		case KindFinding:
			rep.Findings++
		case KindGap:
			rep.Gaps++
			if e.Gap != nil {
				rep.LostEntries += e.Gap.Lost
			}
		}
	}
	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("audit: read chain: %w", err)
	}
	// A chain with recorded gaps verifies as intact — nothing was
	// tampered with — but it is not complete, and saying so is the whole
	// point of writing the gap markers.
	if rep.Gaps > 0 {
		rep.Problems = append(rep.Problems,
			fmt.Sprintf("chain is intact but incomplete: %d gap marker(s) record %d lost entries", rep.Gaps, rep.LostEntries))
	}
	return rep, nil
}

func verifyCheckpoint(e Entry, line int) string {
	cp := e.Checkpoint
	if cp == nil {
		return fmt.Sprintf("line %d: checkpoint entry has no checkpoint block", line)
	}
	if cp.Algorithm != "ed25519" {
		return fmt.Sprintf("line %d: unknown checkpoint algorithm %q", line, cp.Algorithm)
	}
	pub, err := hex.DecodeString(cp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Sprintf("line %d: checkpoint public key is unusable", line)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		return fmt.Sprintf("line %d: checkpoint signature is not valid base64", line)
	}
	if !ed25519.Verify(pub, []byte(cp.ChainHead), sig) {
		return fmt.Sprintf("line %d (%s): checkpoint signature does not verify", line, e.EntryID)
	}
	if cp.ChainHead != e.PrevHash {
		return fmt.Sprintf("line %d (%s): checkpoint commits to %s but follows %s", line, e.EntryID, short(cp.ChainHead), short(e.PrevHash))
	}
	return ""
}

func short(h string) string {
	if len(h) > 23 {
		return h[:23] + "…"
	}
	return h
}

// Tail returns the last n entries of a chain, newest last. Used by the
// dashboard; reading the whole file is acceptable because an audit log
// that has grown past what a single read can handle should be being
// shipped somewhere, not browsed in a web page.
func Tail(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]Entry, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if len(ring) == n {
			copy(ring, ring[1:])
			ring = ring[:n-1]
		}
		ring = append(ring, e)
	}
	return ring, sc.Err()
}
