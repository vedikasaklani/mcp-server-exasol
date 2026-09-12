// Package audit writes the tamper-evident record described in §7.1, using
// the entry schema in §8.1.
//
// Three properties define it, and each one is a deliberate rejection of
// an easier design:
//
//   - Hash-chained, not per-entry signed. Every entry carries the hash of
//     its predecessor, and a signed checkpoint is written every N entries.
//     That gives the same tamper-evidence as signing each entry at a
//     fraction of the cost, which matters because this is on the path of
//     every request.
//   - Never blocks the response path. Entries go to a buffered channel
//     drained by a writer goroutine. A slow or full disk delays the audit
//     log; it does not delay the caller.
//   - Records its own gaps. If the buffer fills, the chain does not
//     silently skip entries — a gap marker is written instead, so a
//     verified chain with missing requests is distinguishable from a
//     verified chain that is complete. An audit log that can lose entries
//     invisibly is not an audit log.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Kind distinguishes the record types that share one chain.
type Kind string

const (
	// KindExecution is one tool call: the §8.1 entry proper.
	KindExecution Kind = "execution"
	// KindFinding is a behavioural detection raised or escalated.
	KindFinding Kind = "finding"
	// KindLifecycle is a session or container state change.
	KindLifecycle Kind = "lifecycle"
	// KindGap records that entries were lost because the buffer filled.
	// It exists so loss is visible in a chain that still verifies.
	KindGap Kind = "gap"
	// KindCheckpoint is a signed commitment to the chain head.
	KindCheckpoint Kind = "checkpoint"
)

// Entry is one record in the chain. Field names follow §8.1; the
// Authorization and ResponseGuard sections are typed and always emitted
// as null in v0, because IBAC and the response guard are v1 — leaving the
// shape in place now means the schema does not change when they land, and
// an explicit null is an honest statement that no authorization decision
// was made, which a missing field is not.
type Entry struct {
	EntryID       string    `json:"entry_id"`
	PrevHash      string    `json:"prev_hash"`
	Timestamp     time.Time `json:"timestamp"`
	Kind          Kind      `json:"kind"`
	SessionID     string    `json:"session_id"`
	RequestID     string    `json:"request_id,omitempty"`
	MCPServerID   string    `json:"mcp_server_id"`
	ImageDigest   string    `json:"image_digest"`
	AttestationID string    `json:"attestation_id,omitempty"`
	AIClientID    string    `json:"ai_client_id,omitempty"`

	// LearningMode must be true for any execution that was not fully
	// confined. CLAUDE.md: "Learning mode is an unconfined execution and
	// must be flagged as such." It is a required field, not an optional
	// one, so an entry that forgets it reads as false and is wrong in the
	// direction that gets noticed.
	LearningMode bool `json:"learning_mode"`

	Authorization *Authorization `json:"authorization"`
	Execution     *Execution     `json:"execution,omitempty"`
	Sandbox       *Sandbox       `json:"sandbox,omitempty"`
	ResponseGuard *ResponseGuard `json:"response_guard"`
	Analysis      *Analysis      `json:"analysis,omitempty"`
	Lifecycle     *Lifecycle     `json:"lifecycle,omitempty"`
	Gap           *Gap           `json:"gap,omitempty"`
	Checkpoint    *Checkpoint    `json:"checkpoint,omitempty"`

	// Hash is this entry's own digest, covering every field above. It is
	// excluded from its own computation (see Digest).
	Hash string `json:"hash"`
}

// Authorization mirrors §8.1's authorization block. Present as a type
// only; v0 writes null.
type Authorization struct {
	DeterministicTuples []string `json:"deterministic_tuples"`
	OpenFGADecision     string   `json:"openfga_decision"`
	TaintLabelsAtCall   []string `json:"taint_labels_at_call"`
	ApprovalTier        string   `json:"approval_tier"`
	Decision            string   `json:"decision"`
	DecisionReason      string   `json:"decision_reason"`
	LatencyMS           int      `json:"latency_ms"`
}

// Execution mirrors §8.1's execution block.
type Execution struct {
	ToolName       string `json:"tool_name"`
	Method         string `json:"method,omitempty"`
	RPCPayloadHash string `json:"rpc_payload_hash"`
	Status         string `json:"status"`
	LatencyMS      int64  `json:"latency_ms"`
	RequestBytes   int    `json:"request_bytes"`
	ResponseBytes  int    `json:"response_bytes"`
}

// Sandbox mirrors §8.1's sandbox block, extended with the byte-flow and
// fan-out measurements the behavioural detectors are built on. The extra
// fields are additive: everything §8.1 names is still here under its
// original name.
type Sandbox struct {
	Runtime          string   `json:"runtime"`
	ContainerID      string   `json:"container_id"`
	SeccompDenials   int      `json:"seccomp_denials"`
	LandlockDenials  int      `json:"landlock_denials"`
	NetworkConns     int      `json:"network_connections"`
	Anomalies        []string `json:"anomalies"`
	SyscallCount     int      `json:"syscall_count"`
	DistinctPaths    int      `json:"distinct_paths"`
	FileReadBytes    int64    `json:"file_read_bytes"`
	FileWriteBytes   int64    `json:"file_write_bytes"`
	NetReadBytes     int64    `json:"net_read_bytes"`
	NetWriteBytes    int64    `json:"net_write_bytes"`
	ProcessSpawns    int      `json:"process_spawns"`
	UnsolicitedMsgs  int      `json:"unsolicited_messages"`
	AttributionExact bool     `json:"attribution_exact"`
}

// ResponseGuard mirrors §8.1's response_guard block. v0 writes null.
type ResponseGuard struct {
	InjectionFlags int      `json:"injection_flags"`
	DLPFlags       int      `json:"dlp_flags"`
	TaintAdded     []string `json:"taint_added"`
}

// Analysis records a behavioural detection or the posture at the time of
// the entry.
type Analysis struct {
	Detector   string   `json:"detector,omitempty"`
	Family     string   `json:"family,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Title      string   `json:"title,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Posture    string   `json:"posture,omitempty"`
	Reason     string   `json:"posture_reason,omitempty"`
}

// Lifecycle records a session or container state change.
type Lifecycle struct {
	Event       string `json:"event"`
	ContainerID string `json:"container_id,omitempty"`
	State       string `json:"state,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// Gap records entries lost to backpressure.
type Gap struct {
	Lost   int64  `json:"lost_entries"`
	Reason string `json:"reason"`
}

// Checkpoint is a signed commitment to the chain up to this point.
type Checkpoint struct {
	Entries   int64  `json:"entries"`
	ChainHead string `json:"chain_head"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// Digest computes the entry's hash over every field except Hash itself.
//
// Canonicalisation is encoding/json's, which sorts struct fields by
// declaration order and map keys lexically — deterministic for a fixed
// struct definition. That makes the chain verifiable by any build of this
// package against a log written by any other, which is the property
// tamper-evidence actually requires.
func (e Entry) Digest() (string, error) {
	c := e
	c.Hash = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize entry: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// HashPayload returns the digest recorded for an RPC body. The body
// itself is never written to the audit log: it can contain the user's
// data and the tool's results, and an audit trail that duplicates every
// payload is an exfiltration target in its own right.
func HashPayload(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
