package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// GenesisHash is the PrevHash of the first entry in a chain.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Config configures a Log.
type Config struct {
	// Path is the append-only chain file.
	Path string
	// SessionID stamps every entry.
	SessionID string
	// ServerID and ImageDigest identify the artifact under audit.
	ServerID    string
	ImageDigest string
	// LearningMode marks every entry in this log as unconfined. It is set
	// once at construction and cannot be changed afterwards, so a log
	// cannot start out flagged and quietly stop being.
	LearningMode bool
	// CheckpointEvery writes a signed checkpoint after this many entries.
	// Defaults to 100.
	CheckpointEvery int64
	// CheckpointInterval writes a signed checkpoint after this long, even
	// if the entry count has not been reached. Defaults to 60s.
	CheckpointInterval time.Duration
	// Buffer is the queue depth before backpressure turns into a
	// recorded gap. Defaults to 4096.
	Buffer int
	// SigningKey signs checkpoints. Generated if nil — a generated key
	// still detects tampering by anyone without the running process's
	// memory, which is the threat a local audit log can actually address.
	SigningKey ed25519.PrivateKey
}

// Log is an append-only, hash-chained audit log.
type Log struct {
	cfg Config

	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	prevHash string
	seq      int64
	lastCP   time.Time

	queue   chan Entry
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Int64
	written atomic.Int64
	backlog atomic.Int64

	pub ed25519.PublicKey
	key ed25519.PrivateKey
}

// Open creates or resumes a chain at cfg.Path.
//
// Resuming re-reads the existing file to recover the chain head, so
// restarting the daemon extends the chain rather than forking it. A new
// chain that ignored the old one would leave a verifiable log whose
// verification proves nothing about the period before the restart.
func Open(cfg Config) (*Log, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: no path configured")
	}
	if cfg.CheckpointEvery <= 0 {
		cfg.CheckpointEvery = 100
	}
	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = 60 * time.Second
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 4096
	}

	key := cfg.SigningKey
	var pub ed25519.PublicKey
	if key == nil {
		var err error
		pub, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("audit: generate signing key: %w", err)
		}
	} else {
		pub = key.Public().(ed25519.PublicKey)
	}

	prev, seq, err := recoverHead(cfg.Path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open chain: %w", err)
	}

	l := &Log{
		cfg:      cfg,
		f:        f,
		w:        bufio.NewWriterSize(f, 64*1024),
		prevHash: prev,
		seq:      seq,
		lastCP:   time.Now(),
		queue:    make(chan Entry, cfg.Buffer),
		done:     make(chan struct{}),
		pub:      pub,
		key:      key,
	}
	go l.writer()
	return l, nil
}

// recoverHead replays an existing chain file to find its head hash and
// entry count.
func recoverHead(path string) (string, int64, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return GenesisHash, 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("audit: read existing chain: %w", err)
	}
	defer f.Close()

	head := GenesisHash
	var n int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// A truncated final line is the normal result of a crash
			// mid-write. Stop here and extend from the last good entry
			// rather than refusing to start.
			break
		}
		head = e.Hash
		n++
	}
	return head, n, nil
}

// PublicKey returns the checkpoint verification key, hex encoded.
func (l *Log) PublicKey() string { return hex.EncodeToString(l.pub) }

// Stats reports the log's own health.
type Stats struct {
	Written   int64  `json:"written"`
	Dropped   int64  `json:"dropped"`
	Backlog   int64  `json:"backlog"`
	ChainHead string `json:"chain_head"`
	PublicKey string `json:"public_key"`
	Path      string `json:"path"`
}

// Stats returns a snapshot of the log's counters.
func (l *Log) Stats() Stats {
	l.mu.Lock()
	head := l.prevHash
	l.mu.Unlock()
	return Stats{
		Written:   l.written.Load(),
		Dropped:   l.dropped.Load(),
		Backlog:   int64(len(l.queue)),
		ChainHead: head,
		PublicKey: l.PublicKey(),
		Path:      l.cfg.Path,
	}
}

// Append queues an entry. It never blocks: §7.1 requires that audit never
// block the response path. If the queue is full the entry is counted as
// lost and a gap marker is written once the writer catches up, so the
// loss appears in the chain rather than being hidden by it.
func (l *Log) Append(e Entry) {
	if l.closed.Load() {
		return
	}
	e.SessionID = l.cfg.SessionID
	e.MCPServerID = l.cfg.ServerID
	e.ImageDigest = l.cfg.ImageDigest
	e.LearningMode = l.cfg.LearningMode
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	select {
	case l.queue <- e:
		l.backlog.Store(int64(len(l.queue)))
	default:
		l.dropped.Add(1)
	}
}

func (l *Log) writer() {
	defer close(l.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-l.queue:
			if !ok {
				l.flushGaps()
				l.mu.Lock()
				l.w.Flush()
				l.mu.Unlock()
				return
			}
			l.flushGaps()
			l.commit(e)
			l.maybeCheckpoint()
		case <-tick.C:
			l.flushGaps()
			l.maybeCheckpoint()
			l.mu.Lock()
			l.w.Flush()
			l.mu.Unlock()
		}
	}
}

// flushGaps records any entries lost to backpressure since the last
// check.
func (l *Log) flushGaps() {
	n := l.dropped.Swap(0)
	if n == 0 {
		return
	}
	l.commit(Entry{
		Kind:         KindGap,
		Timestamp:    time.Now().UTC(),
		SessionID:    l.cfg.SessionID,
		MCPServerID:  l.cfg.ServerID,
		ImageDigest:  l.cfg.ImageDigest,
		LearningMode: l.cfg.LearningMode,
		Gap:          &Gap{Lost: n, Reason: "audit queue full; entries were not recorded"},
	})
}

// commit links, hashes, and writes one entry.
func (l *Log) commit(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e.PrevHash = l.prevHash
	e.EntryID = fmt.Sprintf("ae_%s_%06d", shortID(l.cfg.SessionID), l.seq)
	hash, err := e.Digest()
	if err != nil {
		return
	}
	e.Hash = hash

	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		return
	}
	l.prevHash = hash
	l.written.Add(1)
	l.backlog.Store(int64(len(l.queue)))
}

func (l *Log) maybeCheckpoint() {
	l.mu.Lock()
	due := l.seq > 0 && (l.seq%l.cfg.CheckpointEvery == 0 || time.Since(l.lastCP) >= l.cfg.CheckpointInterval)
	if !due {
		l.mu.Unlock()
		return
	}
	head := l.prevHash
	entries := l.seq
	l.lastCP = time.Now()
	l.mu.Unlock()

	sig := ed25519.Sign(l.key, []byte(head))
	l.commit(Entry{
		Kind:         KindCheckpoint,
		Timestamp:    time.Now().UTC(),
		SessionID:    l.cfg.SessionID,
		MCPServerID:  l.cfg.ServerID,
		ImageDigest:  l.cfg.ImageDigest,
		LearningMode: l.cfg.LearningMode,
		Checkpoint: &Checkpoint{
			Entries:   entries,
			ChainHead: head,
			PublicKey: hex.EncodeToString(l.pub),
			Signature: base64.StdEncoding.EncodeToString(sig),
			Algorithm: "ed25519",
		},
	})
	l.mu.Lock()
	l.w.Flush()
	l.mu.Unlock()
}

// Close drains the queue, writes a final checkpoint, and flushes. It is
// the only place the audit log is allowed to block.
func (l *Log) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.queue)
	<-l.done
	l.forceCheckpoint()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.w.Flush(); err != nil {
		return err
	}
	return l.f.Close()
}

func (l *Log) forceCheckpoint() {
	l.mu.Lock()
	head := l.prevHash
	entries := l.seq
	l.mu.Unlock()
	sig := ed25519.Sign(l.key, []byte(head))
	l.commit(Entry{
		Kind:         KindCheckpoint,
		Timestamp:    time.Now().UTC(),
		SessionID:    l.cfg.SessionID,
		MCPServerID:  l.cfg.ServerID,
		ImageDigest:  l.cfg.ImageDigest,
		LearningMode: l.cfg.LearningMode,
		Checkpoint: &Checkpoint{
			Entries:   entries,
			ChainHead: head,
			PublicKey: hex.EncodeToString(l.pub),
			Signature: base64.StdEncoding.EncodeToString(sig),
			Algorithm: "ed25519",
		},
	})
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	if s == "" {
		return "anon"
	}
	return s
}
