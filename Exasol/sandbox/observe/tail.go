package observe

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// TailStats are the counters a Tailer keeps about its own health. A
// monitoring pipeline that cannot report on its own liveness is a
// pipeline that fails silently, so these are exported and surfaced on the
// dashboard alongside what they measure.
type TailStats struct {
	FilesOpen    int64
	LinesRead    int64
	EventsParsed int64
	Dropped      int64 // events discarded because the consumer fell behind
	Truncations  int64
	BytesRead    int64
}

// Tailer follows every log file runsc writes into a directory and emits
// parsed syscall events as they appear, for the whole life of a
// container. This is what separates continuous monitoring from the
// one-shot Run path: Run waits for a process to exit and then parses a
// complete log, which cannot work for a server that is supposed to stay
// up indefinitely.
//
// Two properties matter for a process that runs for days:
//
//   - Bounded memory. Events go to a buffered channel and are DROPPED,
//     with a counter, if the consumer falls behind. Analysis lagging is
//     recoverable; the daemon OOMing because analysis lagged is not.
//   - Bounded disk. gVisor never rotates its debug log. Past
//     MaxBytesPerFile the Tailer truncates the file it has already
//     consumed (see truncate) rather than letting a long-running
//     container fill the disk.
type Tailer struct {
	// Dir is the runsc -debug-log directory to follow.
	Dir string
	// PollInterval is how often the directory is rescanned for new files
	// and existing files checked for growth. Defaults to 200ms.
	PollInterval time.Duration
	// Buffer is the event channel depth. Defaults to 4096.
	Buffer int
	// MaxBytesPerFile truncates a consumed log file once it exceeds this
	// size. Zero disables truncation (the log then grows without bound).
	MaxBytesPerFile int64

	stats struct {
		filesOpen    atomic.Int64
		linesRead    atomic.Int64
		eventsParsed atomic.Int64
		dropped      atomic.Int64
		truncations  atomic.Int64
		bytesRead    atomic.Int64
	}
}

// Stats returns a snapshot of the tailer's counters. Safe to call
// concurrently with Follow.
func (t *Tailer) Stats() TailStats {
	return TailStats{
		FilesOpen:    t.stats.filesOpen.Load(),
		LinesRead:    t.stats.linesRead.Load(),
		EventsParsed: t.stats.eventsParsed.Load(),
		Dropped:      t.stats.dropped.Load(),
		Truncations:  t.stats.truncations.Load(),
		BytesRead:    t.stats.bytesRead.Load(),
	}
}

type tailedFile struct {
	f      *os.File
	reader *bufio.Reader
	offset int64
	// partial holds a line that was only half-written when we read it.
	// gVisor appends whole lines, but a reader can still observe a write
	// in progress, and half a JSON object parses as nothing at all.
	partial string
}

// Follow streams events until ctx is cancelled, then closes the returned
// channel. It returns immediately; the work happens in a goroutine.
func (t *Tailer) Follow(ctx context.Context) <-chan SyscallEvent {
	interval := t.PollInterval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	buf := t.Buffer
	if buf <= 0 {
		buf = 4096
	}
	out := make(chan SyscallEvent, buf)

	go func() {
		defer close(out)
		open := map[string]*tailedFile{}
		defer func() {
			for _, tf := range open {
				tf.f.Close()
			}
		}()

		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			t.scan(open)
			t.drain(open, out)
			select {
			case <-ctx.Done():
				// One final pass so events emitted just before shutdown
				// are not lost — the last thing a container does before
				// being destroyed is often the most interesting thing it
				// does.
				t.scan(open)
				t.drain(open, out)
				return
			case <-tick.C:
			}
		}
	}()
	return out
}

// scan opens any log file in Dir that isn't already being followed.
func (t *Tailer) scan(open map[string]*tailedFile) {
	entries, err := os.ReadDir(t.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(t.Dir, e.Name())
		if _, ok := open[path]; ok {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		open[path] = &tailedFile{f: f, reader: bufio.NewReaderSize(f, 256*1024)}
		t.stats.filesOpen.Add(1)
	}
}

// drain reads everything newly appended to each followed file.
func (t *Tailer) drain(open map[string]*tailedFile, out chan<- SyscallEvent) {
	for path, tf := range open {
		for {
			line, err := tf.reader.ReadString('\n')
			if len(line) > 0 {
				tf.offset += int64(len(line))
				t.stats.bytesRead.Add(int64(len(line)))
			}
			if err != nil {
				// Short read: hold the fragment and retry next tick once
				// the rest has been appended.
				if len(line) > 0 {
					tf.partial += line
				}
				break
			}
			full := tf.partial + line
			tf.partial = ""
			t.stats.linesRead.Add(1)
			ev, ok := ParseLine(full)
			if !ok {
				continue
			}
			t.stats.eventsParsed.Add(1)
			select {
			case out <- ev:
			default:
				t.stats.dropped.Add(1)
			}
		}
		if t.MaxBytesPerFile > 0 && tf.offset > t.MaxBytesPerFile {
			t.truncate(path, tf)
		}
	}
}

// truncate resets a fully consumed log file to zero length so a
// container that runs for days does not fill the disk with trace output.
//
// This is safe only because we truncate strictly behind our own read
// offset: everything discarded has already been parsed. gVisor opens its
// debug log with O_APPEND, so its next write resumes at offset 0. If a
// future runsc holds an explicit offset instead, it will write past a
// sparse hole; the NUL bytes that produces fail ParseLine and are
// skipped, which costs accounting accuracy but cannot corrupt analysis.
func (t *Tailer) truncate(path string, tf *tailedFile) {
	if err := os.Truncate(path, 0); err != nil {
		return
	}
	if _, err := tf.f.Seek(0, io.SeekStart); err != nil {
		return
	}
	tf.reader.Reset(tf.f)
	tf.offset = 0
	tf.partial = ""
	t.stats.truncations.Add(1)
}
