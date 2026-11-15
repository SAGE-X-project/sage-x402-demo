// Package trace writes the debugging records the demo keeps at every point
// where payment data or the acting party changes. A record names the
// boundary, the party before and after, digests of the data before and after,
// the decision and an internal reason. It never holds keys or signatures.
package trace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event is one trust-boundary record.
type Event struct {
	Time        time.Time `json:"time"`
	Correlation string    `json:"correlation"`
	Boundary    string    `json:"boundary"`
	ActorBefore string    `json:"actor_before,omitempty"`
	ActorAfter  string    `json:"actor_after,omitempty"`
	DigestIn    string    `json:"digest_in,omitempty"`
	DigestOut   string    `json:"digest_out,omitempty"`
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason,omitempty"`
	Detail      any       `json:"detail,omitempty"`
}

// Sink receives events. The zero value of Writer discards them.
type Sink interface{ Emit(Event) }

// Writer appends events as JSON lines to a file.
type Writer struct {
	mu   sync.Mutex
	file *os.File
}

// Open creates path and refuses to overwrite an existing trace.
func Open(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Writer{file: f}, nil
}

func (w *Writer) Emit(e Event) {
	if w == nil || w.file == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.file.Write(append(line, '\n'))
}

func (w *Writer) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	return w.file.Close()
}

// Digest is the hex SHA-256 of a value's JSON encoding.
func Digest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
