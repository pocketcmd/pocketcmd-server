package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// Implementations must never log through slog themselves, which would recurse.
type LogSink interface {
	Append(entry json.RawMessage)
}

type LogEntry struct {
	ID    int64
	Entry json.RawMessage
}

type LogQuery struct {
	Limit    int
	BeforeID int64 // only entries with id < BeforeID; 0 starts at the newest
	UserID   string
	FromMs   int64 // inclusive epoch-millisecond bounds; 0 is unbounded
	ToMs     int64
}

// total counts every filter match, not just the page; hasMore reports whether older entries follow.
type LogSource interface {
	Query(q LogQuery) (entries []LogEntry, total int, hasMore bool)
}

type bufferHandler struct {
	sink   LogSink
	prefix string
	fixed  map[string]any
}

func NewBufferHandler(sink LogSink) slog.Handler {
	return &bufferHandler{sink: sink}
}

func (h *bufferHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *bufferHandler) Handle(_ context.Context, r slog.Record) error {
	m := make(map[string]any, r.NumAttrs()+len(h.fixed)+3)
	m["time"] = r.Time.UTC().Format(time.RFC3339)
	m["level"] = r.Level.String()
	m["msg"] = r.Message
	for k, v := range h.fixed {
		m[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		flattenAttr(m, h.prefix, a)
		return true
	})
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	h.sink.Append(b)
	return nil
}

func (h *bufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.fixed = make(map[string]any, len(h.fixed)+len(attrs))
	for k, v := range h.fixed {
		next.fixed[k] = v
	}
	for _, a := range attrs {
		flattenAttr(next.fixed, h.prefix, a)
	}
	return &next
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	next := *h
	if name != "" {
		next.prefix = h.prefix + name + "."
	}
	return &next
}

func flattenAttr(m map[string]any, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, ga := range v.Group() {
			flattenAttr(m, prefix+a.Key+".", ga)
		}
		return
	}
	m[prefix+a.Key] = v.Any()
}

type teeHandler struct{ handlers []slog.Handler }

func NewTeeHandler(handlers ...slog.Handler) slog.Handler {
	return &teeHandler{handlers: handlers}
}

func (t *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range t.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &teeHandler{handlers: next}
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		next[i] = h.WithGroup(name)
	}
	return &teeHandler{handlers: next}
}
