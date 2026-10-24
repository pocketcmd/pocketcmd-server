package server

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Appends never block and errors are swallowed: the store sits behind the
// default slog handler, so blocking or logging here would stall or recurse.
type LogStore struct {
	db      *sql.DB
	maxRows int

	pruneEvery int // tests tune it before the first Append

	entries chan json.RawMessage
	flushes chan chan struct{}
}

func NewLogStore(db *sql.DB, maxRows int) *LogStore {
	if maxRows <= 0 {
		maxRows = 10000
	}
	s := &LogStore{
		db:         db,
		maxRows:    maxRows,
		pruneEvery: 500,
		entries:    make(chan json.RawMessage, 1024),
		flushes:    make(chan chan struct{}),
	}
	go s.writer()
	return s
}

func (s *LogStore) Append(entry json.RawMessage) {
	select {
	case s.entries <- entry:
	default:
	}
}

func (s *LogStore) flush() {
	done := make(chan struct{})
	s.flushes <- done
	<-done
}

func (s *LogStore) writer() {
	sincePrune := 0
	writeOne := func(entry json.RawMessage) {
		if _, err := s.db.Exec(
			`INSERT INTO server_logs (ts, entry) VALUES (?, ?)`,
			entryTimeMs(entry), string(entry)); err != nil {
			return
		}
		if sincePrune++; sincePrune >= s.pruneEvery {
			sincePrune = 0
			_, _ = s.db.Exec(`DELETE FROM server_logs WHERE id <= (
				SELECT id FROM server_logs ORDER BY id DESC LIMIT 1 OFFSET ?)`,
				s.maxRows)
		}
	}
	for {
		select {
		case entry := <-s.entries:
			writeOne(entry)
		case done := <-s.flushes:
			// select picks cases randomly, so drain entries queued before the flush.
			for {
				select {
				case entry := <-s.entries:
					writeOne(entry)
					continue
				default:
				}
				break
			}
			close(done)
		}
	}
}

func (s *LogStore) PurgeUser(userID string) {
	if userID == "" {
		return
	}
	s.flush()
	_, _ = s.db.Exec(
		`DELETE FROM server_logs WHERE entry LIKE ? ESCAPE '\'`,
		`%"user_id":"`+escapeLike(userID)+`"%`)
}

func escapeLike(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(v)
}

func entryTimeMs(entry json.RawMessage) int64 {
	var meta struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(entry, &meta); err == nil && meta.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, meta.Time); err == nil {
			return t.UnixMilli()
		}
	}
	return time.Now().UnixMilli()
}

func (s *LogStore) Query(q LogQuery) (entries []LogEntry, total int, hasMore bool) {
	s.flush()
	filterClause, args := "", []any{}
	if q.UserID != "" {
		filterClause += ` AND entry LIKE ? ESCAPE '\'`
		args = append(args, `%"user_id":"`+escapeLike(q.UserID)+`"%`)
	}
	if q.FromMs > 0 {
		filterClause += ` AND ts >= ?`
		args = append(args, q.FromMs)
	}
	if q.ToMs > 0 {
		filterClause += ` AND ts <= ?`
		args = append(args, q.ToMs)
	}
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM server_logs WHERE 1=1`+filterClause, args...,
	).Scan(&total); err != nil {
		return nil, 0, false
	}
	pageArgs := args
	pageClause := filterClause
	if q.BeforeID > 0 {
		pageClause += ` AND id < ?`
		pageArgs = append(pageArgs, q.BeforeID)
	}
	rows, err := s.db.Query(
		`SELECT id, entry FROM server_logs WHERE 1=1`+pageClause+
			` ORDER BY id DESC LIMIT ?`,
		append(pageArgs, q.Limit)...)
	if err != nil {
		return nil, total, false
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var entry string
		if err := rows.Scan(&id, &entry); err != nil {
			continue
		}
		if json.Valid([]byte(entry)) {
			entries = append(entries, LogEntry{ID: id, Entry: json.RawMessage(entry)})
		}
	}
	if len(entries) > 0 {
		oldest := entries[len(entries)-1].ID
		var n int
		if err := s.db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM server_logs WHERE id < ?`+filterClause+`)`,
			append([]any{oldest}, args...)...).Scan(&n); err == nil {
			hasMore = n != 0
		}
	}
	return entries, total, hasMore
}
