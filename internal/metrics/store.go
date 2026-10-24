package metrics

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type MetricStore struct {
	writerDB *sql.DB
	readerDB *sql.DB
	writeCh  chan MetricPoint
	flushCh  chan chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
}

const (
	batchSize     = 100
	flushInterval = time.Second
)

func NewMetricStore(dir string) (*MetricStore, error) {
	dbPath := filepath.Join(dir, "metrics.db")
	dsn := fmt.Sprintf("file:%s", dbPath)

	writerDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	writerDB.SetMaxOpenConns(1)

	// modernc.org/sqlite does not support DSN pragma parameters.
	if _, err := writerDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		writerDB.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := writerDB.Exec("PRAGMA busy_timeout=5000"); err != nil {
		writerDB.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	readerDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		writerDB.Close()
		return nil, fmt.Errorf("open reader: %w", err)
	}
	// PRAGMAs are per-connection, so keep the pool at one connection.
	readerDB.SetMaxOpenConns(1)
	if _, err := readerDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		writerDB.Close()
		readerDB.Close()
		return nil, fmt.Errorf("set reader WAL mode: %w", err)
	}
	if _, err := readerDB.Exec("PRAGMA busy_timeout=5000"); err != nil {
		writerDB.Close()
		readerDB.Close()
		return nil, fmt.Errorf("set reader busy timeout: %w", err)
	}

	// auto_vacuum must be set before the schema exists to take effect on a fresh file.
	if err := ensureIncrementalVacuum(writerDB); err != nil {
		writerDB.Close()
		readerDB.Close()
		return nil, err
	}

	if _, err := writerDB.Exec(`
		CREATE TABLE IF NOT EXISTS metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			metric_id TEXT NOT NULL,
			value REAL NOT NULL,
			timestamp INTEGER NOT NULL,
			unit TEXT,
			UNIQUE(metric_id, timestamp)
		);
		CREATE INDEX IF NOT EXISTS idx_metric_time ON metrics(metric_id, timestamp DESC);
	`); err != nil {
		writerDB.Close()
		readerDB.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0600); err != nil && !os.IsNotExist(err) {
			writerDB.Close()
			readerDB.Close()
			return nil, fmt.Errorf("chmod %s: %w", p, err)
		}
	}

	s := &MetricStore{
		writerDB: writerDB,
		readerDB: readerDB,
		writeCh:  make(chan MetricPoint, 1000),
		flushCh:  make(chan chan struct{}),
		done:     make(chan struct{}),
	}

	s.wg.Add(1)
	go s.writerLoop()

	return s, nil
}

func (s *MetricStore) Write(p MetricPoint) {
	select {
	case s.writeCh <- p:
	default:
	}
}

func (s *MetricStore) Flush() {
	flushDone := make(chan struct{})
	select {
	case s.flushCh <- flushDone:
		<-flushDone
	case <-s.done:
	}
}

func (s *MetricStore) writerLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			s.flushBatch()
			return
		case <-ticker.C:
			s.flushBatch()
		case done := <-s.flushCh:
			s.flushBatch()
			close(done)
		}
	}
}

func (s *MetricStore) flushBatch() {
	var batch []MetricPoint
	for {
		select {
		case p := <-s.writeCh:
			batch = append(batch, p)
			if len(batch) >= batchSize {
				s.insertBatch(batch)
				batch = nil
			}
		default:
			if len(batch) > 0 {
				s.insertBatch(batch)
			}
			return
		}
	}
}

func (s *MetricStore) insertBatch(batch []MetricPoint) {
	tx, err := s.writerDB.Begin()
	if err != nil {
		slog.Warn("metric batch begin failed", "error", err)
		return
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO metrics (metric_id, value, timestamp, unit) VALUES (?, ?, ?, ?)")
	if err != nil {
		slog.Warn("metric batch prepare failed", "error", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, p := range batch {
		if _, err := stmt.Exec(p.MetricID, p.Value, p.Timestamp, p.Unit); err != nil {
			slog.Warn("metric write failed", "metric_id", p.MetricID, "error", err)
		}
	}
	if err := tx.Commit(); err != nil {
		slog.Warn("metric batch commit failed", "error", err)
	}
}

func (s *MetricStore) Latest() (map[string]MetricPoint, error) {
	rows, err := s.readerDB.Query(`
		SELECT metric_id, value, timestamp, unit
		FROM metrics
		WHERE (metric_id, timestamp) IN (
			SELECT metric_id, MAX(timestamp) FROM metrics GROUP BY metric_id
		)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]MetricPoint)
	for rows.Next() {
		var p MetricPoint
		var unit sql.NullString
		if err := rows.Scan(&p.MetricID, &p.Value, &p.Timestamp, &unit); err != nil {
			continue
		}
		p.Unit = unit.String
		result[p.MetricID] = p
	}
	return result, nil
}

func (s *MetricStore) Series(metricID string, duration time.Duration) ([]MetricPoint, error) {
	cutoff := time.Now().Add(-duration).UnixMilli()
	rows, err := s.readerDB.Query(
		"SELECT metric_id, value, timestamp, unit FROM metrics WHERE metric_id = ? AND timestamp > ? ORDER BY timestamp",
		metricID, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []MetricPoint
	for rows.Next() {
		var p MetricPoint
		var unit sql.NullString
		if err := rows.Scan(&p.MetricID, &p.Value, &p.Timestamp, &unit); err != nil {
			continue
		}
		p.Unit = unit.String
		points = append(points, p)
	}
	return points, nil
}

func (s *MetricStore) SeriesDownsampled(metricID string, duration time.Duration, bucketSeconds int64) ([]MetricPoint, error) {
	cutoff := time.Now().Add(-duration).UnixMilli()
	bucketMs := bucketSeconds * 1000
	rows, err := s.readerDB.Query(
		`SELECT (timestamp / ?) * ? AS bucket, AVG(value) AS value
		 FROM metrics WHERE metric_id = ? AND timestamp > ?
		 GROUP BY bucket ORDER BY bucket`,
		bucketMs, bucketMs, metricID, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []MetricPoint
	for rows.Next() {
		var p MetricPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			continue
		}
		p.MetricID = metricID
		points = append(points, p)
	}
	return points, nil
}

// Switching to auto_vacuum=INCREMENTAL needs one VACUUM on a NONE-mode file.
func ensureIncrementalVacuum(db *sql.DB) error {
	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return fmt.Errorf("read auto_vacuum: %w", err)
	}
	if mode == 2 { // INCREMENTAL
		return nil
	}
	if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
		return fmt.Errorf("set auto_vacuum: %w", err)
	}
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum for auto_vacuum: %w", err)
	}
	return nil
}

func (s *MetricStore) Cleanup(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	result, err := s.writerDB.Exec("DELETE FROM metrics WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if _, err := s.writerDB.Exec("PRAGMA incremental_vacuum"); err != nil {
			slog.Warn("metrics.db incremental vacuum failed", "error", err)
		}
	}
	return n, nil
}

func (s *MetricStore) Close() {
	close(s.done)
	s.wg.Wait()
	s.writerDB.Close()
	s.readerDB.Close()
}
