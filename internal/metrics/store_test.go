package metrics

import (
	"testing"
	"time"
)

func TestMetricStore_WriteAndLatest(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UnixMilli()
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 45.2, Timestamp: now, Unit: "%"})
	store.Write(MetricPoint{MetricID: "custom:memory", Value: 8.5, Timestamp: now, Unit: "GB"})
	store.Flush()

	latest, err := store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(latest))
	}
	if latest["custom:cpu"].Value != 45.2 {
		t.Fatalf("expected 45.2, got %f", latest["custom:cpu"].Value)
	}
}

func TestMetricStore_Series(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Now().Add(-time.Hour + time.Second).UnixMilli()
	for i := 0; i < 10; i++ {
		store.Write(MetricPoint{
			MetricID:  "custom:cpu",
			Value:     float64(40 + i),
			Timestamp: base + int64(i*60000),
			Unit:      "%",
		})
	}
	store.Flush()

	points, err := store.Series("custom:cpu", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 10 {
		t.Fatalf("expected 10 points, got %d", len(points))
	}
}

func TestMetricStore_SeriesDownsampled(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Now().Add(-6*time.Hour + time.Second).UnixMilli()
	for i := 0; i < 360; i++ {
		store.Write(MetricPoint{
			MetricID:  "custom:cpu",
			Value:     float64(40 + (i % 20)),
			Timestamp: base + int64(i*60000),
			Unit:      "%",
		})
	}
	store.Flush()

	points, err := store.SeriesDownsampled("custom:cpu", 6*time.Hour, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) < 300 {
		t.Fatalf("expected ~360 buckets, got %d", len(points))
	}
}

func TestMetricStore_Retention(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	old := time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	recent := time.Now().UnixMilli()
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 10, Timestamp: old, Unit: "%"})
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 50, Timestamp: recent, Unit: "%"})
	store.Flush()

	deleted, err := store.Cleanup(7 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}

	latest, _ := store.Latest()
	if latest["custom:cpu"].Value != 50 {
		t.Fatal("recent point should remain")
	}
}

func TestMetricStore_DuplicateTimestamp(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UnixMilli()
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 45, Timestamp: now, Unit: "%"})
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 99, Timestamp: now, Unit: "%"})
	store.Flush()

	latest, _ := store.Latest()
	if latest["custom:cpu"].Value != 45 {
		t.Fatalf("expected first value 45, got %f", latest["custom:cpu"].Value)
	}
}

func TestMetricStore_CleanupReclaimsSpace(t *testing.T) {
	store, err := NewMetricStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var mode int
	if err := store.writerDB.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("auto_vacuum=%d (%v), want 2 (incremental)", mode, err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	for i := 0; i < 5000; i++ {
		store.Write(MetricPoint{MetricID: "custom:cpu", Value: float64(i), Timestamp: old + int64(i), Unit: "%"})
		if i%500 == 499 {
			store.Flush()
		}
	}
	store.Flush()
	if n, err := store.Cleanup(7 * 24 * time.Hour); err != nil || n != 5000 {
		t.Fatalf("cleanup: n=%d err=%v", n, err)
	}
	var free int
	if err := store.writerDB.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil || free != 0 {
		t.Fatalf("freelist_count=%d (%v), want 0 after incremental vacuum", free, err)
	}
}
