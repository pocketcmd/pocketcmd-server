package config

import (
	"fmt"
	"os"
	"sync"
)

const (
	DefaultMaxLogSize  = 100 * 1024 * 1024
	DefaultMaxLogFiles = 3
)

type RotatingWriter struct {
	path     string
	maxSize  int64
	maxFiles int
	mu       sync.Mutex
	file     *os.File
	size     int64
}

func NewRotatingWriter(path string) (*RotatingWriter, error) {
	w := &RotatingWriter{
		path:     path,
		maxSize:  DefaultMaxLogSize,
		maxFiles: DefaultMaxLogFiles,
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) openFile() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}

func (w *RotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		w.rotate()
	}

	n, err = w.file.Write(p)
	w.size += int64(n)
	return
}

func (w *RotatingWriter) rotate() {
	if w.file != nil && w.file != os.Stderr {
		w.file.Close()
	}

	for i := w.maxFiles - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(src, dst)
	}
	os.Rename(w.path, w.path+".1")

	os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxFiles+1))

	if err := w.openFile(); err != nil {
		fmt.Fprintf(os.Stderr, "pcmd: audit log rotate: reopen %s failed: %v; falling back to stderr\n", w.path, err)
		w.file = os.Stderr
		w.size = 0
	}
}

func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil && w.file != os.Stderr {
		return w.file.Close()
	}
	return nil
}
