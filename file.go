package zlog

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

type FileConfig struct {
	Path       string
	MaxSize    int64
	MaxAge     time.Duration
	MaxBackups int
	Compress   bool
	Perm       os.FileMode
}

type RotatingFile struct {
	cfg  FileConfig
	mu   sync.Mutex
	f    *os.File
	size int64
}

func NewRotatingFile(cfg FileConfig) (*RotatingFile, error) {
	if cfg.Perm == 0 {
		cfg.Perm = 0640
	}
	rf := &RotatingFile{cfg: cfg}
	return rf, rf.open()
}
func (r *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.cfg.Path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(r.cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, r.cfg.Perm)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	r.f = f
	if st != nil {
		r.size = st.Size()
	}
	return nil
}
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.MaxSize > 0 && r.size+int64(len(p)) > r.cfg.MaxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}
func (r *RotatingFile) rotate() error {
	if r.f != nil {
		_ = r.f.Close()
	}
	ts := time.Now().UTC().Format("20060102T150405")
	dst := r.cfg.Path + "." + ts + "." + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.Rename(r.cfg.Path, dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	if r.cfg.Compress {
		go compressFile(dst)
	}
	r.cleanup()
	r.size = 0
	return r.open()
}
func (r *RotatingFile) cleanup() {
	if r.cfg.MaxBackups <= 0 && r.cfg.MaxAge <= 0 {
		return
	}
	files, _ := filepath.Glob(r.cfg.Path + ".*")
	sort.Slice(files, func(i, j int) bool {
		ai, _ := os.Stat(files[i])
		aj, _ := os.Stat(files[j])
		if ai == nil || aj == nil {
			return files[i] < files[j]
		}
		return ai.ModTime().Before(aj.ModTime())
	})
	now := time.Now()
	if r.cfg.MaxAge > 0 {
		for _, f := range files {
			if st, err := os.Stat(f); err == nil && now.Sub(st.ModTime()) > r.cfg.MaxAge {
				_ = os.Remove(f)
			}
		}
	}
	if r.cfg.MaxBackups > 0 && len(files) > r.cfg.MaxBackups {
		for len(files) > r.cfg.MaxBackups {
			_ = os.Remove(files[0])
			files = files[1:]
		}
	}
}
func (r *RotatingFile) Flush() error { r.mu.Lock(); defer r.mu.Unlock(); return r.f.Sync() }
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}
func compressFile(path string) {
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(path + ".gz")
	if err != nil {
		return
	}
	gz := gzip.NewWriter(out)
	_, _ = io.Copy(gz, in)
	_ = gz.Close()
	_ = out.Close()
	_ = os.Remove(path)
}
