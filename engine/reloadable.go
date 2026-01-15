package engine

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/raulaguila/passguard/config"
	"github.com/raulaguila/passguard/errors"
)

// Metrics contains reload statistics.
type Metrics struct {
	ReloadCount   uint64
	ReloadFailure uint64
	LastReload    time.Time
	LastReloadErr error
}

// ReloadableEngine wraps an Engine with hot-reload capabilities.
type ReloadableEngine struct {
	mu      sync.RWMutex
	engine  *Engine
	path    string
	metrics *Metrics
	logger  *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// NewReloadable creates a new reloadable engine that watches for config changes.
func NewReloadable(path string) (*ReloadableEngine, error) {
	return NewReloadableWithLogger(path, slog.Default())
}

// NewReloadableWithLogger creates a new reloadable engine with a custom logger.
func NewReloadableWithLogger(path string, logger *slog.Logger) (*ReloadableEngine, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	engine, err := BuildFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Use discard handler if logger is nil
	if logger == nil {
		logger = slog.New(discardHandler{})
	}

	r := &ReloadableEngine{
		engine:  engine,
		path:    path,
		metrics: &Metrics{},
		logger:  logger,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	go r.watch(ctx)
	return r, nil
}

// Validate checks the password against all rules.
// The context can be used for cancellation.
func (r *ReloadableEngine) Validate(ctx context.Context, password string, failFast bool) []errors.ValidationError {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.engine.Validate(ctx, password, failFast)
}

// Metrics returns the current reload metrics.
func (r *ReloadableEngine) Metrics() Metrics {
	return Metrics{
		ReloadCount:   atomic.LoadUint64(&r.metrics.ReloadCount),
		ReloadFailure: atomic.LoadUint64(&r.metrics.ReloadFailure),
		LastReload:    r.metrics.LastReload,
		LastReloadErr: r.metrics.LastReloadErr,
	}
}

// Close stops the file watcher and releases resources.
func (r *ReloadableEngine) Close() error {
	r.cancel()
	<-r.done
	return nil
}

func (r *ReloadableEngine) watch(ctx context.Context) {
	defer close(r.done)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		r.logger.Error("failed to create watcher", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(r.path); err != nil {
		r.logger.Error("failed to watch file", "path", r.path, "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// Debounce to avoid multiple reloads
				time.Sleep(100 * time.Millisecond)
				r.reload()
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			r.logger.Error("watcher error", "error", err)
		}
	}
}

func (r *ReloadableEngine) reload() {
	r.metrics.LastReload = time.Now()

	cfg, err := config.Load(r.path)
	if err != nil {
		atomic.AddUint64(&r.metrics.ReloadFailure, 1)
		r.metrics.LastReloadErr = err
		r.logger.Error("policy reload failed", "error", err)
		return
	}

	engine, err := BuildFromConfig(cfg)
	if err != nil {
		atomic.AddUint64(&r.metrics.ReloadFailure, 1)
		r.metrics.LastReloadErr = err
		r.logger.Error("policy build failed", "error", err)
		return
	}

	r.mu.Lock()
	r.metrics.LastReloadErr = nil
	r.engine = engine
	r.mu.Unlock()

	atomic.AddUint64(&r.metrics.ReloadCount, 1)
	r.logger.Info("policy reloaded successfully")
}

// discardHandler is a slog.Handler that discards all logs.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }
