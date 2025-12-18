package validator

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	errPassw "github.com/raulaguila/go-passw/validator/errors"
)

type PolicyMetrics struct {
	ReloadCount   uint64
	ReloadFailure uint64
}

type PolicyEngineReloadable struct {
	mu      sync.RWMutex
	engine  *PolicyEngine
	path    string
	metrics *PolicyMetrics
}

func NewPolicyEngineReloadable(path string) (*PolicyEngineReloadable, error) {
	engine, err := LoadPolicyFromYAML(path)
	if err != nil {
		return nil, err
	}

	r := &PolicyEngineReloadable{
		engine:  engine,
		path:    path,
		metrics: &PolicyMetrics{},
	}

	go r.watch()
	return r, nil
}

func (r *PolicyEngineReloadable) Validate(password string) []errPassw.ValidationError {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.engine.Validate(password)
}

func (r *PolicyEngineReloadable) Metrics() PolicyMetrics {
	return PolicyMetrics{
		ReloadCount:   atomic.LoadUint64(&r.metrics.ReloadCount),
		ReloadFailure: atomic.LoadUint64(&r.metrics.ReloadFailure),
	}
}

func (r *PolicyEngineReloadable) watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("watcher error:", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(r.path); err != nil {
		log.Println("watcher add error:", err)
		return
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				time.Sleep(100 * time.Millisecond) // debounce

				engine, err := LoadPolicyFromYAML(r.path)
				if err != nil {
					atomic.AddUint64(&r.metrics.ReloadFailure, 1)
					log.Println("policy reload failed:", err)
					continue
				}

				r.mu.Lock()
				r.engine = engine
				r.mu.Unlock()

				atomic.AddUint64(&r.metrics.ReloadCount, 1)
				log.Println("policy reloaded successfully")
			}

		case err := <-watcher.Errors:
			log.Println("watcher error:", err)
		}
	}
}
