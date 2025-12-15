package passvalidator

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/raulaguila/passvalidator/errors"
	"github.com/raulaguila/passvalidator/rules"
)

func LoadPolicyFromYAML(path string) (*PolicyEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	engine := NewPolicyEngine()

	if cfg.Policies != nil {
		if cfg.Policies.Length != nil && cfg.Policies.Length.Enabled {
			engine.AddRule(rules.NewLengthRule(cfg.Policies.Length.Min, cfg.Policies.Length.Max))
		}

		if cfg.Policies.Entropy != nil && cfg.Policies.Entropy.Enabled {
			engine.AddRule(rules.NewEntropyRule(cfg.Policies.Entropy.MinEntropy, cfg.Policies.Entropy.Blacklist, cfg.Policies.Entropy.BlacklistBoost))
		}

		if cfg.Policies.Sequence != nil && cfg.Policies.Sequence.Enabled {
			engine.AddRule(rules.NewSequenceRule(cfg.Policies.Sequence.MaxSequence))
		}

		if cfg.Policies.Category != nil && cfg.Policies.Category.Enabled {
			categories := []rules.Category{}
			for _, c := range cfg.Policies.Category.Rules {
				if !c.Enabled {
					continue
				}

				pred, ok := rules.PredicateRegistry[c.Predicate]
				if !ok {
					fmt.Printf("predicate não registrado: %s\n", c.Predicate)
					continue
				}

				categories = append(categories, rules.Category{
					Name:      c.Name,
					Min:       c.Min,
					Predicate: pred,
				})
			}
			engine.AddRule(rules.NewCategoryRule(categories))
		}
	}

	if cfg.Hashing != nil {

	}

	return engine, nil
}

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

func (r *PolicyEngineReloadable) Validate(password string) []errors.ValidationError {
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
