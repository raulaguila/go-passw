package validator

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/raulaguila/go-passw/validator/rule"
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
			engine.AddRule(rule.NewLengthRule(cfg.Policies.Length.Min, cfg.Policies.Length.Max))
		}

		if cfg.Policies.Entropy != nil && cfg.Policies.Entropy.Enabled {
			engine.AddRule(rule.NewEntropyRule(cfg.Policies.Entropy.MinEntropy, cfg.Policies.Entropy.Blacklist, cfg.Policies.Entropy.BlacklistBoost))
		}

		if cfg.Policies.Sequence != nil && cfg.Policies.Sequence.Enabled {
			engine.AddRule(rule.NewSequenceRule(cfg.Policies.Sequence.MaxSequence))
		}

		if cfg.Policies.Category != nil && cfg.Policies.Category.Enabled {
			categories := []rule.Category{}
			for _, c := range cfg.Policies.Category.Rules {
				if !c.Enabled {
					continue
				}

				pred, ok := rule.PredicateRegistry[c.Predicate]
				if !ok {
					fmt.Printf("predicate not found: %s\n", c.Predicate)
					continue
				}

				categories = append(categories, rule.Category{
					Name:      c.Name,
					Min:       c.Min,
					Predicate: pred,
				})
			}
			engine.AddRule(rule.NewCategoryRule(categories))
		}
	}

	if cfg.Hashing != nil {

	}

	return engine, nil
}
