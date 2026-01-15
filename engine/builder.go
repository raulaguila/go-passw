package engine

import (
	"log/slog"

	"github.com/raulaguila/passguard/config"
	"github.com/raulaguila/passguard/rule"
)

// BuildFromConfig creates an Engine with rules from configuration.
func BuildFromConfig(cfg *config.Config) (*Engine, error) {
	engine := New()

	if cfg.Policies == nil {
		return engine, nil
	}

	policies := cfg.Policies

	// Length rule
	if policies.Length != nil && policies.Length.Enabled {
		engine.AddRule(rule.NewLengthRule(policies.Length.Min, policies.Length.Max))
	}

	// Entropy rule
	if policies.Entropy != nil && policies.Entropy.Enabled {
		engine.AddRule(rule.NewEntropyRule(
			policies.Entropy.MinEntropy,
			policies.Entropy.Blacklist,
			policies.Entropy.BlacklistBoost,
		))
	}

	// Sequence rule
	if policies.Sequence != nil && policies.Sequence.Enabled {
		engine.AddRule(rule.NewSequenceRuleWithKeyboard(
			policies.Sequence.MaxSequence,
			policies.Sequence.IncludeKeyboard,
		))
	}

	// Category rule
	if policies.Category != nil && policies.Category.Enabled {
		categories := make([]rule.Category, 0)

		for _, c := range policies.Category.Rules {
			if !c.Enabled {
				continue
			}

			pred := rule.GetPredicate(c.Predicate)
			if pred == nil {
				slog.Warn("predicate not found, skipping category",
					"predicate", c.Predicate,
					"category", c.Name,
				)
				continue
			}

			categories = append(categories, rule.Category{
				Name:      c.Name,
				Min:       c.Min,
				Predicate: pred,
			})
		}

		if len(categories) > 0 {
			engine.AddRule(rule.NewCategoryRule(categories))
		}
	}

	return engine, nil
}
