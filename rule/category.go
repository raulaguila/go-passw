package rule

import (
	"fmt"
	"strings"

	"github.com/raulaguila/passguard/errors"
)

// Category defines a character category requirement.
type Category struct {
	// Name is the identifier for this category (e.g., "uppercase").
	Name string

	// Min is the minimum required count of characters in this category.
	Min int

	// Predicate tests if a rune belongs to this category.
	Predicate Predicate
}

// CategoryRule validates that passwords contain required character categories.
type CategoryRule struct {
	categories []Category
}

// NewCategoryRule creates a new category validation rule.
func NewCategoryRule(categories []Category) *CategoryRule {
	return &CategoryRule{categories: categories}
}

// Name returns the rule identifier.
func (r *CategoryRule) Name() string {
	return "category"
}

// Validate checks if the password meets all category requirements.
func (r *CategoryRule) Validate(password string) *errors.ValidationError {
	found := make(map[string]int)

	// Initialize counts
	for _, c := range r.categories {
		found[c.Name] = 0
	}

	// Count characters in each category
	for _, ch := range password {
		for _, c := range r.categories {
			if c.Predicate(ch) {
				found[c.Name]++
			}
		}
	}

	// Check requirements
	missing := make(map[string]map[string]int)
	for _, c := range r.categories {
		if found[c.Name] < c.Min {
			missing[c.Name] = map[string]int{
				"required": c.Min,
				"found":    found[c.Name],
			}
		}
	}

	if len(missing) > 0 {
		parts := make([]string, 0, len(missing))
		for name, v := range missing {
			parts = append(parts, fmt.Sprintf("%s (min %d, found %d)", name, v["required"], v["found"]))
		}
		return errors.New(
			"CATEGORY_MIN_NOT_MET",
			"Category requirements not met: "+strings.Join(parts, ", "),
		).WithDetails(map[string]any{
			"categories": missing,
		})
	}

	return nil
}
