package rule

import (
	"fmt"
	"strings"
	"unicode"

	errPassw "github.com/raulaguila/go-passw/validator/errors"
)

type Predicate func(rune) bool

var PredicateRegistry = map[string]Predicate{
	"upper":   unicode.IsUpper,
	"lower":   unicode.IsLower,
	"number":  unicode.IsDigit,
	"special": func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSymbol(r) },
	"ascii":   func(r rune) bool { return r <= unicode.MaxASCII },
	"emoji":   func(r rune) bool { return r >= 0x1F600 && r <= 0x1F64F },
}

type Category struct {
	Name      string
	Min       int
	Predicate Predicate
}

type CategoryRule struct {
	Categories []Category
}

func NewCategoryRule(c []Category) *CategoryRule {
	return &CategoryRule{Categories: c}
}

func (r *CategoryRule) Validate(p string) *errPassw.ValidationError {
	found := map[string]int{}

	for _, c := range r.Categories {
		found[c.Name] = 0
	}

	for _, ch := range p {
		for _, c := range r.Categories {
			if c.Predicate(ch) {
				found[c.Name]++
			}
		}
	}

	missing := map[string]map[string]int{}
	for _, c := range r.Categories {
		if found[c.Name] < c.Min {
			missing[c.Name] = map[string]int{
				"required": c.Min,
				"found":    found[c.Name],
			}
		}
	}

	if len(missing) > 0 {
		parts := []string{}
		for name, v := range missing {
			parts = append(parts, fmt.Sprintf("%s (min %d, found %d)", name, v["required"], v["found"]))
		}
		return errPassw.New("CATEGORY_MIN_NOT_MET", "Category requirements not met: "+strings.Join(parts, ", ")).WithDetails(map[string]any{
			"categories": missing,
		})
	}

	return nil
}
