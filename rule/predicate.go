package rule

import (
	"sync"
	"unicode"
)

// Predicate is a function that tests a rune for a specific character class.
type Predicate func(rune) bool

var (
	predicateMu sync.RWMutex
	predicates  = map[string]Predicate{
		"upper":   unicode.IsUpper,
		"lower":   unicode.IsLower,
		"number":  unicode.IsDigit,
		"special": func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSymbol(r) },
		"ascii":   func(r rune) bool { return r <= unicode.MaxASCII },
		"emoji":   func(r rune) bool { return r >= 0x1F600 && r <= 0x1F64F },
	}
)

// GetPredicate returns the predicate function for the given name.
// Returns nil if the predicate is not registered.
func GetPredicate(name string) Predicate {
	predicateMu.RLock()
	defer predicateMu.RUnlock()
	return predicates[name]
}

// RegisterPredicate registers a custom predicate for use in category rules.
// This allows extending the library with custom character classes.
// It is safe for concurrent use.
func RegisterPredicate(name string, fn Predicate) {
	predicateMu.Lock()
	defer predicateMu.Unlock()
	predicates[name] = fn
}

// ListPredicates returns the names of all registered predicates.
func ListPredicates() []string {
	predicateMu.RLock()
	defer predicateMu.RUnlock()
	names := make([]string, 0, len(predicates))
	for name := range predicates {
		names = append(names, name)
	}
	return names
}
