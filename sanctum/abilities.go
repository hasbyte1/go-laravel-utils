package sanctum

// Can reports whether abilities contains the given ability.
// The wildcard ability ("*") grants all abilities.
func Can(abilities []string, ability string) bool {
	if HasWildcard(abilities) {
		return true
	}
	for _, a := range abilities {
		if a == ability {
			return true
		}
	}
	return false
}

// CanAll reports whether abilities contains every ability in required (AND logic).
// Returns true for an empty required list.
func CanAll(abilities []string, required []string) bool {
	for _, r := range required {
		if !Can(abilities, r) {
			return false
		}
	}
	return true
}

// CanAny reports whether abilities contains at least one ability from required (OR logic).
// Returns false for an empty required list.
func CanAny(abilities []string, required []string) bool {
	for _, r := range required {
		if Can(abilities, r) {
			return true
		}
	}
	return false
}

// HasWildcard reports whether abilities contains the wildcard entry ("*").
func HasWildcard(abilities []string) bool {
	for _, a := range abilities {
		if a == "*" {
			return true
		}
	}
	return false
}
