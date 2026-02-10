package hashing

import (
	"fmt"
	"sync"
)

// Manager is a thread-safe driver registry and dispatcher for password hashing.
// It is the Go equivalent of Laravel's HashManager.
//
// Register one or more named [Hasher] implementations, nominate a default
// driver, and then call [Manager.Make] / [Manager.Check] / [Manager.NeedsRehash]
// through the Manager for all day-to-day hashing operations.
//
// # Portability note
//
// In Python this maps to a dict[str, Hasher] + a default key managed inside a
// HashManager class.  In Node.js it maps to a Map<string, Hasher> with an
// equivalent class wrapping it.  The strategy pattern is language-agnostic.
//
// # Thread safety
//
// All Manager methods are safe for concurrent use by multiple goroutines.
// A [sync.RWMutex] serialises writes (RegisterDriver, SetDefaultDriver) while
// allowing concurrent reads (Make, Check, etc.).
type Manager struct {
	mu      sync.RWMutex
	drivers map[DriverName]Hasher
	def     DriverName
}

// NewManager creates an empty Manager with the given default driver name.
// Drivers must be registered with [Manager.RegisterDriver] before any
// hashing operation is invoked through the Manager.
//
// Use [NewDefaultManager] for the batteries-included variant that registers
// all three built-in drivers with their recommended defaults.
func NewManager(defaultDriver DriverName) *Manager {
	return &Manager{
		drivers: make(map[DriverName]Hasher),
		def:     defaultDriver,
	}
}

// NewDefaultManager creates a Manager with all three built-in drivers
// pre-registered using their recommended default options.  The default
// driver is [DriverArgon2id].
//
// This is the recommended starting point for most applications.
//
//	m, err := hashing.NewDefaultManager()
//	hash, _ := m.Make("secret")
func NewDefaultManager() (*Manager, error) {
	bcryptH, err := NewBcryptHasher(DefaultBcryptOptions())
	if err != nil {
		return nil, fmt.Errorf("hashing: failed to create default bcrypt hasher: %w", err)
	}
	argon2iH, err := NewArgon2iHasher(DefaultArgon2Options())
	if err != nil {
		return nil, fmt.Errorf("hashing: failed to create default argon2i hasher: %w", err)
	}
	argon2idH, err := NewArgon2idHasher(DefaultArgon2Options())
	if err != nil {
		return nil, fmt.Errorf("hashing: failed to create default argon2id hasher: %w", err)
	}

	m := NewManager(DriverArgon2id)
	_ = m.RegisterDriver(DriverBcrypt, bcryptH)
	_ = m.RegisterDriver(DriverArgon2i, argon2iH)
	_ = m.RegisterDriver(DriverArgon2id, argon2idH)
	return m, nil
}

// RegisterDriver adds or replaces a named hasher in the Manager.
// It is safe to call RegisterDriver while other goroutines are using the Manager.
//
// Custom drivers must implement the [Hasher] interface:
//
//	type MyHasher struct{ ... }
//	func (h *MyHasher) Make(password string) (string, error)     { ... }
//	func (h *MyHasher) Check(password, hash string) (bool, error) { ... }
//	// ... (remaining Hasher methods)
//
//	m.RegisterDriver("my-algo", &MyHasher{})
func (m *Manager) RegisterDriver(name DriverName, h Hasher) error {
	if name == "" {
		return ErrEmptyDriverName
	}
	if h == nil {
		return ErrNilHasher
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drivers[name] = h
	return nil
}

// Driver returns the [Hasher] registered under name, or [ErrDriverNotFound]
// if no such driver has been registered.
func (m *Manager) Driver(name DriverName) (Hasher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.drivers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrDriverNotFound, name)
	}
	return h, nil
}

// SetDefaultDriver changes the driver used by [Manager.Make], [Manager.Check],
// and [Manager.NeedsRehash].  The named driver must already be registered.
func (m *Manager) SetDefaultDriver(name DriverName) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.drivers[name]; !ok {
		return fmt.Errorf("%w: %q is not registered; call RegisterDriver first",
			ErrDriverNotFound, name)
	}
	m.def = name
	return nil
}

// DefaultDriver returns the name of the currently configured default driver.
func (m *Manager) DefaultDriver() DriverName {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.def
}

// HasDriver reports whether a driver with the given name is registered.
func (m *Manager) HasDriver(name DriverName) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.drivers[name]
	return ok
}

// Make hashes password using the default driver.
func (m *Manager) Make(password string) (string, error) {
	h, err := m.resolveDefault()
	if err != nil {
		return "", err
	}
	return h.Make(password)
}

// Check verifies password against hash using the default driver.
//
// To verify a hash that was produced by a specific (non-default) driver, use
// [Manager.Driver] first:
//
//	ok, err := m.Driver(hashing.DriverBcrypt).Check(password, hash)
func (m *Manager) Check(password, hash string) (bool, error) {
	h, err := m.resolveDefault()
	if err != nil {
		return false, err
	}
	return h.Check(password, hash)
}

// CheckWithDetect verifies password against hash by automatically detecting
// which driver produced the hash.  This is useful when hashes from multiple
// drivers coexist (e.g., during a bcrypt-to-Argon2id migration).
//
// Returns [ErrDriverNotFound] if the detected driver is not registered.
// Returns [ErrInvalidHash] if the hash format is unrecognised.
func (m *Manager) CheckWithDetect(password, hash string) (bool, error) {
	h, err := m.resolveByHash(hash)
	if err != nil {
		return false, err
	}
	return h.Check(password, hash)
}

// NeedsRehash reports whether hash should be re-hashed.
//
// It returns true when:
//  1. The hash was produced by a different driver than the current default, OR
//  2. The hash was produced by the current default driver but with weaker
//     parameters (e.g., a lower bcrypt cost).
//
// On the next successful login, callers should call [Manager.Make] and persist
// the new hash when this returns true.
func (m *Manager) NeedsRehash(hash string) (bool, error) {
	detected, ok := DetectDriver(hash)
	if !ok {
		return false, ErrInvalidHash
	}

	m.mu.RLock()
	def := m.def
	m.mu.RUnlock()

	// Different driver → always needs rehash to match the current default.
	if detected != def {
		return true, nil
	}

	// Same driver — delegate to the hasher to compare parameters.
	h, err := m.Driver(detected)
	if err != nil {
		return false, err
	}
	return h.NeedsRehash(hash)
}

// Info extracts metadata from hash using the default driver.
//
// To inspect a hash produced by a specific driver, use [Manager.Driver] first.
func (m *Manager) Info(hash string) (HashInfo, error) {
	h, err := m.resolveDefault()
	if err != nil {
		return HashInfo{}, err
	}
	return h.Info(hash)
}

// InfoWithDetect extracts metadata from hash by automatically detecting
// which driver produced it.
func (m *Manager) InfoWithDetect(hash string) (HashInfo, error) {
	h, err := m.resolveByHash(hash)
	if err != nil {
		return HashInfo{}, err
	}
	return h.Info(hash)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

func (m *Manager) resolveDefault() (Hasher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.drivers[m.def]
	if !ok {
		return nil, fmt.Errorf("%w: default driver %q has not been registered",
			ErrDriverNotFound, m.def)
	}
	return h, nil
}

func (m *Manager) resolveByHash(hash string) (Hasher, error) {
	name, ok := DetectDriver(hash)
	if !ok {
		return nil, ErrInvalidHash
	}
	return m.Driver(name)
}
