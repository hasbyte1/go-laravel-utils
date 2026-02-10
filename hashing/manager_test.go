package hashing_test

import (
	"errors"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hasbyte1/go-laravel-utils/hashing"
)

// newTestManager returns a Manager with all three drivers registered using
// fast (test-safe) options.  It accepts testing.TB so it can be called from
// both *testing.T (unit tests) and *testing.B (benchmarks).
func newTestManager(tb testing.TB) *hashing.Manager {
	tb.Helper()
	m := hashing.NewManager(hashing.DriverArgon2id)
	bcH, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost})
	a2iH, _ := hashing.NewArgon2iHasher(fastArgon2Opts())
	a2idH, _ := hashing.NewArgon2idHasher(fastArgon2Opts())
	_ = m.RegisterDriver(hashing.DriverBcrypt, bcH)
	_ = m.RegisterDriver(hashing.DriverArgon2i, a2iH)
	_ = m.RegisterDriver(hashing.DriverArgon2id, a2idH)
	return m
}

// ──────────────────────────────────────────────────────────────────────────────
// NewDefaultManager
// ──────────────────────────────────────────────────────────────────────────────

func TestNewDefaultManager_Succeeds(t *testing.T) {
	m, err := hashing.NewDefaultManager()
	if err != nil {
		t.Fatalf("NewDefaultManager: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewDefaultManager_DefaultDriver(t *testing.T) {
	m, _ := hashing.NewDefaultManager()
	if m.DefaultDriver() != hashing.DriverArgon2id {
		t.Errorf("default driver = %q, want argon2id", m.DefaultDriver())
	}
}

func TestNewDefaultManager_AllDriversRegistered(t *testing.T) {
	m, _ := hashing.NewDefaultManager()
	for _, d := range []hashing.DriverName{hashing.DriverBcrypt, hashing.DriverArgon2i, hashing.DriverArgon2id} {
		if !m.HasDriver(d) {
			t.Errorf("driver %q not registered", d)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RegisterDriver
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_RegisterDriver_EmptyName(t *testing.T) {
	m := hashing.NewManager(hashing.DriverArgon2id)
	h, _ := hashing.NewArgon2idHasher(fastArgon2Opts())
	err := m.RegisterDriver("", h)
	if !errors.Is(err, hashing.ErrEmptyDriverName) {
		t.Errorf("expected ErrEmptyDriverName, got %v", err)
	}
}

func TestManager_RegisterDriver_NilHasher(t *testing.T) {
	m := hashing.NewManager(hashing.DriverArgon2id)
	err := m.RegisterDriver("custom", nil)
	if !errors.Is(err, hashing.ErrNilHasher) {
		t.Errorf("expected ErrNilHasher, got %v", err)
	}
}

func TestManager_RegisterDriver_ReplaceExisting(t *testing.T) {
	m := newTestManager(t)
	// Register a new bcrypt hasher with a different cost — it should replace the old one.
	newH, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost + 1})
	_ = m.RegisterDriver(hashing.DriverBcrypt, newH)
	got, _ := m.Driver(hashing.DriverBcrypt)
	if got.(*hashing.BcryptHasher).Cost() != bcrypt.MinCost+1 {
		t.Error("driver should be replaced after re-registration")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SetDefaultDriver
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_SetDefaultDriver_Valid(t *testing.T) {
	m := newTestManager(t)
	if err := m.SetDefaultDriver(hashing.DriverBcrypt); err != nil {
		t.Fatalf("SetDefaultDriver: %v", err)
	}
	if m.DefaultDriver() != hashing.DriverBcrypt {
		t.Errorf("got %q, want bcrypt", m.DefaultDriver())
	}
}

func TestManager_SetDefaultDriver_Unregistered(t *testing.T) {
	m := hashing.NewManager(hashing.DriverArgon2id)
	err := m.SetDefaultDriver("not-registered")
	if !errors.Is(err, hashing.ErrDriverNotFound) {
		t.Errorf("expected ErrDriverNotFound, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Make / Check / NeedsRehash / Info
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_Make_UsesDefaultDriver(t *testing.T) {
	m := newTestManager(t)
	hash, err := m.Make("password")
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	driver, ok := hashing.DetectDriver(hash)
	if !ok || driver != hashing.DriverArgon2id {
		t.Errorf("expected argon2id hash, detected %q", driver)
	}
}

func TestManager_Check_Correct(t *testing.T) {
	m := newTestManager(t)
	hash, _ := m.Make("secret")
	ok, err := m.Check("secret", hash)
	if err != nil || !ok {
		t.Fatalf("Check: ok=%v err=%v", ok, err)
	}
}

func TestManager_Check_Wrong(t *testing.T) {
	m := newTestManager(t)
	hash, _ := m.Make("secret")
	ok, err := m.Check("wrong", hash)
	if err != nil || ok {
		t.Fatalf("Check wrong: ok=%v err=%v", ok, err)
	}
}

func TestManager_Check_NoDefaultDriver(t *testing.T) {
	m := hashing.NewManager(hashing.DriverArgon2id) // no drivers registered
	_, err := m.Check("pw", "hash")
	if !errors.Is(err, hashing.ErrDriverNotFound) {
		t.Errorf("expected ErrDriverNotFound, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CheckWithDetect
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_CheckWithDetect_Bcrypt(t *testing.T) {
	m := newTestManager(t)
	// Produce a bcrypt hash directly.
	bcH, _ := m.Driver(hashing.DriverBcrypt)
	hash, _ := bcH.Make("pw")
	// Manager default is argon2id, but CheckWithDetect should auto-detect bcrypt.
	ok, err := m.CheckWithDetect("pw", hash)
	if err != nil || !ok {
		t.Fatalf("CheckWithDetect bcrypt: ok=%v err=%v", ok, err)
	}
}

func TestManager_CheckWithDetect_Unknown(t *testing.T) {
	m := newTestManager(t)
	_, err := m.CheckWithDetect("pw", "not-a-hash")
	if !errors.Is(err, hashing.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// NeedsRehash
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_NeedsRehash_SameDriver(t *testing.T) {
	m := newTestManager(t)
	hash, _ := m.Make("pw")
	needs, err := m.NeedsRehash(hash)
	if err != nil || needs {
		t.Errorf("NeedsRehash same config: needs=%v err=%v", needs, err)
	}
}

func TestManager_NeedsRehash_DifferentDriver(t *testing.T) {
	m := newTestManager(t)
	// Hash with bcrypt, check against argon2id default.
	bcH, _ := m.Driver(hashing.DriverBcrypt)
	hash, _ := bcH.Make("pw")
	needs, err := m.NeedsRehash(hash)
	if err != nil || !needs {
		t.Errorf("expected NeedsRehash=true for bcrypt hash with argon2id default: needs=%v err=%v", needs, err)
	}
}

func TestManager_NeedsRehash_InvalidHash(t *testing.T) {
	m := newTestManager(t)
	_, err := m.NeedsRehash("garbage")
	if !errors.Is(err, hashing.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Info / InfoWithDetect
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_InfoWithDetect_Bcrypt(t *testing.T) {
	m := newTestManager(t)
	bcH, _ := m.Driver(hashing.DriverBcrypt)
	hash, _ := bcH.Make("pw")
	info, err := m.InfoWithDetect(hash)
	if err != nil {
		t.Fatalf("InfoWithDetect: %v", err)
	}
	if info.Driver != hashing.DriverBcrypt {
		t.Errorf("driver = %q, want bcrypt", info.Driver)
	}
}

func TestManager_InfoWithDetect_Unknown(t *testing.T) {
	m := newTestManager(t)
	_, err := m.InfoWithDetect("garbage")
	if !errors.Is(err, hashing.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Driver migration workflow
// ──────────────────────────────────────────────────────────────────────────────

// TestManager_Migration simulates a bcrypt-to-argon2id migration:
//   - Old hashes (bcrypt) are still verifiable.
//   - On next login the application detects NeedsRehash=true and re-hashes.
//   - After re-hashing, NeedsRehash=false.
func TestManager_Migration_BcryptToArgon2id(t *testing.T) {
	m := newTestManager(t)

	// Step 1: legacy hash produced by bcrypt.
	bcH, _ := m.Driver(hashing.DriverBcrypt)
	legacyHash, _ := bcH.Make("user-password")

	// Step 2: verify the legacy hash still works (via CheckWithDetect).
	ok, err := m.CheckWithDetect("user-password", legacyHash)
	if err != nil || !ok {
		t.Fatalf("legacy bcrypt check failed: ok=%v err=%v", ok, err)
	}

	// Step 3: NeedsRehash reports true (different driver than default argon2id).
	needs, err := m.NeedsRehash(legacyHash)
	if err != nil || !needs {
		t.Fatalf("expected NeedsRehash=true for legacy bcrypt: needs=%v err=%v", needs, err)
	}

	// Step 4: re-hash with current default (argon2id).
	newHash, err := m.Make("user-password")
	if err != nil {
		t.Fatalf("re-hash: %v", err)
	}

	// Step 5: new hash no longer needs rehashing.
	needs, err = m.NeedsRehash(newHash)
	if err != nil || needs {
		t.Fatalf("new argon2id hash should not need rehash: needs=%v err=%v", needs, err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Concurrency
// ──────────────────────────────────────────────────────────────────────────────

func TestManager_ConcurrentMakeCheck(t *testing.T) {
	m := newTestManager(t)
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			hash, err := m.Make("concurrent-pw")
			if err != nil {
				errs <- err
				return
			}
			ok, err := m.CheckWithDetect("concurrent-pw", hash)
			if err != nil {
				errs <- err
				return
			}
			if !ok {
				errs <- errors.New("Check returned false for correct password")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestManager_ConcurrentRegisterAndRead(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer goroutine: re-registers the bcrypt driver.
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			h, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost})
			_ = m.RegisterDriver(hashing.DriverBcrypt, h)
		}
	}()

	// Reader goroutine: reads from the manager.
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, _ = m.Driver(hashing.DriverBcrypt)
		}
	}()

	wg.Wait()
}
