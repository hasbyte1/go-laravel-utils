package passport

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestJwkToRSA_ValidExponent(t *testing.T) {
	// e = 65537 (standard RSA public exponent)
	n := new(big.Int)
	n.SetString("00c4b2a3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4", 16)
	e := big.NewInt(65537)
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(e.Bytes())

	pub, err := jwkToRSA(nB64, eB64)
	if err != nil {
		t.Fatalf("jwkToRSA with e=65537: %v", err)
	}
	if pub.E != 65537 {
		t.Errorf("E = %d, want 65537", pub.E)
	}
}

func TestJwkToRSA_RejectsExponentOfOne(t *testing.T) {
	n := big.NewInt(0xdeadbeef)
	e := big.NewInt(1)
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(e.Bytes())

	_, err := jwkToRSA(nB64, eB64)
	if err == nil {
		t.Fatal("jwkToRSA should reject exponent == 1")
	}
}

func TestJwkToRSA_RejectsExponentOfZero(t *testing.T) {
	n := big.NewInt(0xdeadbeef)
	e := big.NewInt(0)
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	// big.Int(0).Bytes() is empty; encode that
	eB64 := base64.RawURLEncoding.EncodeToString(e.Bytes())

	_, err := jwkToRSA(nB64, eB64)
	if err == nil {
		t.Fatal("jwkToRSA should reject exponent == 0")
	}
}

func TestJwkToRSA_RejectsExponentAboveMaxInt32(t *testing.T) {
	n := big.NewInt(0xdeadbeef)
	// Exponent just above 2^31-1
	e := new(big.Int).SetInt64(1<<31)
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(e.Bytes())

	_, err := jwkToRSA(nB64, eB64)
	if err == nil {
		t.Fatal("jwkToRSA should reject exponent >= 2^31")
	}
}
