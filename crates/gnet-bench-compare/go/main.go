// Cross-language reference timings: Go 1.24+ stdlib + golang.org/x/crypto
// running the same per-op categories the Rust perf_gate bench measures,
// printed in the same ns/op format so the two numbers are directly
// side-by-side.
//
// Each category uses best-of-10 sampling (matching the Rust gate's
// `measure_best`), so a noisy CI VM / powersave-throttled host doesn't
// dominate the comparison. Both Go and Rust pick their own min on the
// same hardware; the ratio between the two is what's meaningful.
//
// Run:
//
//	cd crates/gnet-bench-compare/go
//	go run ./...
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	xsha3 "golang.org/x/crypto/sha3"
)

const (
	itersX25519 = 1000
	itersAEAD   = 1000
	itersMLKEM  = 100
	itersHEX    = 200000
	itersBLAKE  = 50000
	itersSHAKE  = 50000
	bestOf      = 10
)

// measure times f over iters iterations (after iters/4 warm-up) and returns
// the average ns/op of one sample.
func measure(iters int, f func()) float64 {
	for i := 0; i < iters/4+1; i++ {
		f()
	}
	start := time.Now()
	for i := 0; i < iters; i++ {
		f()
	}
	elapsed := time.Since(start)
	return float64(elapsed.Nanoseconds()) / float64(iters)
}

// measureBest returns the minimum of bestOf samples — the standard
// best-of-N microbench protocol for frequency-scaling / noisy hardware.
func measureBest(iters int, f func()) float64 {
	best := -1.0
	for i := 0; i < bestOf; i++ {
		sample := measure(iters, f)
		if best < 0 || sample < best {
			best = sample
		}
	}
	return best
}

func benchX25519() float64 {
	curve := ecdh.X25519()
	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pk := sk.PublicKey()
	return measureBest(itersX25519, func() {
		_, err := sk.ECDH(pk)
		if err != nil {
			panic(err)
		}
	})
}

func benchAEADSeal() float64 {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	aad := make([]byte, 16)
	pt := make([]byte, 1400)
	ct := make([]byte, 0, 1400+aead.Overhead())
	return measureBest(itersAEAD, func() {
		ct = ct[:0]
		ct = aead.Seal(ct, nonce, pt, aad)
	})
}

func benchAEADOpen() float64 {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	aad := make([]byte, 16)
	pt := make([]byte, 1400)
	ct := aead.Seal(nil, nonce, pt, aad)
	out := make([]byte, 0, 1400)
	return measureBest(itersAEAD, func() {
		out = out[:0]
		_, err := aead.Open(out, nonce, ct, aad)
		if err != nil {
			panic(err)
		}
	})
}

func benchMLKEMKeygen() float64 {
	return measureBest(itersMLKEM, func() {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			panic(err)
		}
		_ = dk.EncapsulationKey()
	})
}

func benchMLKEMEncaps() float64 {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	ek := dk.EncapsulationKey()
	return measureBest(itersMLKEM, func() {
		_, _ = ek.Encapsulate()
	})
}

func benchMLKEMDecaps() float64 {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	ek := dk.EncapsulationKey()
	_, ct := ek.Encapsulate()
	return measureBest(itersMLKEM, func() {
		_, err := dk.Decapsulate(ct)
		if err != nil {
			panic(err)
		}
	})
}

func benchHexEncode() float64 {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return measureBest(itersHEX, func() {
		_ = hex.EncodeToString(buf)
	})
}

func benchHexDecode() float64 {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	s := hex.EncodeToString(buf)
	return measureBest(itersHEX, func() {
		_, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
	})
}

func benchBLAKE2s() float64 {
	input := make([]byte, 64)
	if _, err := rand.Read(input); err != nil {
		panic(err)
	}
	return measureBest(itersBLAKE, func() {
		h, err := blake2s.New256(nil)
		if err != nil {
			panic(err)
		}
		_, _ = h.Write(input)
		_ = h.Sum(nil)
	})
}

func benchSHAKE128() float64 {
	input := make([]byte, 34)
	if _, err := rand.Read(input); err != nil {
		panic(err)
	}
	out := make([]byte, 168)
	return measureBest(itersSHAKE, func() {
		h := xsha3.NewShake128()
		_, _ = h.Write(input)
		_, _ = h.Read(out)
	})
}

func main() {
	fmt.Println("Go stdlib + golang.org/x/crypto — cross-language reference timings")
	fmt.Println("Same per-op categories as the Rust perf_gate, best-of-10 samples.")
	fmt.Println()
	fmt.Printf("  %-32s  %12s\n", "category", "go ns/op")
	fmt.Println("  ----------------------------------------------")

	type entry struct {
		name string
		ns   float64
	}
	rows := []entry{
		{"X25519 ECDH", benchX25519()},
		{"AEAD seal 1400B", benchAEADSeal()},
		{"AEAD open 1400B", benchAEADOpen()},
		{"ML-KEM-768 keygen", benchMLKEMKeygen()},
		{"ML-KEM-768 encaps", benchMLKEMEncaps()},
		{"ML-KEM-768 decaps", benchMLKEMDecaps()},
		{"Hex encode 32B", benchHexEncode()},
		{"Hex decode 32B", benchHexDecode()},
		{"BLAKE2s-256 64B", benchBLAKE2s()},
		{"SHAKE128 34→168B", benchSHAKE128()},
	}
	for _, r := range rows {
		fmt.Printf("  %-32s  %12.1f\n", r.name, r.ns)
	}
}
