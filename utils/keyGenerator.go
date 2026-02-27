package utils

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"runtime"
	"time"
)

type RSAKeys struct {
	E *big.Int
	D *big.Int
	N *big.Int
	P *big.Int
	Q *big.Int

	DP   *big.Int
	DQ   *big.Int
	QInv *big.Int 
}

func generateLargePrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

func GenerateKeysFromPQ(p, q *big.Int) (*RSAKeys, error) {
	if p == nil || q == nil {
		return nil, errors.New("p/q nil")
	}
	if p.Sign() <= 0 || q.Sign() <= 0 {
		return nil, errors.New("p/q must be > 0")
	}
	if p.Cmp(q) == 0 {
		return nil, errors.New("p and q must be different")
	}

	one := big.NewInt(1)

	n := new(big.Int).Mul(p, q)

	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pm1, qm1)

	e := big.NewInt(65537)

	g := new(big.Int)
	g.GCD(nil, nil, e, phi)
	if g.Cmp(one) != 0 {
		return nil, errors.New("gcd(e, phi) != 1; regenerate primes")
	}

	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("no modular inverse for e")
	}

	dp := new(big.Int).Mod(d, pm1)
	dq := new(big.Int).Mod(d, qm1)
	qInv := new(big.Int).ModInverse(q, p)
	if qInv == nil {
		return nil, errors.New("no modular inverse for q mod p")
	}

	return &RSAKeys{
		E: new(big.Int).Set(e),
		D: new(big.Int).Set(d),
		N: new(big.Int).Set(n),
		P: new(big.Int).Set(p),
		Q: new(big.Int).Set(q),

		DP:   dp,
		DQ:   dq,
		QInv: qInv,
	}, nil
}

func GenerateHeavyPQ(bitsPerPrime int) (*big.Int, *big.Int, error) {
	if bitsPerPrime < 512 {
		return nil, nil, errors.New("bitsPerPrime too small")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type res struct {
		v   *big.Int
		err error
	}

	gen := func(out chan<- res) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			v, err := rand.Prime(rand.Reader, bitsPerPrime)
			out <- res{v: v, err: err}
			return
		}
	}

	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)

	_ = runtime.GOMAXPROCS(0)

	pStart := time.Now()
	go gen(ch1)
	go gen(ch2)

	r1 := <-ch1
	r2 := <-ch2
	pqTime := time.Since(pStart)

	if r1.err != nil {
		return nil, nil, r1.err
	}
	if r2.err != nil {
		return nil, nil, r2.err
	}

	p := r1.v
	q := r2.v

	// Rare collision: regenerate q until different
	if p.Cmp(q) == 0 {
		for {
			v, err := rand.Prime(rand.Reader, bitsPerPrime)
			if err != nil {
				return nil, nil, err
			}
			if p.Cmp(v) != 0 {
				q = v
				break
			}
		}
	}

	_ = pqTime
	return p, q, nil
}

func GenerateKeysHeavy(bitsPerPrime int) (*RSAKeys, error) {
	totalStart := time.Now()

	p, q, err := GenerateHeavyPQ(bitsPerPrime)
	if err != nil {
		return nil, err
	}

	one := big.NewInt(1)

	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)

	nStart := time.Now()
	n := new(big.Int).Mul(p, q)
	nTime := time.Since(nStart)

	phiStart := time.Now()
	phi := new(big.Int).Mul(pm1, qm1)
	phiTime := time.Since(phiStart)

	e := big.NewInt(65537)

	gcdStart := time.Now()
	g := new(big.Int)
	g.GCD(nil, nil, e, phi)
	gcdTime := time.Since(gcdStart)
	if g.Cmp(one) != 0 {
		return nil, errors.New("gcd(e, phi) != 1; regenerate primes")
	}

	dStart := time.Now()
	d := new(big.Int).ModInverse(e, phi)
	dTime := time.Since(dStart)
	if d == nil {
		return nil, errors.New("no modular inverse for e")
	}

	crtStart := time.Now()
	dp := new(big.Int).Mod(d, pm1)
	dq := new(big.Int).Mod(d, qm1)
	qInv := new(big.Int).ModInverse(q, p)
	crtTime := time.Since(crtStart)
	if qInv == nil {
		return nil, errors.New("no modular inverse for q mod p")
	}

	totalTime := time.Since(totalStart)

	println("GenerateKeysHeavy:")
	println("  n(ns):", nTime.Nanoseconds())
	println("  phi(ns):", phiTime.Nanoseconds())
	println("  gcd(ns):", gcdTime.Nanoseconds())
	println("  modInverse(ns):", dTime.Nanoseconds())
	println("  crt(ns):", crtTime.Nanoseconds())
	println("  total:", totalTime.Nanoseconds(), "ns")

	return &RSAKeys{
		E: new(big.Int).Set(e),
		D: new(big.Int).Set(d),
		N: new(big.Int).Set(n),
		P: new(big.Int).Set(p),
		Q: new(big.Int).Set(q),

		DP:   dp,
		DQ:   dq,
		QInv: qInv,
	}, nil
}

func DecryptCRT(c *big.Int, k *RSAKeys) (*big.Int, error) {
	if c == nil || k == nil || k.P == nil || k.Q == nil || k.DP == nil || k.DQ == nil || k.QInv == nil {
		return nil, errors.New("invalid key/ciphertext")
	}


	m1 := new(big.Int).Exp(c, k.DP, k.P)

	m2 := new(big.Int).Exp(c, k.DQ, k.Q)

	h := new(big.Int).Sub(m1, m2)
	h.Mod(h, k.P)
	h.Mul(h, k.QInv)
	h.Mod(h, k.P)

	m := new(big.Int).Mul(h, k.Q)
	m.Add(m, m2)
	return m, nil
}