package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type RSAKeys struct {
	E *big.Int
	D *big.Int
	N *big.Int
	P *big.Int
	Q *big.Int
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

	n := new(big.Int).Mul(p, q)

	one := big.NewInt(1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

	e := big.NewInt(2)
	g := new(big.Int)
	for {
		g.GCD(nil, nil, e, phi)
		if g.Cmp(one) == 0 {
			break
		}
		e.Add(e, one)
		if e.Cmp(phi) >= 0 {
			return nil, errors.New("failed to find e")
		}
	}

	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("no modular inverse for e")
	}

	return &RSAKeys{
		E: new(big.Int).Set(e),
		D: new(big.Int).Set(d),
		N: new(big.Int).Set(n),
		P: new(big.Int).Set(p),
		Q: new(big.Int).Set(q),
	}, nil
}

func GenerateHeavyPQ(bitsPerPrime int) (*big.Int, *big.Int, error) {
	if bitsPerPrime < 512 {
		return nil, nil, errors.New("bitsPerPrime too small")
	}

	p, err := rand.Prime(rand.Reader, bitsPerPrime)
	if err != nil {
		return nil, nil, err
	}

	for {
		q, err := rand.Prime(rand.Reader, bitsPerPrime)
		if err != nil {
			return nil, nil, err
		}
		if p.Cmp(q) != 0 {
			return p, q, nil
		}
	}
}

func GenerateKeysHeavy(bitsPerPrime int) (*RSAKeys, error) {
	p, q, err := GenerateHeavyPQ(bitsPerPrime)
	if err != nil {
		return nil, err
	}

	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

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

	return &RSAKeys{
		E: new(big.Int).Set(e),
		D: new(big.Int).Set(d),
		N: new(big.Int).Set(n),
		P: new(big.Int).Set(p),
		Q: new(big.Int).Set(q),
	}, nil
}