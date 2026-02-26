package utils

import "math/big"

func PowerBig(base, expo, m *big.Int) *big.Int {
	res := big.NewInt(1)
	baseMod := new(big.Int).Mod(new(big.Int).Set(base), m)

	e := new(big.Int).Set(expo)
	zero := big.NewInt(0)
	one := big.NewInt(1)

	for e.Cmp(zero) > 0 {
		if new(big.Int).And(e, one).Cmp(one) == 0 {
			res.Mul(res, baseMod)
			res.Mod(res, m)
		}
		baseMod.Mul(baseMod, baseMod)
		baseMod.Mod(baseMod, m)
		e.Rsh(e, 1)
	}
	return res
}

func modInverse(e, phi *big.Int) *big.Int {
	one := big.NewInt(1)
	d := big.NewInt(2)

	for d.Cmp(phi) < 0 {
		tmp := new(big.Int).Mul(e, d)
		tmp.Mod(tmp, phi)

		if tmp.Cmp(one) == 0 {
			return new(big.Int).Set(d)
		}
		d.Add(d, one)
	}
	return big.NewInt(-1)
}

func GCD(a int, b int) int {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}