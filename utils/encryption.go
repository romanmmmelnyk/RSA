package utils

import "math/big"

func Encrypt(m, e, n *big.Int) *big.Int {
	return new(big.Int).Exp(m, e, n)
}

func Decrypt(c, d, n *big.Int) *big.Int {
	return new(big.Int).Exp(c, d, n)
}
