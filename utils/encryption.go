package utils

import "math/big"

func Encrypt(m, e, n *big.Int) *big.Int {
	return PowerBig(m, e, n)
}

func Decrypt(c, d, n *big.Int) *big.Int {
	return PowerBig(c, d, n)
}