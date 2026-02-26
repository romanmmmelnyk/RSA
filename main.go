package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/romanmmmelnyk/RSA.git/utils"
)

func main() {
	keys, err := utils.GenerateKeysHeavy(512)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("PUBLIC KEY (E, N):")
	fmt.Println("E =", keys.E.String())
	fmt.Println("N =", keys.N.String())
	fmt.Println()
	fmt.Println("PRIVATE KEY (D):")
	fmt.Println("D =", keys.D.String())
	fmt.Println()

	in := bufio.NewReader(os.Stdin)
	fmt.Print("Message: ")
	msg, _ := in.ReadString('\n')
	msg = strings.TrimRight(msg, "\r\n")

	m := new(big.Int).SetBytes([]byte(msg))

	if m.Cmp(keys.N) >= 0 {
		log.Fatal("message too long for this N (m must be < N). Use shorter message or bigger primes.")
	}

	c := utils.PowerBig(m, keys.E, keys.N)

	m2 := utils.PowerBig(c, keys.D, keys.N)

	plain := string(m2.Bytes())

	fmt.Println("Ciphertext (hex):", hex.EncodeToString(c.Bytes()))
	fmt.Println("Decrypted:", plain)
}