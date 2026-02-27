package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/romanmmmelnyk/RSA.git/utils"
)

func main() {
	keygenStart := time.Now()
	keys, err := utils.GenerateKeysHeavy(512)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Keygen total: %s\n", time.Since(keygenStart))
	fmt.Printf("Key size: %d bits\n\n", keys.N.BitLen())

	in := bufio.NewReader(os.Stdin)
	fmt.Print("Message: ")
	msg, _ := in.ReadString('\n')
	msg = strings.TrimRight(msg, "\r\n")

	m := new(big.Int).SetBytes([]byte(msg))

	if m.Cmp(keys.N) >= 0 {
		log.Fatal("message too long for this N (m must be < N). Use shorter message or bigger primes.")
	}

	c := new(big.Int).Exp(m, keys.E, keys.N)

	m2, err := utils.DecryptCRT(c, keys)
	if err != nil {
		log.Fatal(err)
	}

	plain := string(m2.Bytes())

	fmt.Println("Ciphertext (hex):", hex.EncodeToString(c.Bytes()))
	fmt.Println("Decrypted:", plain)
}
