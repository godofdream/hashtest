package main

import (
	"fmt"

	"github.com/rbastic/go-zaphod64"
)

func main() {
	// These seeds and test string taken from demerphq's zaphod64 C code
	// Output expected is 0x2ed781397cec97af
	seed := []uint64{0x1234567890123456, 0x9876543210abcdef, 0xabcdef0123456789}
	key := []byte("The shaved yak drank from the bitter well")

	var keyLen uint64 = uint64(len(key))

	fmt.Printf("%016x\n", zaphod64.Hash(seed, key, keyLen))
}
