package zaphod64

//import "fmt"

import "encoding/binary"

func scramble64(v uint64, prime uint64) uint64 {
	v ^= (v >> 13)
	v ^= (v << 35)
	v ^= (v >> 30)
	v *= prime
	v ^= (v >> 19)
	v ^= (v << 15)
	v ^= (v >> 46)
	return v
}

func rotl64(x uint64, r uint8) uint64 {
	return (x << r) | (x >> (64 - r))
}

func rotr64(x uint64, r uint64) uint64 {
	return (((x) >> (r)) | ((x) << (64 - r)))
}

func mix(v0, v1, v2 uint64) (uint64, uint64, uint64) {
	v0 = rotl64(v0, 57) + v1
	v1 = rotl64(v1, 43) ^ v2
	v2 = rotl64(v2, 24) ^ v0
	v0 = rotr64(v0, 5) + v2
	v2 = rotr64(v2, 8) - v1
	v1 = rotr64(v1, 63) ^ v0
	v0 = rotl64(v0, 17) ^ v2
	v2 = rotl64(v2, 55) - v0
	return v0, v1, v2
}

func finalize(v0, v1, v2 uint64) (uint64, uint64, uint64) {
	//fmt.Printf("v0=%016x v1=%016x v2=%016x - ZAPHOD64 ENTER FINALIZE\n", v0, v1, v2)

	v0 = rotr64(v0, 61) - v2
	v2 ^= v1
	v2 = rotl64(v2, 8) - v0
	v1 -= v2
	v0 = rotr64(v0, 23) - v2
	v1 = rotl64(v1, 11)
	v0 -= v1
	v1 = rotl64(v1, 11)
	v0 -= v1
	v0 = rotr64(v0, 32)
	v2 = rotr64(v2, 7) - v0
	v1 = rotr64(v1, 61) + v0
	v2 = rotl64(v2, 9)
	v1 -= v2
	v1 = rotr64(v1, 19)

	//fmt.Printf("v0=%016x v1=%016x v2=%016x - ZAPHOD64 MID FINALIZE\n", v0, v1, v2)

	v2 ^= v1
	v1 -= v0
	v2 = rotr64(v2, 40)
	v1 ^= v2
	v1 = rotl64(v1, 47) - v2
	v0 = rotr64(v0, 49) ^ v1
	v0 = rotl64(v0, 57)
	v1 ^= v0
	v1 = rotl64(v1, 25)
	v2 -= v1
	v2 = rotr64(v2, 37)
	v1 = ^v1
	return v0, v1, v2
}

type State [3]uint64

func SeedState(seed []uint64) State {
	var state State
	state[0] = seed[0] ^ 0x43f6a8885a308d31
	state[1] = seed[1] ^ 0x3198a2e03707344a
	state[2] = seed[2] ^ 0x4093822299f31d00

	if state[0] == 0 {
		state[0] = 1
	}
	if state[1] == 0 {
		state[1] = 2
	}
	if state[2] == 0 {
		state[2] = 4
	}
	state[0] = scramble64(state[0], 0x801178846e899d17)
	state[1] = scramble64(state[1], 0x803340f36895c2b5)
	state[2] = scramble64(state[2], 0x80445170f5f2e0b1)
	state[0] = scramble64(state[0], 0x9c1b8e1e9628323f)
	state[1] = scramble64(state[1], 0xa52a78f6dea653c1)
	state[2] = scramble64(state[2], 0xd0959cc6bf8d866d)
	//fmt.Printf("v0=%016x v1=%016x v2=%016x - ZAPHOD64 SEED-STATE FINAL\n", state[0], state[1], state[2])
	return state
}

func HashWithState(state *State, key []byte, keyLen uint64) uint64 {
	v0 := state[0]
	v1 := state[1]
	v2 := state[2] ^ (0xc0f9edd07d89152f * (keyLen + 1))
	len := keyLen

	//fmt.Printf("v0=%016x v1=%016x v2=%016x ln=%016x - ZAPHOD64 HASH START\n", state[0], state[1], state[2], keyLen)
	//fmt.Printf("len=%v\n", len)

	for len >= 16 {
		//fmt.Printf("m0=%016x m1=%016x - ZAPHOD64 READ 2-WORDS A\n", binary.LittleEndian.Uint64(key[0:]), binary.LittleEndian.Uint64(key[8:]))

		v1 -= binary.LittleEndian.Uint64(key)
		key = key[8:]

		v0 += binary.LittleEndian.Uint64(key)
		key = key[8:]
		//fmt.Printf("v0=%016x v1=%016x v2=%016x - ZAPHOD64 MIX 2-WORDS A MIX STEP 1\n\n", v0, v1, v2)
		v0, v1, v2 = mix(v0, v1, v2)

		len -= 16
	}

	if len >= 8 {
		v1 -= binary.LittleEndian.Uint64(key)
		key = key[8:]
	}

	v0 += uint64(keyLen+1) << 56

	//fmt.Printf("v0=%016x v1=%016x v2=%016x - ALMOST FINAL\n\n", v0, v1, v2)
	switch len & 0x7 {
	case 7:
		v0 += uint64(key[6]) << 48
		fallthrough
	case 6:
		v0 += uint64(binary.LittleEndian.Uint16(key[4:])) << 32
		v0 += uint64(binary.LittleEndian.Uint32(key))
		break
	case 5:
		v0 += uint64(key[4]) << 32
		fallthrough
	case 4:
		v0 += uint64(binary.LittleEndian.Uint32(key))
		break
	case 3:
		v0 += uint64(key[2]) << 16
		fallthrough
	case 2:
		v0 += uint64(binary.LittleEndian.Uint16(key))
		break
	case 1:
		v0 += uint64(key[0])
		break
	case 0:
		fallthrough
	default:
		v2 ^= 0xFF
	}

	v0, v1, v2 = finalize(v0, v1, v2)
	hash := v0 ^ v1 ^ v2

	//fmt.Printf("v0=%016x v1=%016x v2=%016x hh=%016x - ZAPHOD64 FINAL\n\n", v0, v1, v2, hash)

	return hash
}

func Hash(seed []uint64, key []byte, keyLen uint64) uint64 {
	state := SeedState(seed)
	return HashWithState(&state, key, keyLen)
}
