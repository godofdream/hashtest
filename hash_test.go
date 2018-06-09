package main

import (
	// "crypto/md5"
	// "crypto/sha1"
	// "crypto/sha256"
	// "crypto/sha512"
	// "math/rand"
	// "testing"
	//
	//"hash/adler32"
	// "hash/crc32"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"strconv"
	"testing"
	// "hash/fnv"
	//
	// "github.com/pborman/uuid"
	//
	// creachadairCity "bitbucket.org/creachadair/cityhash"
	// jpathyCity "bitbucket.org/jpathy/dmc/cityhash"
	// surgeCity "github.com/surge/cityhash"
	//
	// hashlandSpooky "github.com/tildeleb/hashland/spooky"
	//
	// huichenMurmur "github.com/huichen/murmur"
	// reuseeMurmur "github.com/reusee/mmh3"
	// zhangMurmur "github.com/zhangxinngang/murmur"
	//
	// farmhash "github.com/leemcloughlin/gofarmhash"
	//
	// "github.com/minio/highwayhash"

	xxhash "github.com/OneOfOne/xxhash"
	murmur2 "github.com/aviddiviner/go-murmur"
	xxhashfast "github.com/cespare/xxhash"
	dchestsip "github.com/dchest/siphash"
	"github.com/dgryski/dgohash"
	"github.com/dgryski/go-farm"
	highway "github.com/dgryski/go-highway"
	"github.com/dgryski/go-marvin32"
	"github.com/dgryski/go-metro"
	"github.com/dgryski/go-sip13"
	"github.com/dgryski/go-spooky"
	"github.com/dgryski/go-stadtx"
	"github.com/dgryski/go-t1ha"
	farmhash "github.com/leemcloughlin/gofarmhash"
	"github.com/opennota/fasthash"
	"github.com/rbastic/go-zaphod64"
	murmur3 "github.com/spaolacci/murmur3"
	"github.com/surge/cityhash"

	tsip "github.com/dgryski/trifles/tsip/go"

	// "crypto/md5"
	// "crypto/rand"
	// "crypto/sha1"
	// "crypto/sha512"
	"github.com/minio/highwayhash"
	//sha256Avx512 "github.com/minio/sha256-simd"
	"golang.org/x/crypto/blake2b"
)

// 32 bit hashes

func Benchmark32bitDJB(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewDjb32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitJava(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewJava32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitELF(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewElf32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitSDBM(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewSDBM32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitSQLITE(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewSQLite32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitJenkins(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 {
		h := dgohash.NewJenkins32()
		h.Write(k)
		return h.Sum32()
	})
}

func Benchmark32bitCRC32(b *testing.B) { benchmarkHash(b, crc32.ChecksumIEEE) }
func Benchmark32bitMarvin(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 { return marvin32.Sum32(0, k) })
}

func Benchmark32bitMurMur2(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 { return murmur2.MurmurHash2(k, 0) })
}
func Benchmark32bitMurMur2a(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 { return murmur2.MurmurHash2A(k, 0) })
}

func Benchmark32bitcityhash(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint32 { return cityhash.CityHash32(k, uint32(len(k))) })
}

func Benchmark32bitSpooky(b *testing.B) { benchmarkHash(b, spooky.Hash32) }

func Benchmark32bitFarm(b *testing.B) { benchmarkHash(b, farm.Hash32) }

func Benchmark32bitXXHash(b *testing.B) { benchmarkHash(b, xxhash.Checksum32) }

// murmur3 "github.com/spaolacci/murmur3"
func Benchmark32bitMurMur3(b *testing.B)  { benchmarkHash(b, murmur3.Sum32) }
func Benchmark64bitMurMur3(b *testing.B)  { benchmarkHash(b, murmur3.Sum64) }
func Benchmark128bitMurMur3(b *testing.B) { benchmarkHash(b, murmur3.Sum128) }

func Benchmark64bitMurMur2(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return murmur2.MurmurHash64A(k, 0) })
}

func Benchmark64bitSpooky(b *testing.B) { benchmarkHash(b, spooky.Hash64) }

func Benchmark64bitSipHash(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return dchestsip.Hash(0, 0, k) })
}

func Benchmark64bitFarm(b *testing.B) { benchmarkHash(b, farm.Hash64) }

func Benchmark64bitCity(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return cityhash.CityHash64(k, uint32(len(k))) })
}

func Benchmark64bitMetro(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return metro.Hash64(k, 0) })
}

func Benchmark64bitXXHash(b *testing.B) { benchmarkHash(b, xxhash.Checksum64) }

func Benchmark64bitXXFast(b *testing.B) { benchmarkHash(b, xxhashfast.Sum64) }

func Benchmark64bitFasthash(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return fasthash.Hash64(0, k) })
}

func Benchmark64bitHighway(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return highway.Hash(highway.Lanes{}, k) })
}

var crc64table = crc64.MakeTable(crc64.ECMA)

func Benchmark64bitCRC64(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return crc64.Checksum(k, crc64table) })
}

func Benchmark64bitSip13Hash(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return sip13.Sum64(0, 0, k) })
}

func Benchmark64bitFNV1A(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 {
		h := fnv.New64a()
		h.Write(k)
		return h.Sum64()
	})
}

func Benchmark64bitFNV1(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 {
		h := fnv.New64()
		h.Write(k)
		return h.Sum64()
	})
}

func Benchmark64bitT1ha(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return t1ha.Sum64(k, 0) })
}

var zaphodSeed zaphod64.State

func Benchmark64bitZaphod64(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return uint64(zaphod64.HashWithState(&zaphodSeed, k, uint64(len(k)))) })
}

var stadtxState stadtx.State

func Benchmark64bitStadtx(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return stadtx.Hash(&stadtxState, k) })
}

func Benchmark64bitTsip(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return tsip.HashASM(0, 0, k) })
}

func Benchmark32bitFarmHash(b *testing.B) { benchmarkHash(b, farmhash.Hash32) }
func Benchmark64bitFarmHash(b *testing.B) { benchmarkHash(b, farmhash.Hash64) }

func Benchmark256bitSHA256(b *testing.B) { benchmarkHash(b, sha256.Sum256) }

var key32 []byte = []byte("18086354421675971832404208891150")

func Benchmark64bitHighwayhash(b *testing.B) {
	benchmarkHash(b, func(k []byte) uint64 { return highwayhash.Sum64(k, key32) })
}

func Benchmark128bitHighwayhash(b *testing.B) {
	benchmarkHash(b, func(k []byte) [16]byte { return highwayhash.Sum128(k, key32) })
}

func Benchmark256bitHighwayhash(b *testing.B) {
	benchmarkHash(b, func(k []byte) [32]byte { return highwayhash.Sum(k, key32) })
}

func Benchmark256bitBlake2b(b *testing.B) { benchmarkHash(b, blake2b.Sum256) }
func Benchmark384bitBlake2b(b *testing.B) { benchmarkHash(b, blake2b.Sum384) }
func Benchmark512bitBlake2b(b *testing.B) { benchmarkHash(b, blake2b.Sum512) }

var (
	key0, key1 uint64
	buf        = make([]byte, 8<<10)
)
var sizes = []int{4, 8, 16, 32, 64, 96, 128, 1024, 8192}
var total32 uint32
var total64 uint64
var total128 [16]byte
var total256 [32]byte
var total384 [48]byte
var total512 [64]byte

func benchmarkHash(b *testing.B, h interface{}) {
	for _, n := range sizes {
		switch v := h.(type) {
		case func([]byte) uint32:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash32n(b, int64(n), h.(func([]byte) uint32)) })
		case func([]byte) uint64:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash64n(b, int64(n), h.(func([]byte) uint64)) })
		case func([]byte) [16]byte:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash128n(b, int64(n), h.(func([]byte) [16]byte)) })
		case func([]byte) [32]byte:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash256n(b, int64(n), h.(func([]byte) [32]byte)) })
		case func([]byte) [48]byte:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash384n(b, int64(n), h.(func([]byte) [48]byte)) })
		case func([]byte) [64]byte:
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash512n(b, int64(n), h.(func([]byte) [64]byte)) })
		case func([]byte) (uint64, uint64):
			b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash128_2n(b, int64(n), h.(func([]byte) (uint64, uint64))) })
		default:
			fmt.Printf("I don't know about type %T!\n", v)
		}

	}
}

func benchmarkHash32n(b *testing.B, size int64, h func([]byte) uint32) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total32 += h(buf[:size])
	}
}

func benchmarkHash64n(b *testing.B, size int64, h func([]byte) uint64) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total64 += h(buf[:size])
	}
}

func benchmarkHash128n(b *testing.B, size int64, h func([]byte) [16]byte) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total128 = h(buf[:size])
	}
}
func benchmarkHash128_2n(b *testing.B, size int64, h func([]byte) (uint64, uint64)) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total64, total64 = h(buf[:size])
	}
}

func benchmarkHash256n(b *testing.B, size int64, h func([]byte) [32]byte) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total256 = h(buf[:size])
	}
}

func benchmarkHash384n(b *testing.B, size int64, h func([]byte) [48]byte) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total384 = h(buf[:size])
	}
}

func benchmarkHash512n(b *testing.B, size int64, h func([]byte) [64]byte) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total512 = h(buf[:size])
	}
}
