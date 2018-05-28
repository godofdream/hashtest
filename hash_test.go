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
)

// 32 bit hashes

var h32djb = func(k []byte) uint32 {
	h := dgohash.NewDjb32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32DJB(b *testing.B) { benchmarkHash32(b, "djb", h32djb) }

var h32java = func(k []byte) uint32 {
	h := dgohash.NewJava32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32Java(b *testing.B) { benchmarkHash32(b, "java", h32java) }

var h32elf = func(k []byte) uint32 {
	h := dgohash.NewElf32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32ELF(b *testing.B) { benchmarkHash32(b, "djb", h32elf) }

var h32sdbm = func(k []byte) uint32 {
	h := dgohash.NewSDBM32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32SDBM(b *testing.B) { benchmarkHash32(b, "sdbm", h32sdbm) }

var h32sqlite = func(k []byte) uint32 {
	h := dgohash.NewSQLite32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32SQLITE(b *testing.B) { benchmarkHash32(b, "sqlite", h32sqlite) }

var h32jenkins = func(k []byte) uint32 {
	h := dgohash.NewJenkins32()
	h.Write(k)
	return h.Sum32()
}

func Benchmark32Jenkins(b *testing.B) { benchmarkHash32(b, "jenkins", h32jenkins) }

var h32crc32 = func(k []byte) uint32 { return crc32.ChecksumIEEE(k) }

func Benchmark32CRC32(b *testing.B) { benchmarkHash32(b, "crc32", h32crc32) }

var h32marvin = func(k []byte) uint32 { return marvin32.Sum32(0, k) }

func Benchmark32Marvin(b *testing.B) { benchmarkHash32(b, "Marvin32", h32marvin) }

var h32murmur3 = func(k []byte) uint32 { return murmur3.Sum32(k) }

func Benchmark32MurMur3(b *testing.B) { benchmarkHash32(b, "murmur3", h32murmur3) }

var h32murmur2 = func(k []byte) uint32 { return murmur2.MurmurHash2(k, 0) }

func Benchmark32MurMur2(b *testing.B) { benchmarkHash32(b, "murmur2", h32murmur2) }

var h32murmur2a = func(k []byte) uint32 { return murmur2.MurmurHash2A(k, 0) }

func Benchmark32MurMur2a(b *testing.B) { benchmarkHash32(b, "murmur2a", h32murmur2a) }

var h32cityhash = func(k []byte) uint32 { return cityhash.CityHash32(k, uint32(len(k))) }

func Benchmark32cityhash(b *testing.B) { benchmarkHash32(b, "cityhash", h32cityhash) }

var h32spooky = func(k []byte) uint32 { return spooky.Hash32(k) }

func Benchmark32Spooky(b *testing.B) { benchmarkHash32(b, "Spooky", h32spooky) }

var h32farm = func(k []byte) uint32 { return farm.Hash32(k) }

func Benchmark32Farm(b *testing.B) { benchmarkHash32(b, "Farm", h32farm) }

var h32xxhash = func(k []byte) uint32 { return xxhash.Checksum32(k) }

func Benchmark32XXHash(b *testing.B) { benchmarkHash32(b, "XXHash", h32xxhash) }

var h32farmhash = func(k []byte) uint32 { return farmhash.Hash32(k) }

func Benchmark32FarmHash(b *testing.B) { benchmarkHash32(b, "Farmhash", h32farmhash) }

// 64 bit hashes

var h64murmur3 = func(k []byte) uint64 { return murmur3.Sum64(k) }

func Benchmark64MurMur3(b *testing.B) { benchmarkHash64(b, "murmur3", h64murmur3) }

var h64murmur2 = func(k []byte) uint64 { return murmur2.MurmurHash64A(k, 0) }

func Benchmark64MurMur2(b *testing.B) { benchmarkHash64(b, "murmur2", h64murmur2) }

var h64spooky = func(k []byte) uint64 { return spooky.Hash64(k) }

func Benchmark64Spooky(b *testing.B) { benchmarkHash64(b, "Spooky", h64spooky) }

var h64siphash = func(k []byte) uint64 { return dchestsip.Hash(0, 0, k) }

func Benchmark64SipHash(b *testing.B) { benchmarkHash64(b, "SipHash", h64siphash) }

var h64farm = func(k []byte) uint64 { return farm.Hash64(k) }

func Benchmark64Farm(b *testing.B) { benchmarkHash64(b, "Farm", h64farm) }

var h64city = func(k []byte) uint64 { return cityhash.CityHash64(k, uint32(len(k))) }

func Benchmark64City(b *testing.B) { benchmarkHash64(b, "City", h64city) }

var h64metro = func(k []byte) uint64 { return metro.Hash64(k, 0) }

func Benchmark64Metro(b *testing.B) { benchmarkHash64(b, "Metro", h64metro) }

var h64xxhash = func(k []byte) uint64 { return xxhash.Checksum64(k) }

func Benchmark64XXHash(b *testing.B) { benchmarkHash64(b, "XXHash", h64xxhash) }

var h64xxhashfast = func(k []byte) uint64 { return xxhashfast.Sum64(k) }

func Benchmark64XXFast(b *testing.B) { benchmarkHash64(b, "XXFast", h64xxhashfast) }

var fsthash = func(k []byte) uint64 { return fasthash.Hash64(0, k) }

func Benchmark64Fasthash(b *testing.B) { benchmarkHash64(b, "Fasthash", fsthash) }

var h64igh = func(k []byte) uint64 { return highway.Hash(highway.Lanes{}, k) }

func Benchmark64Highway(b *testing.B) { benchmarkHash64(b, "Highway", h64igh) }

var crc64table = crc64.MakeTable(crc64.ECMA)
var h64crc64 = func(k []byte) uint64 { return crc64.Checksum(k, crc64table) }

func Benchmark64CRC64(b *testing.B) { benchmarkHash64(b, "crc64", h64crc64) }

var h64sip13hash = func(k []byte) uint64 { return sip13.Sum64(0, 0, k) }

func Benchmark64Sip13Hash(b *testing.B) { benchmarkHash64(b, "Sip13", h64sip13hash) }

var h64fnva = func(k []byte) uint64 {
	h := fnv.New64a()
	h.Write(k)
	return h.Sum64()
}

func Benchmark64FNV1A(b *testing.B) { benchmarkHash64(b, "fnv1a", h64fnva) }

var h64fnv = func(k []byte) uint64 {
	h := fnv.New64()
	h.Write(k)
	return h.Sum64()
}

func Benchmark64FNV1(b *testing.B) { benchmarkHash64(b, "fnv1", h64fnv) }

var ht1ha = func(k []byte) uint64 { return t1ha.Sum64(k, 0) }

func Benchmark64T1ha(b *testing.B) { benchmarkHash64(b, "T1ha", ht1ha) }

var zaphodSeed zaphod64.State
var hzaphod64 = func(k []byte) uint64 { return uint64(zaphod64.HashWithState(&zaphodSeed, k, uint64(len(k)))) }

func Benchmark64Zaphod64(b *testing.B) { benchmarkHash64(b, "Zaphod64", hzaphod64) }

var stadtxState stadtx.State
var hstadtx = func(k []byte) uint64 { return stadtx.Hash(&stadtxState, k) }

func Benchmark64Stadtx(b *testing.B) { benchmarkHash64(b, "Stadtx", hstadtx) }

var htsip = func(k []byte) uint64 { return tsip.HashASM(0, 0, k) }

func Benchmark64Tsip(b *testing.B) { benchmarkHash64(b, "Tsip", htsip) }

var h64farmhash = func(k []byte) uint64 { return farmhash.Hash64(k) }

func Benchmark64FarmHash(b *testing.B) { benchmarkHash64(b, "Farmhash", h64farmhash) }

var (
	key0, key1 uint64
	buf        = make([]byte, 8<<10)
)

func benchmarkHash64(b *testing.B, str string, h func([]byte) uint64) {
	var sizes = []int{4, 8, 16, 32, 64, 96, 128, 1024, 8192}
	for _, n := range sizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash64n(b, int64(n), h) })
	}
}

var total uint64

func benchmarkHash64n(b *testing.B, size int64, h func([]byte) uint64) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total += h(buf[:size])
	}
}

func benchmarkHash32(b *testing.B, str string, h func([]byte) uint32) {
	var sizes = []int{4, 8, 16, 32, 64, 96, 128, 1024, 8192}
	for _, n := range sizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) { benchmarkHash32n(b, int64(n), h) })
	}
}

var total32 uint32

func benchmarkHash32n(b *testing.B, size int64, h func([]byte) uint32) {
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		total32 += h(buf[:size])
	}
}
