package main

import (
	"testing"

	creachadairCity "bitbucket.org/creachadair/cityhash"
	jpathyCity "bitbucket.org/jpathy/dmc/cityhash"
	dgryskiSpooky "github.com/dgryski/go-spooky"
	huichenMurmur "github.com/huichen/murmur"
	farmhash "github.com/leemcloughlin/gofarmhash"
	"github.com/pborman/uuid"
	reuseeMurmur "github.com/reusee/mmh3"
	hashlandSpooky "github.com/tildeleb/hashland/spooky"
	zhangMurmur "github.com/zhangxinngang/murmur"
)

func mkinput(n int) [][]byte {
	rv := make([][]byte, n)
	for i := 0; i < n; i++ {
		rv[i] = uuid.NewRandom()
	}
	return rv
}
func BenchmarkFarmHashHash32(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = farmhash.Hash32(input[n])
	}
}
func BenchmarkFarmHashHash64(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint64, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = farmhash.Hash64(input[n])
	}
}
func BenchmarkHuichenMurmur(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = huichenMurmur.Murmur3(input[n])
	}
}
func BenchmarkReuseeMurmur(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = reuseeMurmur.Sum32(input[n])
	}
}
func BenchmarkZhangMurmur(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = zhangMurmur.Murmur3(input[n])
	}
}
func BenchmarkDgryskiSpooky32(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = dgryskiSpooky.Hash32(input[n])
	}
}
func BenchmarkDgryskiSpooky64(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint64, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = dgryskiSpooky.Hash64(input[n])
	}
}
func BenchmarkHashlandSpooky32(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = hashlandSpooky.Hash32(input[n], 0)
	}
}
func BenchmarkHashlandSpooky64(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint64, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = hashlandSpooky.Hash64(input[n], 0)
	}
}
func BenchmarkJPathyCity32(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = jpathyCity.Hash32(input[n])
	}
}
func BenchmarkCreachadairCity32(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint32, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = creachadairCity.Hash32(input[n])
	}
}
func BenchmarkCreachadairCity64(b *testing.B) {
	input := mkinput(b.N)
	output := make([]uint64, b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		output[n] = creachadairCity.Hash64(input[n])
	}
}