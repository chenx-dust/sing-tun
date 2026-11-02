//go:build !linux

package tun

func goAllocateSlab() *goSlab {
	return new(goSlab)
}

func goFreeSlab(slab *goSlab) {
}
