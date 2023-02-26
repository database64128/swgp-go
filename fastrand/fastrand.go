package fastrand

import _ "unsafe"

//go:linkname Uint32 runtime.fastrand
func Uint32() uint32

//go:linkname Uint32n runtime.fastrandn
func Uint32n(n uint32) uint32

//go:linkname Uint64 runtime.fastrand64
func Uint64() uint64

//go:linkname Uint runtime.fastrandu
func Uint() uint
