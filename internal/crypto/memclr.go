package crypto

import "runtime"

// Memclr securely wipes all bytes in the given slice by setting them to zero
// and ensuring the memory write is not optimized away by the compiler.
// It is safe to pass nil or an empty slice.
func Memclr(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b[0])
}
