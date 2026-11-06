package crypto

import (
	"encoding/binary"
	"runtime"
)

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func ConcatBytes(fields ...[]byte) []byte {
	totalLen := 0
	for _, f := range fields {
		totalLen += 4 + len(f)
	}

	res := make([]byte, totalLen)
	offset := 0
	for _, f := range fields {
		binary.BigEndian.PutUint32(res[offset:offset+4], uint32(len(f)))
		offset += 4
		copy(res[offset:], f)
		offset += len(f)
	}
	return res
}
